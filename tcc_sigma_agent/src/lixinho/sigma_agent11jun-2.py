import re
import os
import yaml
import uuid
import requests     #biblioteca pra conversar com a internet (pip3 install requests)
from typing import TypedDict
from langchain_huggingface import HuggingFaceEmbeddings
from sentence_transformers import CrossEncoder
# from langchain_community.vectorstores import Chroma       #deprecated
from langchain_chroma import Chroma
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from bs4 import BeautifulSoup
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_DIR = os.path.join(BASE_DIR, "..", "data", "chroma_db")
EMBEDDINGS_MODEL = HuggingFaceEmbeddings(model_name="BAAI/bge-small-en-v1.5")
RERANKER_MODEL = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-12-v2")
PROMPT_PATH = os.path.join(BASE_DIR, "..", "prompts", "sigma_system_prompt.md")
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    SIGMA_SYSTEM_PROMPT = f.read()

# >>>>>>>> máquina de estados <<<<<<<<<<
# nó 1 = classificador determinístico de entrada (Entendimento)
# nó 2 = procura informações nas APIs (threat intelligence)  <-- roda ANTES do RAG
# nó 3 = recupera contexto com RAG (usa a descrição da API p/ enriquecer a busca)
# nó 4 = criação da regra com LLM local
# nó 5 = validação com o Sigma CLI
# OBS: a API (nó 2) roda antes do RAG (nó 3) para que a descrição técnica da ameaça
#      (ex.: a descrição do CVE vinda do MITRE/NVD) sirva de consulta semântica rica
#      ao banco vetorial, recuperando exemplos mais relevantes.

from funcoes import (
    extrair_referencias,
    extrair_palavras_chave_url,
    extrair_secoes_tecnicas,
    extrair_urls_de_referencias,
    detectar_regime,
    limpar_instrucoes,
    avaliar_contexto,
    filtrar_urls_doc,
    consulta_mitre,
    consulta_nvd,
    validar_tags_attack,
    busca_duckduckgo,
)

# >>>>>>>> ESTADO <<<<<<<<<     (caderno de anotações)
class GraphState(TypedDict):
    input_usuario: str       #entrada: "gere uma regra para ..."
    tipo_input: str          #pode ser cve, uma hash ou 'texto_livre'
    termo_busca: str         #cve ou hash extraído
    url_fornecida: list       #possível url que esteja no input
    texto_para_rag: str        #trechos técnicos extraídos do RAG (nó 2)
    contexto_pobre: bool       #flag: input só com URLs/sem descrição textual da ameaça
    contexto_rag: str        #exemplos de regras (nó 2)
    contexto_api: str        #dados técnicos da ameaça (nó 3)
    regra_gerada: str        #YAML gerado pela LLM (nó 4)
    erro_validacao: str      #erro do sigma-cli
    tentativas: int          #qtas vezes a LLM tentou refazer a regra

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 1 (classificador determinístico de entrada) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# Pré-processador ROBUSTO: lida tanto com prompts ESTRUTURADOS (com cabeçalhos
# '# Threat to detect', '# References'...) quanto com prompts SOLTOS (texto corrido).
# Decide o regime uma vez e processa de acordo, convergindo para uma saída comum:
#   - tipo_input  : cve / hash / texto_livre
#   - termo_busca : o CVE/hash isolado (se houver)
#   - url_fornecida: URLs da ameaça (sem as de documentação de sintaxe)
#   - texto_para_rag: descrição da ameaça, limpa de URLs e de frases-instrução
#   - contexto_pobre: True se sobrou pouca descrição (info está atrás dos links)
def no_1_classificador(state: GraphState) -> GraphState:

    print("\n[Nó 1] Classificando input...")
    texto = state.get("input_usuario", "")

    # (a) detecta o regime do prompt
    regime = detectar_regime(texto)
    print(f" -> Regime detectado: {regime}")

    # (b) extrai URLs conforme o regime
    if regime == "estruturado":
        #tenta a seção '# References'; se não houver, pega todas as URLs do texto
        urls_das_refs = extrair_urls_de_referencias(texto)
        if urls_das_refs is not None:
            urls_brutas = urls_das_refs
            print(" -> URLs extraídas da seção '# References'.")
        else:
            urls_brutas = re.findall(r"https?://[^\s]+", texto)
            urls_brutas = [u.rstrip(r".,;!?)\]}>'\"") for u in urls_brutas]
            print(" -> Estruturado sem '# References'; usando todas as URLs.")
    else:
        #regime solto: pega todas as URLs do texto
        urls_brutas = re.findall(r"https?://[^\s]+", texto)
        urls_brutas = [u.rstrip(r".,;!?)\]}>'\"") for u in urls_brutas]
        print(" -> Prompt solto; coletando todas as URLs do texto.")

    # (c) filtra URLs de documentação de sintaxe (ex.: sigmahq.io) — não são a ameaça
    urls_limpas = filtrar_urls_doc(urls_brutas)
    if len(urls_limpas) < len(urls_brutas):
        print(f" -> {len(urls_brutas) - len(urls_limpas)} URL(s) de documentação ignorada(s).")

    # (d) remove TODAS as URLs do texto antes de procurar CVE/hash e montar a descrição
    texto_sem_url = texto
    for u in urls_brutas:   #remove até as de doc, para não sujar a descrição
        texto_sem_url = texto_sem_url.replace(u, "")

    # (e) identifica CVE ou hash isolado
    padrao_cve = re.search(r"CVE-\d{4}-\d+", texto_sem_url, re.IGNORECASE)
    padrao_hash = re.search(r"\b[a-fA-F0-9]{32,64}\b", texto_sem_url)

    if padrao_cve:
        tipo = "cve"
        termo = padrao_cve.group().upper()
    elif padrao_hash:
        tipo = "hash"
        termo = padrao_hash.group().lower()
    else:
        tipo = "texto_livre"
        termo = ""

    # (f) monta a descrição da ameaça para o RAG, conforme o regime
    if regime == "estruturado":
        #isola as seções de contexto (ignora # Requirements, # Output, etc.)
        descricao = extrair_secoes_tecnicas(texto_sem_url)
    else:
        #solto: o texto inteiro (sem URLs) é a descrição
        descricao = texto_sem_url

    # (g) limpa frases-instrução (ruído para a busca semântica)
    texto_para_rag = limpar_instrucoes(descricao)

    # (h) avalia se o contexto é pobre (pouca descrição + só URLs)
    contexto_pobre = avaliar_contexto(texto_para_rag, urls_limpas)

    #-- logs de diagnóstico --
    print(f" -> Tipo: {tipo}")
    if termo:
        print(f" -> Termo isolado: {termo}")
    if urls_limpas:
        print(f" -> URLs da ameaça: {len(urls_limpas)} encontrada(s).")
        for u in urls_limpas:
            print(f"    - {u}")
    print(f" -> Descrição p/ RAG: {len(texto_para_rag)} caractere(s).")
    if contexto_pobre:
        print(" -> !! CONTEXTO POBRE: descrição insuficiente; info está atrás dos links.")
        print("    (a expansão por LLM no Nó 2 tentará destilar a ameaça do scraping)")

    return {
        "tipo_input": tipo,
        "termo_busca": termo,
        "url_fornecida": urls_limpas,
        "texto_para_rag": texto_para_rag,
        "contexto_pobre": contexto_pobre,
    }

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>>>>>>>>>>>>> NÓ 2 (API) <<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Vai buscar informações técnicas na internet sobre a ameaça extraída.
#Roda ANTES do RAG para que a descrição da ameaça enriqueça a busca vetorial.
#Se a API falhar ou não tiver internet, o agente não dá erro, vai seguir em frente.
def no_2_api(state: GraphState) -> GraphState:

    print("\n[Nó 2] Buscando dados em APIs externas...")
    
    tipo = state.get("tipo_input", "")  #usar .get() evita q o programa quebre (keyerror) caso as chaves não existam no estado
    termo = state.get("termo_busca", "")
    urls = state.get("url_fornecida", [])
    entrada_usuario = state.get("input_usuario", "")
    contexto_api = "Nenhum dado externo coletado."      #inicialização da váriavel que vai pegar esse contexto
    trechos = []

    if isinstance(urls, str):       #se por acaso vier string, normaliza pra lista
        urls = [urls] if urls else []

    #procura CVEs e CWEs em todo o texto de entrada do usuário:
    cves_encontrados, cwes_encontrados = extrair_referencias(entrada_usuario)

    #procura uma URL para acessar:
    if urls:
        print(f" -> {len(urls)} fornecida(s) para processar.")
        
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }

        for i, url in enumerate(urls, start=1):

            #Conversão de URL do github para a versão raw
            if "github.com" in url and "/blob/" in url:
                url_raw = url.replace("github.com", "raw.githubusercontent.com")
                url_raw = url_raw.replace("/blob/", "/")
                print(f" -> URL do github convertida para raw: {url_raw}")
                url = url_raw

            acesso_ok = False
            try:
                resposta_url = requests.get(url, timeout=10, headers=headers)
                if resposta_url.status_code == 200:
                    soup = BeautifulSoup(resposta_url.text, "html.parser")
                    # pega só parágrafos e títulos, que costumam ter o conteúdo principal
                    elementos = soup.find_all(["p","article"])
                    texto_limpo = " ".join(
                        e.get_text(separator=" ", strip=True) for e in elementos
                    )
                    if not texto_limpo:   # fallback se a página não usa tags semânticas
                        texto_limpo = soup.get_text(separator=" ", strip=True)
                    trechos.append(f"Conteúdo da URL {url}:\n{texto_limpo[:1500]}")
                    print(" -> Conteúdo da URL extraído com sucesso.")
                    acesso_ok = True
                else:
                    print(f" -> ERRO HTTP {resposta_url.status_code} ao acessar a URL.")
            except requests.exceptions.RequestException as e:
                print(f" -> Falha ao acessar a URL: {e}")
            
            #mesmo se o acesso funcionar, vai procurar CVE/CWE na URL:
            cves_url, cwes_url = extrair_referencias(url)
            cves_encontrados.update(cves_url)
            cwes_encontrados.update(cwes_url)

            #se a URL falhar, extrai as palavras-chave do caminho (fallback):
            if not acesso_ok:
                palavras = extrair_palavras_chave_url(url)
                if palavras:
                    trechos.append(
                        f"\tURL inacessível. Palavras extraídas da URL: {', '.join(palavras)}"
                    )
                    print(f" -> Palavras da URL: {', '.join(palavras)}")
        
    #Consulta o MITRE e o NVD para cada CVE encontrado no texto ou na URL:
    if cves_encontrados:
        for cve_id in sorted(cves_encontrados):
            print(f" -> Consultando MITRE e NVD para {cve_id}...")

            desc_mitre = consulta_mitre(cve_id)
            if desc_mitre:
                trechos.append(f"MITRE - {cve_id}:\n{desc_mitre}")
                print(" -> Dados obtidos do MITRE.")
            else:
                print(" -> Sem dados obtidos do MITRE.")
            
            dados_nvd = consulta_nvd(cve_id)
            if dados_nvd:
                texto = f"NVD - {cve_id}:\n"
                if dados_nvd["descricao"]:
                    texto += f"Descrição: {dados_nvd['descricao']}\n"
                if dados_nvd["cwes"]:
                    texto += f"CWE associado: {', '.join(dados_nvd['cwes'])}\n"
                    cwes_encontrados.update(dados_nvd["cwes"])
                if dados_nvd["cvss"]:
                    texto += f"CVSS: {dados_nvd['cvss']}\n"
                trechos.append(texto)
                print(" -> Dados obtidos do NVD.")
            else:
                print(" -> Dados não obtidos do NVD.")

    #Registra os CWEs encontrados como contexto adicional:
    if cwes_encontrados:
        trechos.append(f"CWEs identificados: {', '.join(sorted(cwes_encontrados))}")

    #Se for Hash consulta a API do VirusTotal:
    if tipo == "hash" and termo:
        #print(f" -> Consultando plataforma para a hash '{termo}'. . .")
        #as hashes são consultadas no virustotal.com, mas ele exige uma API key pessoal. tenho aqui uma simulação apenas para entender a lógica
        trechos.append(
            f"Simulação de API: a hash {termo} foi identificada como malware\n"
            f"{termo} cria processo x em diretórios temporários.\n"
            f"{termo} está associada à man in the middle."
        )
        print(" -> Dados da hash carregados.")

    # ~* BUSCA DUCKDUCKGO (incremento sempre, após as APIs) *~
    # Escolhe o melhor termo disponível para a busca livre:
    termo_busca_web = termo if termo else state.get("texto_para_rag", "")
    if termo_busca_web:
        # limita o tamanho da query (DuckDuckGo não lida bem com textos longos)
        termo_busca_web = termo_busca_web[:200]
        print(f" -> Busca complementar no DuckDuckGo: {termo_busca_web[:60]}...")
        resultado_web = busca_duckduckgo(termo_busca_web, max_resultados=5)
        if resultado_web:
            trechos.append(f"Resultados da busca web (DuckDuckGo):\n{resultado_web}")
            print(" -> Resultados da web obtidos.")
        else:
            print(" -> Sem resultados da web (ou lib indisponível).")
    
    #6: junta tudo
    if trechos:
        contexto_api = "\n\n---\n\n".join(trechos)
    else:
        print(" -> Sem fonte de texto com referências.")
    return {"contexto_api": contexto_api}   #atualiza o graphstate com a matéria-prima técnica

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 3 (procura contexto no RAG) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# i)primeiro crio o banco (chromadb) para transformar as regras em vetores matemáticos (embeddings) e os salvar no chromadb;
# ii) depois o agente lê o banco e busca no RAG as regras mais parecidas com a entrada;
# uso o modelo bge-small-en-v1.5 de embeddings.
# então:    o nó 3 acessa o chromadb e busca as regras Sigma mais parecidas com a entrada;
#           essas regras servirão de molde pra LLM (few-shot prompting).
# NOVIDADE: como o nó 2 (API) já rodou, a descrição técnica da ameaça (ex.: descrição
#           do CVE vinda do MITRE/NVD) já está em contexto_api. Quando ela existe, vira
#           o sinal semântico mais forte para a busca vetorial, recuperando exemplos
#           muito mais relevantes do que o código opaco de um CVE/hash.

#limite de caracteres da parte da API que entra na consulta vetorial.
#motivo: o bge-small-en-v1.5 perde qualidade perto do limite de tokens; manter a
#consulta focada (~800 chars) recupera exemplos mais precisos do que jogar 5000 chars.
LIMITE_API_NA_CONSULTA = 800

def _extrair_descricao_relevante_api(contexto_api: str, limite: int = LIMITE_API_NA_CONSULTA) -> str:
    """Seleciona a parte mais útil do contexto_api para usar como consulta ao RAG.

    Prioriza as descrições técnicas estruturadas (MITRE, NVD, CWE) sobre o conteúdo
    bruto de URL, porque elas concentram o sinal semântico da ameaça. Trunca o
    resultado em `limite` caracteres para não diluir o embedding.

    Args:
        contexto_api: o texto completo reunido pelo nó 2 (API).
        limite: número máximo de caracteres a retornar.

    Returns:
        Trecho priorizado e truncado, ou string vazia se não houver descrição útil.
    """
    if not contexto_api or contexto_api.strip() == "Nenhum dado externo coletado.":
        return ""

    #os trechos no contexto_api são separados por "\n\n---\n\n" (ver nó 2)
    blocos = contexto_api.split("\n\n---\n\n")

    #prefixos que indicam descrição técnica de alto valor semântico
    prefixos_ricos = ("MITRE", "NVD", "CWEs", "Simulação de API")
    blocos_ricos = [b for b in blocos if b.strip().startswith(prefixos_ricos)]

    #se achou descrições estruturadas, usa-as; senão, cai pro conteúdo geral (URLs/web)
    fonte = "\n\n".join(blocos_ricos) if blocos_ricos else contexto_api
    return fonte.strip()[:limite]


def no_3_rag(state: GraphState) -> GraphState:

    print("\n[Nó 3] Buscando contexto no RAG - com re-ranking\n")

    #-- monta a consulta ao banco vetorial seguindo uma prioridade clara --
    #1) se a API trouxe descrição rica, ENRIQUECE: input do usuário + descrição da API;
    #2) senão, usa o texto pré-processado (seções técnicas) do nó 1;
    #3) senão, usa o termo isolado (CVE/hash) cru;
    #4) senão, usa o input completo (fallback).

    desc_api = _extrair_descricao_relevante_api(state.get("contexto_api", ""))

    if desc_api:
        #base = o melhor sinal vindo do usuário (termo isolado ou seções técnicas)
        base_usuario = state.get("termo_busca") or state.get("texto_para_rag") \
                       or state.get("input_usuario", "")
        termo_pesquisa = f"{base_usuario}\n\n{desc_api}".strip()
        origem = "input + descrição da API (enriquecido)"
    elif state.get("texto_para_rag"):
        termo_pesquisa = state["texto_para_rag"]
        origem = "seções técnicas"
    elif state.get("termo_busca"):
        termo_pesquisa = state["termo_busca"]
        origem = "termo isolado (CVE/hash)"
    else:
        termo_pesquisa = state.get("input_usuario", "")
        origem = "fallback (input completo)"

    #gancho da flag: se o nó 1 marcou contexto pobre, apenas registra (a expansão por
    #LLM, quando implementada no nó 2, já terá enriquecido contexto_api antes daqui).
    if state.get("contexto_pobre"):
        print(" -> Aviso: nó 1 sinalizou CONTEXTO POBRE para este input.")

    print(f" -> Estratégia: {origem}")
    print(f" -> ChromaDB recebe ({len(termo_pesquisa)} caracteres): "
          f"{termo_pesquisa[:120]}...\n")

    # Carregamos o banco vetorial persistido
    vector_store = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=EMBEDDINGS_MODEL
    )

    #1a busca no RAG usando similaridade de cosseno; faz uma busca ampla, pega 20 candidatos:
    candidatos = vector_store.similarity_search(termo_pesquisa, k=20)

    if not candidatos:
        print(" -> Aviso: nenhuma regra similar encontrada no banco.")
        return {"contexto_rag": "Nenhuma exemplo recuperado."}
    print(f" -> {len(candidatos)} regras candidatas recuperadas do ChromaDB.")

    #re-ranking - cross-encoder avalia cada par (pergunta + candidato)
    pares = [(termo_pesquisa, doc.page_content) for doc in candidatos]
    scores = RERANKER_MODEL.predict(pares)

    #ordena do maior score p menor e pega os 5 melhores:
    candidatos_com_score = sorted(zip(scores, candidatos), key=lambda x: x[0], reverse=True)
    top_5 = candidatos_com_score[:5]

    print(f" -> re-ranking concluído.")
    print(f" -> scores: {[round(float(s),3) for s, _ in top_5]}")

    contexto_formatado = "\n\n".join([
        f"### EXEMPLO {i} ###\n{doc.page_content}"
        for i, (_, doc) in enumerate(top_5, start=1)
    ])
    return {"contexto_rag": contexto_formatado}


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>>> NÓ 4 (GERAÇÃO DA REGRA - LLM) <<<<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 
def no_4_gerador(state: GraphState) -> GraphState:
    tentativa_atual = state.get("tentativas", 0) + 1    #sinalizar quantas tentativas
    print(f"\n[Nó 4] Gerando a regra... Tentativa {tentativa_atual}")

    #llm = ChatOllama(model="qwen2.5:1.5b", temperature=0.1)
    llm = ChatOllama(model="llama3.1", temperature=0.1)

# ~* Lista explícita de URLs permitidas para 'references:' ~*
    urls_permitidas = state.get("url_fornecida", [])
    if urls_permitidas:
        bloco_urls = "USER-PROVIDED REFERENCES (use EXACTLY these URLs in 'references:', no others):\n"
        bloco_urls += "\n".join(f"- {u}" for u in urls_permitidas)
    else:
        bloco_urls = (
            "USER-PROVIDED REFERENCES: None.\n"
            "Either omit the 'references:' field entirely OR set it to an empty list. "
            "Do NOT fabricate URLs."
        )

    #USER PROMPT:
    user_prompt = f"""USER REQUEST:
{state['input_usuario']}

{bloco_urls}

FORMATTING TEMPLATE - base the YAML structure on these real Sigma rules: 
{state['contexto_rag']}

ADDITIONAL TECHNICAL CONTEXT - use to build detection logic if relevant:
{state['contexto_api']}

OUTPUT REQUIREMENTS:
1. Return ONLY the YAML code, no markdown fences, no explanations.
2. If the USER REQUEST contains URLs, put them in 'references:'.
3. Do NOT copy URLs from the FORMATTING TEMPLATE.
4. Do NOT invent URLs.
"""
    
    # caso hajam novas tentativas:
    erro_anterior = state.get("erro_validacao", "")
    if erro_anterior and erro_anterior != "APROVADO":
        user_prompt += f"""

ATTENTION - the previous attempt failed validation with this error:
{erro_anterior}

Fix this specific problem and return a corrected, valid Sigma rule."""

    mensagens = [
        SystemMessage(content=SIGMA_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt)
    ]

    print(" -> Enviando contexto para a GPU")
    resposta = llm.invoke(mensagens)   #chama a LLM
    print(" -> Regra gerada.")
    return{"regra_gerada": resposta.content}
    
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>> NÓ 5 (VALIDADOR SINTÁTICO) <<<<<<<<<< 
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#vê se o YAML gerado pela LLM possui algum erro; confere a qualidade.
def no_5_validador(state: GraphState) ->GraphState:

    print("\n[Nó 5] Revisando em 3 etapas a qualidade da regra gerada...")

    regra_revisao = state.get("regra_gerada", "")
    tentativas = state.get("tentativas", 0) + 1

    # ~* LIMPEZA DE MARKDOWN *~ agora vai limpar tudo de markdown e/ou vai extrair tudo entre ``` e ```:
    marcador = "`" * 3
    padrao_regex = marcador + r"[^\n]*\n(.*?)\n?" + marcador
    match = re.search(padrao_regex, regra_revisao, re.DOTALL | re.IGNORECASE)
    if match:
        yaml_limpo = match.group(1).strip() #if match else regra_revisao.strip()
    else:
        yaml_limpo = regra_revisao.strip()  #remove crases manualmente caso o regex falhe
        if yaml_limpo.startswith(marcador):     #remove a linha inicial se começar com ```
            linhas = yaml_limpo.split("\n",1) 
            yaml_limpo = linhas[1] if len(linhas) > 1 else ""
        if yaml_limpo.rstrip().endswith(marcador):
            yaml_limpo = yaml_limpo.rstrip()[:-len(marcador)].rstrip()

    #se o agente gerou várias regras separadas por '---', extrai só a primeira.
    if "\n---" in yaml_limpo or yaml_limpo.startswith("---"):
        print(" -> Detectado múltiplos documentos YAML; mantendo apenas o primeiro.")
        try:
            documentos = list(yaml.safe_load_all(yaml_limpo))
            documentos_validos = [d for d in documentos if isinstance(d, dict) and d]
            if documentos_validos:
                yaml_limpo = yaml.safe_dump(
                    documentos_validos[0],
                    sort_keys=False,
                    allow_unicode=True,
                    default_flow_style=False
                )
            else:
                msg_erro = "Nenhum documento YAML válido encontrado entre os múltiplos gerados."
                print(f"    ERRO: \n{msg_erro}")
                return {"erro_validacao": msg_erro, "tentativas": tentativas}
        except yaml.YAMLError as e:
            msg_erro = f"Falha ao separar documentos YAML múltiplos. Detalhes: {e}"
            print(f"    ERRO: \n{msg_erro}")
            return {"erro_validacao": msg_erro, "tentativas": tentativas}

    # ~* Correção automática de UUID *~ pro caso do agente gerar um id errado
    regra_corrigida = re.sub(
        r'^id:\s*.+$',
        f'id: {uuid.uuid4()}',
        yaml_limpo,
        flags=re.MULTILINE
    )
    if not re.search(r'^id:', regra_corrigida, re.MULTILINE):
        regra_corrigida = re.sub(
            r'^(title:.+)$',
            r'\1\nid: ' + str(uuid.uuid4()),
            regra_corrigida,
            flags=re.MULTILINE
        )
    yaml_limpo = regra_corrigida

    # 1. PyYAML - validação da sintaxe:
    print(" [1/3] -> Validando a sintaxe com PyYAML")
    try:
        regra_dict = yaml.safe_load(yaml_limpo)
    except yaml.YAMLError as e:
        msg_erro = f"[1/3] falhou (erro de sintaxe YAML. \nDetalhes: {e})"
        print(f"    ERRO: \n{msg_erro}")
        return{"erro_validacao":msg_erro, "tentativas":tentativas}
    
    # 2. Validação pelo Python:
    print(" [2/3] -> Validando estrutura mínima")
    if not isinstance(regra_dict, dict):
        msg_erro = "Etapa 2 falhou - o texto gerado não é um YAML válido."
        print(f"    ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    
    campos_obrigatorios = ["title", "logsource", "detection"]
    for campo in campos_obrigatorios:
        if campo not in regra_dict:
            msg_erro = f"Etapa 2 falhou - faltou campo obrigatório: '{campo}'"
            print(f"    ERRO: \n{msg_erro}")
            return {"erro_validacao":msg_erro, "tentativas":tentativas}
        
    # ~* VALIDAÇÃO DE TAGS MITRE ATT&CK *~
    tags = regra_dict.get("tags", [])
    if tags:
        validas, invalidas = validar_tags_attack(tags)
        if invalidas:
            msg_erro = (
                f"Etapa 2 falhou - as seguintes tags não existem na taxonomia "
                f"MITRE ATT&CK: {', '.join(invalidas)}. "
                f"Use APENAS tags no formato 'attack.tXXXX' (técnicas reais, ex: "
                f"attack.t1190) ou 'attack.<tatica>' (ex: attack.initial-access, "
                f"attack.execution, attack.persistence). "
                f"Remova ou substitua as tags inválidas por equivalentes reais."
            )
            print(f"    ERRO: \n{msg_erro}")
            return {"erro_validacao": msg_erro, "tentativas": tentativas}
        else:
            print("    -> Todas as tags ATT&CK são válidas.")

    # 3. pySigma - validação semântica do Sigma:
    print(" [3/3] -> Validação semântica e lógica pelo pySigma")
    try:
        colecao = SigmaCollection.from_yaml(yaml_limpo)
    except SigmaError as e:
        msg_erro = f"Etapa 3 falhou - erro de semântica - \npySigma relata: {e}"
        print(f"    ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    except Exception as e:
        msg_erro = f"Etapa 3 falhou - \npySigma relata: {e}"
        print(f"    ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    
    print("\n ---> Regra validada pelas 3 etapas.\n")
    return{
        "erro_validacao": "APROVADO",
        "regra_gerada": yaml_limpo,
        "tentativas": tentativas
    }

# >>>>>>>>>>>>> roteador de validação <<<<<<<<<<<<<<
#não altera o estado, apenas lê o erro e decide o próximo passo, se precisa corrigir ou não
def roteador_de_validacao(state: GraphState) -> str:
    erro = state.get("erro_validacao", "")
    tentativas = state.get("tentativas", 0)

    if erro == "APROVADO":
        return "fim"
    if tentativas >= 4:
        print("\n!!! Atingiu 4 tentativas de correção; já é suficiente.")
        return "fim"
    print("\n -> Enviando regra para correção...")
    return "refazer"

# >>>>>>>>>>>>> montagem e compilação do grafo <<<<<<<<<<<<<<
#print("\n")
def criar_agente():
    builder = StateGraph(GraphState)    #montando a arquitetura do grafo langgraph

    # i) adicionando os nós no grafo:
    builder.add_node("entendimento", no_1_classificador)
    builder.add_node("api", no_2_api)
    builder.add_node("rag", no_3_rag)
    builder.add_node("geracao", no_4_gerador)
    builder.add_node("validacao", no_5_validador)

    # ii) fluxo do grafo:
    #     a API (nó 2) roda antes do RAG (nó 3) para enriquecer a busca vetorial
    #     com a descrição técnica da ameaça.
    builder.add_edge(START, "entendimento")
    builder.add_edge("entendimento", "api")
    builder.add_edge("api", "rag")
    builder.add_edge("rag", "geracao")
    builder.add_edge("geracao", "validacao")

    # iii) rota condicional:
    builder.add_conditional_edges(
        "validacao",    #a decisão parte deste nó
        roteador_de_validacao,      #a função que toma a decisão
        {
            "fim": END,     #se retornar "fim", termina a execução
            "refazer":"geracao"     #se retornar "refazer", manda de novo pro nó 4
        }
    )

    # iv) compilação:
    agente_sigma = builder.compile()
    return agente_sigma

# ==========================================
# EXECUÇÃO DO AGENTE
# ==========================================
if __name__ == '__main__':
    print("\nBem vindo ao Agente_Sigma!\nCarregando modelos...\n")
    agente_sigma = criar_agente()       #chama a função e guarda o resultado
    
    while True:     #loop externo p permitir múltiplas execuções sem precisar rodar o programa de novo
    
        print("Type your prompt and end it with word 'END' in the last line. Type 'q' alone to quit.\n")    
        linhas = []
        while True:
            linha = input()
            if linha.strip().upper() == "END":
                break
            if linha.strip().lower() == "q":
                print("Encerrando o agente.\n")
                exit() 
            linhas.append(linha)
        
        entrada_terminal = "\n".join(linhas)
        if not entrada_terminal.strip():
            continue  #se o usuário só apertar enter, volta pro início do loop sem rodar o agente

        estado_inicial = {
            "input_usuario": entrada_terminal,
            "tipo_input": "",
            "termo_busca": "",
            "url_fornecida": "",
            "texto_para_rag": "",
            "contexto_pobre": False,
            "contexto_rag": "",
            "contexto_api": "",
            "regra_gerada": "",
            "erro_validacao": "",
            "tentativas": 0
        }
        
        resultado_final = agente_sigma.invoke(estado_inicial)       #.invoke() liga a máquina de estados e faz tudo acontecer
    
        if resultado_final["erro_validacao"] == "APROVADO":
            print("\n\tDeu certo.\n")
        else:
            print("\n\tA execução falhou.\n")
        #print(resultado_final["regra_gerada"])

        # ==========================================
        # SALVANDO A REGRA EM ARQUIVO
        # ==========================================
        regra = resultado_final["regra_gerada"]
        if regra:
            #extrai o title via regex p usar como nome do arquivo:
            match = re.search(r'^title:\s*(.+)$', regra, re.MULTILINE)

            if match:
                #limpa o título p ser um nome de arquivo válido e remove aspas se tiver:
                title = match.group(1).strip().strip('"\'')
                #substitui caracteres inválidos por underline:
                base = re.sub(r'[^a-zA-Z0-9_-]', '_', title).strip('_') 
                
                if not base:        
                    filename = "regra_sem_nome.yml"
                else:
                    filename = base + ".yml"
            else:
                filename = "regra_sigma_gerada.yml"     #fallback

            pasta_destino = os.path.join(BASE_DIR, "..", "data", "regras_geradas")
            os.makedirs(pasta_destino, exist_ok=True)

            caminho_arquivo = os.path.join(pasta_destino, filename)
            
            #contador para adicionar no nome do arquivo caso rode mais de uma vez para a mesma regra:
            cont = 1    
            while os.path.exists(caminho_arquivo):
                nome_base = filename.replace(".yml", "")
                caminho_arquivo = os.path.join(pasta_destino, f"{nome_base}_{cont}.yml")
                cont += 1
            
            #salva o arquivo em modo escrita (write):
            with open(caminho_arquivo, "w", encoding="utf-8") as file:
                file.write(regra)
            
            print(f"\n\tRegra salva em: {caminho_arquivo}\n")