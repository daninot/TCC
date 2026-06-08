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
from langgraph.graph import StateGraph, START, END
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from bs4 import BeautifulSoup
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_DIR = os.path.join(BASE_DIR, "..", "data", "chroma_db")
EMBEDDINGS_MODEL = HuggingFaceEmbeddings(model_name="BAAI/bge-small-en-v1.5")
RERANKER_MODEL = CrossEncoder("cross-enco"der/ms-marco-MiniLM-L-12-v2")
PROMPT_PATH = os.path.join(BASE_DIR, "..", "prompts", "sigma_system_prompt.md")
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    SIGMA_SYSTEM_PROMPT = f.read()

# >>>>>>>> máquina de estados <<<<<<<<<<
# nó 1 = classificador determinístico de entrada (Entendimento)
# nó 2 = recupera contexto com RAG
# nó 3 = procura informações nas APIs (threat intelligence)
# nó 4 = criação da regra com LLM local
# nó 5 = validação com o Sigma CLI

#função para encontrar todas as menções de CVE e CWE em qualquer texto:
def extrair_referencias(texto: str):
    cves = set(m.group().upper() for m in re.finditer(r"CVE-\d{4}-\d+", texto, re.IGNORECASE))
    cwes = set(m.group().upper() for m in re.finditer(r"CWE-\d+", texto, re.IGNORECASE))
    return cves, cwes

#função para extrair palavras significativas do caminho de uma URL. usado quando a página fica inacessível:
def extrair_palavras_chave_url(url:str):
    caminho = urlparse(url).path
    texto = re.sub(r"[/\-_\.]+", " ", caminho)
    lixo = {"html", "htm", "php", "asp", "aspx", "vuln", "detail", "www"}
    return [
        p.lower() for p in texto.split()
        if len(p) >= 3 and not p.isdigit() and p.lower() not in lixo
    ]

#função para consultar a API do MITRE para um CVE:
def consulta_mitre(cve_id:str):
    try:
        r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=10)
        if r.status_code == 200:
            descricoes = r.json().get("containers",{}).get("cna",{}).get("descriptions",[])
            if descricoes:
                return descricoes[0].get("value", "")   #retorna a descrição ou None
    except requests.exceptions.RequestException:
        pass
    return None

#função que consulta a API do NVD para um CVE:
def consulta_nvd(cve_id:str):
    try:
        url_api = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = requests.get(url_api, timeout=10)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities",[])
            if vulns:
                cve_item = vulns[0].get("cve",{})
                descricao = next(
                    (x["value"] for x in cve_item.get("descriptions",[]) if x.get("lang") == "en"),
                    None
                )
                cwes = [
                    d["value"]
                    for w in cve_item.get("weaknesses",[])
                    for d in w.get("description",[])
                    if d.get("lang") == "en"
                ]
                cvss = None
                for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if chave in cve_item.get("metrics",{}) and cve_item["metrics"][chave]:
                        cvss = cve_item["metrics"][chave][0].get("cvssData", {}).get("baseScore")
                        break
                return {"descricao": descricao, "cwes": cwes, "cvss": cvss}
    except requests.exceptions.RequestException:
        pass
    return None


# >>>>>>>> ESTADO <<<<<<<<<     (caderno de anotações)
class GraphState(TypedDict):
    input_usuario: str       #entrada: "gere uma regra para ..."
    tipo_input: str          #pode ser cve, uma hash ou 'texto_livre'
    termo_busca: str         #cve ou hash extraído
    url_fornecida: list       #possível url que esteja no input
    contexto_rag: str        #exemplos de regras (nó 2)
    contexto_api: str        #dados técnicos da ameaça (nó 3)
    regra_gerada: str        #YAML gerado pela LLM (nó 4)
    erro_validacao: str      #erro do sigma-cli
    tentativas: int          #qtas vezes a LLM tentou refazer a regra

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 1 (classificador determinístico de entrada) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#vai analisar a entrada do usuário e definir qual será a estratégia de busca
def no_1_classificador(state: GraphState) -> GraphState: #recebe um state como argumento; -> G.. avisa o langgraph q a função vai devolver um dicionário GraphState
    
    print("\n[Nó 1] Classificando input...")
    texto = state.get("input_usuario", "")              
    
    urls_brutas = re.findall(r"https?://[^\s]+", texto)     #encontra TODAS as URLs (retorna uma lista de strings)
    urls_limpas = [u.rstrip(r".,;!?)\]}>'\"") for u in urls_brutas]      #limpa a pontuação do final de CADA URL encontrada

    #remove TODAS as URLs do texto antes de buscar CVE/hash
    texto_sem_url = texto       
    for u in urls_limpas:
        texto_sem_url = texto_sem_url.replace(u, "")

    padrao_cve = re.search(r"CVE-\d{4}-\d+", texto_sem_url, re.IGNORECASE)      
    #re.search varre a string inteira procurando o primeiro local onde o padrão regex acontece p/ encontrar um padrão de cve (CVE-2024-1234)
    padrao_hash = re.search(r"\b[a-fA-F0-9]{32,64}\b", texto_sem_url)           #procura um padrão de hash (md5, sha1, sha256); explicação nas anotações

    #classifica o tipo principal de input: 
    if padrao_cve:
        tipo = "cve"
        termo = padrao_cve.group().upper()
    elif padrao_hash:
        tipo = "hash"
        termo = padrao_hash.group().lower()
    else:
        tipo = "texto_livre"
        termo = texto  #mantém o texto inteiro para buscar no banco vetorial depois
    
    print(f" -> Tipo: {tipo}")
    print(f" -> Termo isolado: {termo}")
    if urls_limpas:
        print(f" -> URLs detectadas: {len(urls_limpas)} encontrada(s).")
        for u in urls_limpas:
            print(f"    - {u}")

    #retorna atualizando o estado com a nova lista de URLs
    return {
        "tipo_input": tipo, 
        "termo_busca": termo, 
        "urls_fornecidas": urls_limpas
    }

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 2 (procura contexto no RAG) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# i)primeiro crio o banco (chromadb) para transformar as regras em vetores matemáticos (embeddings) e os salvar no chromadb;
# ii) depois o agente lê o banco e busca no RAG as regras mais parecidas com a entrada;
# agora no laptop vou usar o modelo bge-small-en-v1.5 de embeddings
# então:    o nó 2 vai acessar o chromadb e buscar as regras Sigma que são mais parecidas com a entrada;
#           essas regras servirão de molde pra LLM (few-shot prompting)
def no_2_rag(state: GraphState) -> GraphState:

    print("\n[Nó 2] Buscando contexto no RAG - com re-ranking\n")
    
    # Se o Nó 1 identificou um termo (ex: um CVE), usamos ele para buscar.
    # Se for texto livre, usamos a frase inteira do usuário.
    termo_pesquisa = state["termo_busca"] if state.get("termo_busca") else state["input_usuario"]
    print(f" -> Pesquisando no banco vetorial por: {termo_pesquisa[:80]}\n")

    # Carregamos o modelo leve de embeddings e o banco criado
    #embeddings = HuggingFaceEmbeddings(model_name="bge-small-en-v1.5")
    vector_store = Chroma(
        persist_directory=CHROMA_DIR, 
        embedding_function=EMBEDDINGS_MODEL
    )

    #1a busca no RAG usando similaridade de cosseno; faz uma busca ampla, pega 20 candidados:
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

    contexto_formatado = "\n\n---\n\n".join([doc.page_content for _, doc in top_5])
    return {"contexto_rag": contexto_formatado}

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>>>>>>>>>>>>> NÓ 3 (API) <<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Vai buscar informações técnicas na internet sobre a ameaça extraída.
#Se a API falhar ou não tiver internet, o agente não dá erro, vai seguir em frente.
def no_3_api(state: GraphState) -> GraphState:

    print("\n||Nó 3|| Buscando dados em APIs externas...")
    
    tipo = state.get("tipo_input", "")  #usar .get() evita q o programa quebre (keyerror) caso as chaves não existam no estado
    termo = state.get("termo_busca", "")
    url = state.get("url_fornecida", "")
    entrada_usuario = state.get("input_usuario", "")
    contexto_api = "Nenhum dado externo coletado."      #inicialização da váriavel que vai pegar esse contexto
    trechos = []

    #1: procura CVEs e CWEs em todo o texto de entrada do usuário:
    cves_encontrados, cwes_encontrados = extrair_referencias(entrada_usuario)

    #2: procura uma URL para acessar:
    if url:
        print(f" -> URL fornecida detectada. Acessando: {url}")
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }
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
                texto_limpo = soup.get_text(separator=" ", strip=True)
                trechos.append(f"Conteúdo da URL {url}:\n{texto_limpo[:3000]}")
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
        
    #3: Consulta o MITRE e o NVD para cada CVE encontrado no texto ou na URL:
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

    #4: Registra os CWEs encontrados como contexto adicional:
    if cwes_encontrados:
        trechos.append(f"CWEs identificados: {', '.join(sorted(cwes_encontrados))}")

    #5: Se for Hash consulta a API do VirusTotal:
    if tipo == "hash" and termo:
        #print(f" -> Consultando plataforma para a hash '{termo}'. . .")
        #as hashes são consultadas no virustotal.com, mas ele exige uma API key pessoal. tenho aqui uma simulação apenas para entender a lógica
        trechos.append(
            f"Simulação de API: a hash {termo} foi identificada como malware\n"
            f"{termo} cria processo x em diretórios temporários.\n"
            f"{termo} está associada à man in the middle."
        )
        print(" -> Dados da hash carregados.")
    
    #6: junta tudo
    if trechos:
        contexto_api = "\n\n---\n\n".join(trechos)
    else:
        print(" -> Sem fonte de texto com referências.")
    return {"contexto_api": contexto_api}   #atualiza o graphstate com a matéria-prima técnica


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>>> NÓ 4 (GERAÇÃO DA REGRA - LLM) <<<<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 
def no_4_gerador(state: GraphState) -> GraphState:
    tentativa_atual = state.get("tentativas", 0) + 1    #sinalizar quantas tentativas
    print(f"\n[Nó 4] Gerando a regra... Tentativa {tentativa_atual}")

    #llm = ChatOllama(model="qwen2.5:1.5b", temperature=0.1)
    llm = ChatOllama(model="llama3.1", temperature=0.1)

    #USER PROMPT:
    user_prompt = f"""USER REQUEST:
{state['input_usuario']}

FORMATTING TEMPLATE - base the YAML structure on these real Sigma rules: 
{state['contexto_rag']}

ADDITIONAL TECHNICAL CONTEXT - use to build detection logic if relevant:
{state['contexto_api']}

OUTPUT REQUIREMENTS:
1. Return ONLY the YAML code, no markdown fences, no explanations.
2. If the USER REQUEST contains URLs, put them in 'references:'.
3. Do NOT copy URLs from the FORMATTING TEMPLATE.
4. Do NOT invent URLs that are not in the user request.
"""
    
    #caso hajam novas tentativas:
    erro_anterior = state.get("erro_validacao", "")
    if erro_anterior and erro_anterior != "APROVADO":
        user_prompt += f"""

ATTENTION - YOUR PREVIOUS ATTEMPT FAILED:
Validation error:
{erro_anterior}

Rule generated with error:
{state.get('regra_gerada', '')}

Fix the error and rewrite the YAML perfectly.
"""

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

    print("\n||Nó 5|| Revisando em 3 etapas a qualidade da regra gerada...")

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
    if tentativas >= 3:
        print("\n!!! Atingiu 3 tentativas de correção; já é suficiente.")
        return "fim"
    print("\n -> Enviando regra para correção...")
    return "refazer"

# >>>>>>>>>>>>> montagem e compilação do grafo <<<<<<<<<<<<<<
#print("\n")
def criar_agente():
    builder = StateGraph(GraphState)    #montando a arquitetura do grafo langgraph

    # i) adicionando os nós no grafo:
    builder.add_node("entendimento", no_1_classificador)
    builder.add_node("rag", no_2_rag)
    builder.add_node("api", no_3_api)
    builder.add_node("geracao", no_4_gerador)
    builder.add_node("validacao", no_5_validador)

    # ii) fluxo do grafo:
    builder.add_edge(START, "entendimento")
    builder.add_edge("entendimento", "rag")
    builder.add_edge("rag", "api")
    builder.add_edge("api", "geracao")
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