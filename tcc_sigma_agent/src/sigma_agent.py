import re
import yaml
import requests     #biblioteca pra conversar com a internet (pip3 install requests)
from typing import TypedDict
from langchain_huggingface import HuggingFaceEmbeddings
# from langchain_community.vectorstores import Chroma       #deprecated
from langchain_chroma import Chroma
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

# >>>>>>>> máquina de estados <<<<<<<<<<
# nó 1 = classificador determinístico de entrada (Entendimento)
# nó 2 = recupera contexto com RAG
# nó 3 = procura informações nas APIs (threat intelligence)
# nó 4 = criação da regra com LLM local
# nó 5 = validação com o Sigma CLI


# >>>>>>>> ESTADO <<<<<<<<<     (caderno de anotações)
class GraphState(TypedDict):
    input_usuario: str       #entrada: "gere uma regra para ..."
    tipo_input: str          #pode ser cve, uma hash ou 'texto_livre'
    termo_busca: str         #cve ou hash extraído
    contexto_rag: str        #exemplos de regras (nó 2)
    contexto_api: str        #dados técnicos da ameaça (nó 3)
    regra_gerada: str        #YAML gerado pela LLM (nó 4)
    erro_validacao: str      #erro do sigma-cli
    tentativas: int          #qtas vezes a LLM tentou refazer a regra

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 1 (classificador determinístico de entrada) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#vai analisar a entrada do usuário e definir qual será a estratégia de busca
def no1_classificador(state: GraphState) -> GraphState: #recebe um state como argumento; -> G.. avisa o langgraph q a função vai devolver um dicionário GraphState
    
    print("||Nó 1|| Classificando input...")
    texto = state["input_usuario"]              #acessa o dicionário state e pega o input do usuário
    
    padrao_cve = re.search(r"CVE-\d{4}-\d+", texto, re.IGNORECASE)      
    #re.search varre a string inteira procurando o primeiro local onde o padrão regex acontece p/ encontrar um padrão de cve (CVE-2024-1234)
    
    padrao_hash = re.search(r"\b[a-fA-F0-9]{32,64}\b", texto)           #procura um padrão de hash (md5, sha1, sha256); explicação nas anotações
    
    if padrao_cve:
        tipo = "cve"
        termo = padrao_cve.group().upper()
    elif padrao_hash:
        tipo = "hash"
        termo = padrao_hash.group().lower()
    else:
        tipo = "texto_livre"
        termo = texto           #mantém o texto inteiro para buscar no banco vetorial depois
        
    print(f" -> Tipo: {tipo}")
    print(f" -> Termo isolado: {termo}")
    
    return {"tipo_input": tipo, "termo_busca": termo}           #retorna apenas o que for atualizar no "Caderno"

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 2 (procura contexto no RAG) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# i)primeiro crio o banco (chromadb) para transformar as regras em vetores matemáticos (embeddings) e os salvar no chromadb;
# ii) depois o agente lê o banco e busca no RAG as regras mais parecidas com a entrada;
# agora no laptop vou usar o modelo all-MiniLM-L6-v2 de embeddings
# então:    o nó 2 vai acessar o chromadb e buscar as regras Sigma que são mais parecidas com a entrada;
#           essas regras servirão de molde pra LLM (few-shot prompting)
def no2_rag(state: GraphState) -> GraphState:

    print("\n||Nó 2|| Buscando contexto no RAG...\n")
    
    # Se o Nó 1 identificou um termo (ex: um CVE), usamos ele para buscar.
    # Se for texto livre, usamos a frase inteira do usuário.
    termo_pesquisa = state["termo_busca"] if state.get("termo_busca") else state["input_usuario"]
    print(f" -> Pesquisando no banco vetorial por: {termo_pesquisa}")

    # Carregamos o modelo leve de embeddings e o banco criado
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_store = Chroma(
        persist_directory="../data/chroma_db", 
        embedding_function=embeddings
    )

    # Buscamos as 2 regras que mais se aproximam do contexto pedido
    # Usamos k=2 para não sobrecarregar a memória do nosso pequeno Qwen 2.5
    resultados = vector_store.similarity_search(termo_pesquisa, k=2)

    # Pegamos o conteúdo dos arquivos YAML encontrados e juntamos em uma string só
    contexto_formatado = "\n\n---\n\n".join([doc.page_content for doc in resultados])
    
    print(f" -> {len(resultados)} regras de exemplo recuperadas com sucesso.")
    
    # Atualizamos o "caderno de anotações" com os exemplos
    return {"contexto_rag": contexto_formatado}

# ==========================================
# TESTANDO O NÓ 2
# ==========================================
# Atualize o bloco final do arquivo para testarmos a passagem de bastão:
#if __name__ == "__main__":
    # Teste de integração: Nó 1 passando para o Nó 2
#    estado_inicial = {"input_usuario": "Crie uma regra para detectar a execução do mimikatz na memória."}
    
    # Executa o Nó 1
#    estado_atualizado_1 = no1_classificador(estado_inicial)
    
    # O LangGraph junta os estados nos bastidores, então vamos emular isso:
#    estado_inicial.update(estado_atualizado_1) 
    
    # Executa o Nó 2
#    estado_atualizado_2 = no2_rag(estado_inicial)
    
#    print("\n[RESULTADO FINAL DO ESTADO]")
#    print(f"Tipo: {estado_atualizado_1['tipo_input']}")
#    print(f"Tamanho do Contexto RAG gerado: {len(estado_atualizado_2['contexto_rag'])} caracteres")

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>> NÓ 3 (API) <<<<<<<< 
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Vai buscar informações técnicas na internet sobre a ameaça extraída.
#Se a API falhar ou não tiver internet, o agente não dá erro, vai seguir em frente.
def no_3_api(state: GraphState) -> GraphState:

    print("||Nó 3|| Buscando dados em APIs externas...")
    
    #opção 1: CVE
    tipo = state["tipo_input"]
    termo = state["termo_busca"]
    contexto_api = "Nenhum dado externo coletado."      #inicialização da váriavel que vai pegar esse contexto

    if tipo == "cve"    and termo:
        print(f"-> Consultando MITRE para '{termo}'. . .")
        url = f"https://cveawg.mitre.org/api/cve/{termo}"       #API pública e gratuita que não exige API key

        try:
            resposta = requests.get(url, timeout=10)        #timeout evita q o código trave se cair a internet
            if resposta.status_code == 200:     # ?
                dados = resposta.json()

                descricoes = dados.get("containers", {}).get("cna", {}).get("descriptions", [])     #vai navegar no JSON p achar a descrição em inglês
                if descricoes:
                    texto_descricao = descricoes[0].get("value", "Descrição indisponível.")
                    contexto_api = f"Informação do MITRE para {termo}: {texto_descricao}"
                    print(" --> Dados extraídos com sucesso da web.")
                else:
                    print(f" --> CVE não encontrado na API ou erro {resposta.status_code}.")
        except Exception as e:
            print(f" --> Falha de conexão com API: {e}")

    #opção 2: Hash
    elif tipo == "hash" and termo:
        print(f"-> Consultando plataforma para a hash '{termo}'. . .")
        #as hashes são consultadas no virustotal.com, mas ele exige uma API key pessoal. tenho aqui uma simulação apenas para entender a lógica
        contexto_api=(
            f"Simulação de API: a hash {termo} foi identificada como malware"
            f"{termo} cria processo x em diretórios temporários"
            f"{termo} está associada à man in the middle"
        )

    #opção 3: texto livre
    else:
        print("-> Busca por texto livre (sem consulta de hash e CVE).")

    return {"contexto_api": contexto_api}   #atualiza o graphstate com a matéria-prima técnica

# ==========================================
# TESTANDO O NÓ 3
# ==========================================
# Testar se o script consegue baixar dados reais da internet.
#__name__ == "__main__"
#estado_teste = {
#    "input_usuário": "Preciso de uma regra Sigma para o CVE-2021-44228",
#    "tipo_input": "cve",
#    "termo_busca": "CVE-2021-44228"     #log4shell
#}
#estado_atualizado = no_3_api(estado_teste)
#print("\n~*Resultado do contexto da API*~")
#print(estado_atualizado["contexto_api"])

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>>> NÓ 4 (GERAÇÃO DA REGRA - LLM) <<<<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 
def no_4_gerador(state: GraphState) -> GraphState:
    tentativa_atual = state.get("tentativas", 0) + 1    #sinalizar quantas tentativas
    print("\n||Nó 4|| Iniciando o motor de IA para gerar a regra...")

    llm = ChatOllama(model="qwen2.5:1.5b", temperature=0.1)

    prompt = f"""Você é um Engenheiro de Detecção de Ameaças (Threat Hunter) Sênior.
    Sua tarefa é criar uma regra Sigma válida baseada exclusivamente no pedido do usuário.

    PEDIDO DO USUÁRIO:
    {state['input_usuario']}

    MOLDE DE FORMATAÇÃO -- Baseie a estrutura do seu YAML rigorosamente nos exemplos a seguir:
    {state['contexto_rag']}

    CONTEXTO TÉCNICO ADICIONAL -- Use estas informações para criar a lógica de detecção, se relevante:
    {state['contexto_api']}
    """
    
    erro_anterior = state.get("erro_validacao","")
    if erro_anterior and erro_anterior != "APROVADO":
        prompt+= f"""
        ATENÇÃO! SUA TENTATIVA ANTERIOR FALHOU:
        O código YAML que você gerou anteriormente falhou na validação com o seguinte erro:
        {erro_anterior}.

        Regra gerada com erro:
        {state.get('regra_gerada','')}

        Corrija o erro apontado acima e reescreva o código YAML perfeitamente.
        """
    prompt+= """    
    Instruções:
    1. Retorne APENAS o código YAML da regra Sigma.
    2. Não adicione explicações, saudações ou formatações markdown fora do bloco de código.
    3. Certifique-se de que os campos obrigatórios do Sigma (title, logsource, detection, condition) estejam presentes.
    """

    print(" -> Enviando contexto para a GPU com Qwen 2.5. . .")
    resposta = llm.invoke(prompt)   #chama a LLM
    print(" -> Regra gerada.")
    return {"regra_gerada": resposta.content}
            
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>> NÓ 5 (VALIDADOR SINTÁTICO) <<<<<<<<<< 
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#vê se o YAML gerado pela LLM possui algum erro; confere a qualidade.
def no_5_validador(state: GraphState) ->GraphState:

    print("\n||Nó 5|| Revisando em 3 etapas a qualidade da regra gerada...")

    regra_revisao = state.get("regra_gerada", "")
    tentativas = state.get("tentativas", 0) + 1

    # ~* LIMPEZA DE MARKDOWN *~ agora vai limpar tudo de markdown e/ou vai extrair tudo entre ``` e ```:
    padrao_regex = ```r"(?:yaml)?\n(.?)\n"```
    match = re.search(padrao_regex, regra_revisao, re.DOTALL | re.IGNORECASE)
    yaml_limpo = match.group(1).strip() if match else regra_revisao.strip()

    # 1. PyYAML - validação da sintaxe:
    print("~~ [1/3] ~~ Validando a sintaxe com PyYAML")
    try:
        regra_dict = yaml.safe_load(yaml_limpo)
    except yaml.YAMLError as e:
        msg_erro = f"[1/3] falhou (erro de sintaxe YAML. \nDetalhes: {e})"
        print(f"ERRO: \n{msg_erro}")
        return{"erro_validacao":msg_erro, "tentativas":tentativas}
    
    # 2. Validação pelo Python:
    print("~~ [2/3] ~~ Validando estrutura mínima")
    if not isinstance(regra_dict, dict):
        msg_erro = "Etapa 2 falhou - o texto gerado não é um YAML válido."
        print(f"ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    
    campos_obrigatorios = ["title", "logsource", "detection"]
    for campo in campos_obrigatorios
        if campo not in regra_dict:
            msg_erro = f"Etapa 2 falhou - faltou campo obrigatório: '{campo}'"
            print(f"ERRO: \n{msg_erro}")
            return {"erro_validacao":msg_erro, "tentativas":tentativas}
        
    # 3. pySigma - validação semântica do Sigma:
    print("~~ [3/3] ~~ Validação semântica e lógica pelo pySigma")
    try:
        colecao = SigmaCollection.from_yaml(yaml_limpo)
    except SigmaError as e:
        msg_erro = f"Etapa 3 falhou - erro de semântica - \npySigma relata: {e}"
        print(f"ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    except Exception e:
        msg_erro = f"Etapa 3 falhou - \npySigma relata: {e}"
        print(f"ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    
    print("\n--- Regra validada pelas 3 etapas. ---\n")
    return{
        "erro_validacao": "APROVADO",
        "regra_gerada": yaml_limpo,
        "tentativas": tentativas
    }



