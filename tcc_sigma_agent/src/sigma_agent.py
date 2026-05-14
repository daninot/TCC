import re
import requests     #biblioteca pra conversar com a internet (pip3 install requests)
from typing import TypedDict
from langchain_huggingface import HuggingFaceEmbeddings
# from langchain_community.vectorstores import Chroma       #deprecated
from langchain_chroma import Chroma
#from langchain_ollama import ChatOllama

# >>>>>>>> máquina de estados <<<<<<<<<<
# nó 1 = 
# nó 2 = 
# nó 3 = 
# nó 4 = 
# nó 5 = 



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


# >>>>>>>> NÓ 1 (classificador determinístico de entrada) <<<<<<<<<<
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

# >>>>>>>> NÓ 2 (procura contexto no RAG) <<<<<<<<<<
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
# 5. TESTANDO O NÓ 2
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


#>>>>>> NÓ 3 (API) <<<<<< 
#Vai buscar informações técnicas na internet sobre a ameaça extraída.
#Se a API falhar ou não tiver internet, o agente não dá erro, vai seguir em frente.
def no_3_api(state: GraphState) -> GraphState:

#
    print("||Nó 3|| Buscando dados em APIs externas...")
    
    #opção 1: CVE
    tipo = state["tipo_input"]
    termo = state["termo_busca"]
    contexto_api = "Nenhum dado externo coletado."      #inicialização da váriavel que vai pegar esse contexto

    if tipo == "cve"    and termo:
        print(f"--> Consultando MITRE para '{termo}'. . .")
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
        print(f"--> Consultando plataforma para a hash '{termo}'. . .")
        #as hashes são consultadas no virustotal.com, mas ele exige uma API key pessoal. tenho aqui uma simulação apenas para entender a lógica
        contexto_api=(
            f"Simulação de API: a hash {termo} foi identificada como malware"
            f"{termo} cria processo x em diretórios temporários"
            f"{termo} está associada à man in the middle"
        )

    #opção 3: texto livre
    else:
        print("--> Busca por texto livre (sem consulta de hash e CVE).")

    return {"contexto_api": contexto_api}   #atualiza o graphstate com a matéria-prima técnica

# ==========================================
# 5. TESTANDO O NÓ 3
# ==========================================
# Testar se o script consegue baixar dados reais da internet.
__name__ == "__main__"
estado_teste = {
    "input_usuário": "Preciso de uma regra Sigma para o CVE-2021-44228",
    "tipo_input": "cve",
    "termo_busca": "CVE-2021-44228"     #log4shell
}
estado_atualizado = no_3_api(estado_teste)
print("\n~*Resultado do contexto da API*~")
print(estado_atualizado["contexto_api"])
