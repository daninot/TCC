import re
from typing import TypedDict

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


# >>>>>>>> NÓ 1 (classificador de entrada) <<<<<<<<<<
def no_1_classificador(state: GraphState) -> GraphState: #recebe um state como argumento; -> G.. avisa o langgraph q a função vai devolver um dicionário GraphState
    
    #"""Analisa o input do usuário e define qual será a estratégia de busca."""
    print("[Nó 1] Classificando input...")
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

# >>>>>>>> NÓ 2 () <<<<<<<<<<
