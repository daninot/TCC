import os
import random
import shutil
import yaml

# Configurações de pastas
TRAIN_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/rag_knowledge/"    #onde estão as 50 regras de treino
TEST_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/test_cases/"        #onde as 50 regras de teste serão salvas
SIGMA_REPO_DIR = "/home/daniela/Documents/TCC/sigma/"  #repositório completo SigmaHQ

def get_logsource_key(filepath):
    """Lê um arquivo YAML e extrai a assinatura do logsource (category, product, service)."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:       
            # Algumas regras Sigma têm múltiplos documentos YAML separados por ---
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and 'logsource' in doc:
                    logsource = doc['logsource']
                    category = logsource.get('category', 'any')
                    product = logsource.get('product', 'any')
                    service = logsource.get('service', 'any')
                    return f"{category}_{product}_{service}"
    except Exception as e:
        # Ignora arquivos que não puderam ser lidos corretamente
        pass
    return "unknown"

def main():

    #reconhecer e separar os arquivos de treinamento:

    print("1. Analisando a distribuição da base de treinamento...")
    train_distribution = {}     #cria um dicionário vazio; vai guardar pares "chave:valor"
    train_files = set()         #cria um conjunto; vai memorizar os nomes dos arquivos

    for filename in os.listdir(TRAIN_DIR):      #os.listdir() lê a pasta e devolve uma lista com todos os arquivos lá dentro
        if filename.endswith(".yml"):   
            filepath = os.path.join(TRAIN_DIR, filename)    #filepath é uma lista de arrays 'caminho da pasta + nome do arquivo'
            train_files.add(filename)                       #guarda no conjunto só o nome para não copiar duplicado
            key = get_logsource_key(filepath)       #key recebe o retorno da função criada (lê o arquivo e retorna uma "assinatura" em string)
            
            if key != "unknown":        
                train_distribution[key] = train_distribution.get(key, 0) + 1

    print(f"Distribuição encontrada no Treino: {train_distribution}")

    print("\n2. Mapeando o repositório completo de SigmaHQ...")
    pool_rules = {}     #dicionário: {chave_logsource:[caminhos_dos_arquivos]}
                        #o índice vai ser a "assinatura" e o valor vai ser uma lista com todos os caminhos de todos os arquivos que batem com essa assinatura
    
    
    #percorre todas as subpastas do repositório Sigma
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):       #essa função entra em todas as subpastas e te devolve onde está(root), as pastas lá dentro e os arquivos
        for filename in files:                              #itera dentro da última pasta na folha da árvore
            if filename.endswith(".yml") and filename not in train_files: #ignora os arquivos que estão na base de treinamento
                filepath = os.path.join(root, filename)     #filepath recebe diretório+nome do aquivo
                key = get_logsource_key(filepath)           #key é a assinatura de cada arquivo
                if key != "unknown":                        #valida se tem key
                    if key not in pool_rules:               #se é a primeira vez desta assinatura aqui
                        pool_rules[key] = []                #cria uma lista vazia pra ela
                    pool_rules[key].append(filepath)        #vai adicionando no final da lista o caminho do arquivo que tem esta assinatura

    print("\n3. Sorteando as regras para a base de Teste...")
    os.makedirs(TEST_DIR, exist_ok=True)
    
    regras_copiadas = 0
    for key, count in train_distribution.items():   #percorre a lista train_distribution, uma vez para cada assinatura; #key recebe o nome da assinatura e count recebe a qtd
        if key in pool_rules and len(pool_rules[key]) >= count:
            # Sorteia 'count' regras aleatórias que batem com esta categoria
            selected_files = random.sample(pool_rules[key], count)
            for src_path in selected_files:
                dst_path = os.path.join(TEST_DIR, os.path.basename(src_path))
                shutil.copy2(src_path, dst_path)
                regras_copiadas += 1
        else:
            disponivel = len(pool_rules.get(key, []))
            print(f"Aviso: Não há regras suficientes no repositório para '{key}'. Precisava de {count}, encontrou {disponivel}.")

    print(f"\nSucesso! {regras_copiadas} regras foram selecionadas e copiadas para a pasta de testes.")

if __name__ == "__main__":
    main()