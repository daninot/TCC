import os
import random
import shutil
import yaml


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
        if filename.endswith(".yml"):           #filename recebe, em cada loop, o nome do arquivo da lista
            filepath = os.path.join(TRAIN_DIR, filename)    #filepath recebe a concatenação 'caminho da pasta + nome do arquivo' para cada volta do loop
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

    print("\n3. Sorteando as regras para a base de teste:")
    os.makedirs(TEST_DIR, exist_ok=True)    #os.makedirs seria o mkdir()
    
    regras_copiadas = 0
    for key, count in train_distribution.items():   #na lista, o loop gira uma vez para cada assinatura; #key recebe o nome da assinatura e count recebe a qtd
        if key in pool_rules and len(pool_rules[key]) >= count:    #checa se o repositório original tem a chave e se a lista de arquivos encontrados tem um tamanho maior ou igual ao que preciso
            
            #sorteia 'count' regras aleatórias que batem com esta categoria
            selected_files = random.sample(pool_rules[key], count)  #sorteia count arquivos; selected_files é a lista com os caminhos sorteados
            
            for src_path in selected_files:     #percorre a lista e atribui a src_path o valor a cada loop
                
                caminho = os.path.relpath(src_path, SIGMA_REPO_DIR) #pega o caminho do arquivo relativo à pasta raíz do sigma
                caminho_vira_nome = caminho.replace(os.sep, '_')    #pega o caminho e troca as barras de diretório por '_' pra não dar conflito de nomes na pasta teste
                
                dst_path = os.path.join(TEST_DIR, caminho_vira_nome)  #agora não vai ter arquivo de nome igual, causando conflito pra salvar na pasta
                shutil.copy2(src_path, dst_path)    #faz a cópia física do arquivo no HD
                regras_copiadas += 1    
        
        else:   #se não tiver arquivos suficientes no repositório original...
            disponivel = len(pool_rules.get(key, []))
            print(f"Aviso: Não há regras suficientes no repositório para '{key}'. Precisava de {count}, encontrou {disponivel}.")

    print(f"\nSucesso! {regras_copiadas} regras foram selecionadas e copiadas para a pasta de testes.")

if __name__ == "__main__":
    main()