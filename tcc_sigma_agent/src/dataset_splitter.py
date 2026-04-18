import os
import random
import shutil
import yaml

# Configurações de pastas
TRAIN_DIR = "../data/rag_knowledge"    # Onde estão suas 50 regras base
TEST_DIR = "../data/test_cases"        # Onde as 50 regras de teste serão salvas
SIGMA_REPO_DIR = "../data/sigma_repo"  # Onde você baixou o repositório completo da SigmaHQ (ex: pasta 'rules')

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
    print("1. Analisando a distribuição da base de treinamento...")
    train_distribution = {}
    train_files = set()

    for filename in os.listdir(TRAIN_DIR):
        if filename.endswith(".yml"):
            filepath = os.path.join(TRAIN_DIR, filename)
            train_files.add(filename) # Guarda o nome para não copiar duplicado
            key = get_logsource_key(filepath)
            
            if key != "unknown":
                train_distribution[key] = train_distribution.get(key, 0) + 1

    print(f"Distribuição encontrada no Treino: {train_distribution}")

    print("\n2. Mapeando o repositório completo da SigmaHQ...")
    pool_rules = {} # Dicionário: { chave_logsource : [caminhos_dos_arquivos] }
    
    # Percorre todas as subpastas do repositório Sigma
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):
        for filename in files:
            if filename.endswith(".yml") and filename not in train_files: # Evita Vazamento de Dados!
                filepath = os.path.join(root, filename)
                key = get_logsource_key(filepath)
                if key != "unknown":
                    if key not in pool_rules:
                        pool_rules[key] = []
                    pool_rules[key].append(filepath)

    print("\n3. Sorteando as regras para a base de Teste...")
    os.makedirs(TEST_DIR, exist_ok=True)
    
    regras_copiadas = 0
    for key, count in train_distribution.items():
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