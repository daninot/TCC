import os
import random
import shutil
import yaml

SIGMA_REPO_DIR = "/home/daniela/Documents/TCC/sigma/"  
NEW_TRAIN_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/rag_knowledge/" 

def get_logsource_key(filepath):
    """Lê um arquivo YAML e extrai uma assinatura do logsource."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:       
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and 'logsource' in doc:
                    logsource = doc['logsource']
                    category = logsource.get('category', 'any')
                    product = logsource.get('product', 'any')
                    service = logsource.get('service', 'any')
                    return f"{category}_{product}_{service}"
    except Exception:
        pass
    return "unknown"

def main():
    print("1. Lendo o repositório Sigma e mapeando TODAS as regras...")
    pool_rules = {}
    
    # Percorre o repositório inteiro e agrupa as regras por assinatura
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):
        for filename in files:
            if filename.endswith(".yml") and not filename.startswith("deprecated"):
                filepath = os.path.join(root, filename)
                chave = get_logsource_key(filepath)
                
                if chave not in pool_rules:
                    pool_rules[chave] = []
                pool_rules[chave].append(filepath)

    # Remove a categoria "unknown" se houver (arquivos mal formatados)
    if "unknown" in pool_rules:
        del pool_rules["unknown"]

    print(f"Foram encontradas {len(pool_rules)} assinaturas diferentes no repositório!")
    
    # Prepara para a seleção Round-Robin (o seu loop)
    selected_files = []
    assinaturas = list(pool_rules.keys())
    random.shuffle(assinaturas) # Embaralha a fila de seleção para não pegar sempre as mesmas assinaturas nas primeiras rodadas
    
    print("\n2. Selecionando 50 regras de forma diversificada (Round-Robin)...")
    
    # Este é o loop que você idealizou:
    while len(selected_files) < 50:
        regras_nesta_rodada = 0
        
        for assinatura in assinaturas:
            if len(selected_files) == 50:
                break # Sai do 'for' se batermos a meta de 50
            
            # Se a assinatura ainda tem arquivos na lista dela...
            if len(pool_rules[assinatura]) > 0:
                # Sorteia uma regra desta assinatura
                regra_escolhida = random.choice(pool_rules[assinatura])
                
                selected_files.append(regra_escolhida)
                
                # Tira a regra da lista para não sorteá-la de novo na próxima volta
                pool_rules[assinatura].remove(regra_escolhida)
                regras_nesta_rodada += 1
                
        # Proteção contra loop infinito (caso o repositório tivesse menos de 50 regras no total)
        if regras_nesta_rodada == 0:
            print("Aviso: O repositório acabou antes de chegarmos a 50 regras!")
            break

    # 3. Copia os arquivos selecionados para a pasta de treinamento
    print("\n3. Copiando as regras selecionadas...")
    
    # Limpa a pasta antiga de treinamento (se existir) e cria uma nova
    if os.path.exists(NEW_TRAIN_DIR):
        shutil.rmtree(NEW_TRAIN_DIR)
    os.makedirs(NEW_TRAIN_DIR)
    
    for src_path in selected_files:
        caminho_relativo = os.path.relpath(src_path, SIGMA_REPO_DIR)
        novo_nome = caminho_relativo.replace(os.sep, '_')
        dst_path = os.path.join(NEW_TRAIN_DIR, novo_nome)
        shutil.copy2(src_path, dst_path)
        
    print(f"\nConcluído! {len(selected_files)} regras altamente diversificadas foram salvas em:")
    print(NEW_TRAIN_DIR)

if __name__ == "__main__":
    main()