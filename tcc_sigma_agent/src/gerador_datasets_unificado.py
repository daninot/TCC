import os
import random
import shutil   #manipula os arquivos (copiar/deletar)
import yaml     #lê o conteúdo das regras

SIGMA_REPO_DIR = "/home/daniela/Documents/TCC/sigma/"  #repositório completo SigmaHQ
TRAIN_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/rag_knowledge/"    #onde estão as regras de treino
TEST_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/test_cases/"        #onde as 50 regras de teste serão salvas

DIRETORIOS_PERMITIDOS = [
    'rules',
    'rules-compliance',
    'rules-emerging-threats',
    'rules-placeholder',
    'rules-threat-hunting'    
]

random.seed(42)     #mantém os datasets idênticos sempre que o script for executado

#lê um arquivo yaml e extrai uma assinatura a partir do logsource:
def get_logsource_key(filepath)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and 'logsource' in doc:                          #cada doc é um dicionário
                    logsource = doc['logsource']                        #logsource recebe o sub-dicionário na variável
                    category = logsource.get('category', 'any')         #pega a palavra-chave de categoria
                    product = logsource.get('product', 'any')
                    service = logsource.get('service', 'any')
                    return f"{category}_{product}_{service}"            #retorna eles em uma string
    except Exception:
        pass
    return "unknown"


def main():
    print("1. Lendo o repositório Sigma e mapeando todas as regras.")

    #i)varredura nas pastas:
    all_valid_rules = []
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):       #os.walk percorre os diretórios
        if root == SIGMA_REPO_DIR:
            dirs[:] = [d for d in dirs if d in DIRETORIOS_PERMITIDOS]       #'dirs' in-place modificado p q o python só entre nas pastas permitidas
            continue        #pula a leitura 
        for file in files:
            if file.endswith('.yml'):
                all_valid_rules.append(os.path.join(root, file))

    #ii)agrupamento por categorias:
    #print("Agrupando regras por assinatura...")
    regras_por_categoria = {}
    for rule_path in all_valid_rules:
        key = get_logsource_key(rule_path)
        if key not in regras_por_categoria:
            regras_por_categoria[key] = []
        regras_por_categoria[key].append(rule_path)

    print("Regras agrupadas em {len(regras_por_categoria)} categorias.")

    #iii)separação das regras de teste (50 regras):
    #uso de round-robin p garantir q pegarei 1 regra de cada até fechar 50
    #print("Selecionando 50 regras para base de teste.")
    test_set = []
    lista_categorias = list(regras_por_categoria.keys())

    while len(test_set) < 50 and len(lista_categorias) > 0:
        for cat in list(lista_categorias):
            if len(test_set) >= 50:
                break
            if regras_por_categoria[cat]:
                regra_escolhida = random.choice(regras_por_categoria[cat])
                test_set.append(regra_escolhida)
                regras_por_categoria[cat].remove(regra_escolhida)       #remove a regra do dicionário para que não vá p a base de treino
            else:
                lista_categorias.remove(cat)        #categoria esvaziou
    
    print(f" -> {len(test_set)} regras de teste isoladas.")

    #iv)separação das regras de treino:
    #print("Selecinando as regras para base de treinamento RAG.")
    remaining_rules = []
    for cat, rules in regras_por_categoria.items():
        remaining_rules.extend(rules)
    
    target_train_count = int(total_rules_count * 0.60)

    if len(remaining_rules) < target_train_count:
        print(f" !Aviso! Não existem regras restantes o suficiente para 60%. Usando as {len(remaining_rules)} restantes.")
        train_set = remaining_rules
    else:
        train_set = random.sample(remaining_rules, target_train_count)      #sorteia aleatoriamente dentre as regras que sobraram

    print(f" -> {len(train_set)} regras de treino selecionadas (60% de {total_rules_count}).")

    #v)copia os arquivos físicos:
    #print("Limpando pastas antigas e gravando novos arquivos.")
    for folder in [TRAIN_DIR, TEST_DIR]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
        os.makedirs(folder, exist_ok=True)      #exist_ok=True previne falha de concorrência com o SO na criação da pasta

    def copy_files_to_dir(file_list, dest_dir):
        regras_copiadas = 0
        for src_path in file_list:
            caminho_relativo = os.path.relpath(src_path, SIGMA_REPO_DIR)
            caminho_seguro = caminho_relativo.replace(os.sep, '_')
            dst_path = os.path.join(dest_dir, caminho_seguro)
            shutil.copy2(src_path, dst_path)
            regras_copiadas += 1
        return regras_copiadas
    
    copiadas_teste = copy_files_to_dir(test_set, TEST_DIR)
    copiadas_treino = copy_files_to_dir(train_set, TRAIN_DIR)

    print("Processo concluído com sucesso.")
    print(f" -> Base de teste: {copiadas_teste} arquivos em {TEST_DIR}")
    print(f" -> Base de treino: {copiadas_treino} arquivos em {TRAIN_DIR}")


if __name__ == "__main__":
    main()