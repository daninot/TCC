import os   #lida com os caminhos no linux
import random   
import shutil   #manipula os arquivos (copiar/deletar)
import yaml     #lê o conteúdo das regras

SIGMA_REPO_DIR = "/home/daniela/Documents/TCC/sigma/"  
NEW_TRAIN_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/rag_knowledge/" 

#lê um arquivo yaml e extrai uma assinatura a partir do logsource:
def get_logsource_key(filepath):    

    try:
        with open(filepath, 'r', encoding='utf-8') as f:       
            docs = list(yaml.safe_load_all(f))      #docs 
            for doc in docs:
                if doc and 'logsource' in doc:      #cada doc é um dicionário
                    logsource = doc['logsource']    #logsource recebe o sub-dicionário na variável
                    category = logsource.get('category', 'any') #pega a palavra-chave de categoria
                    product = logsource.get('product', 'any')   #pega o product
                    service = logsource.get('service', 'any')   #pega o serviço
                    return f"{category}_{product}_{service}"
    except Exception:
        pass
    return "unknown"

def main():
    print("1. Lendo o repositório Sigma e mapeando todas as regras:")
    ficheiro_organizador_regras = {}     #dicionário vazio; {"chave":[caminhos dos arquivos]}
    
    #percorre o repositório inteiro e agrupa as regras por assinatura:
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):       #os.walk gera os nomes dos arquivos numa árvore de diretórios; 
                                                            #root = string-> pasta onde está, dirs = lista dos nomes das subpastas, files = lista dos nomes dos arquivos
        for filename in files:                              #itera na última folha da árvore; filename é str e files é uma lista dos arquivos soltos na pasta;
            if filename.endswith(".yml") and not filename.startswith("deprecated"):     #confere se um .yml mesmo e garante que não está deprecated
                filepath = os.path.join(root, filename)     #filepath é uma string do diretório+nome do arquivo
                chave = get_logsource_key(filepath)         #usa o filepath pra pegar a assinatura (chave) do arquivo
                
                if chave not in ficheiro_organizador_regras:            #se essa chave ainda não estiver no ficheiro de regras
                    ficheiro_organizador_regras[chave] = []             #cria uma lista vazia para esta chave
                ficheiro_organizador_regras[chave].append(filepath)     #adiciona no final da lista desta chave o caminho do arquivo que possui esta chave/assinatura 


    #remove a categoria "unknown" se houver (para arquivos mal formatados):
    if "unknown" in ficheiro_organizador_regras:
        del ficheiro_organizador_regras["unknown"]

    print(f"Foram encontradas {len(ficheiro_organizador_regras)} assinaturas diferentes no repositório.")
    

    #prepara para a seleção:
    selected_files = []                                         #inicializa a lista
    assinaturas = list(ficheiro_organizador_regras.keys())      #.keys é um método que extrai o lado esquerdo dos pares dos dicionários; coloca elas dentro de list pra embaralhar
    random.shuffle(assinaturas)                                 #embaralha a fila de seleção para não pegar sempre as mesmas assinaturas nas primeiras rodadas
    
    print("\n2. Selecionando 50 regras de forma diversificada...")  #round-robin
    
    while len(selected_files) < 50: 
        regras_nesta_rodada = 0
        
        for assinatura in assinaturas:
            if len(selected_files) == 50:   #se já atingiu as 50 regras faz a beatriz se revirar onde quer que ela esteja
                break
            
            # Se a assinatura ainda tem arquivos na lista dela...
            if len(ficheiro_organizador_regras[assinatura]) > 0:    #
                # Sorteia uma regra desta assinatura
                regra_escolhida = random.choice(ficheiro_organizador_regras[assinatura])
                
                selected_files.append(regra_escolhida)
                
                # Tira a regra da lista para não sorteá-la de novo na próxima volta
                ficheiro_organizador_regras[assinatura].remove(regra_escolhida)
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