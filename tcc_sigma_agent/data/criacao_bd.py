import os
import shutil   #biblioteca manipula pastas
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

def criar_banco_chroma():

    pasta_banco = "./chroma_db"
    pasta_conhecimento = "./rag_knowledge"

    #se já existe uma pasta, limpa a antiga pra criar uma nova:
    if os.path.exists(pasta_banco):     #só apaga a pasta se ela já existe
            printf("--- Removendo o banco antigo em {pasta_banco} ---")
            shutil.rmtree(pasta_banco)      #deleta a pasta inteira e os diretórios, recursivamente

    print(f"i) Carregando as regras da pasta '{pasta_conhecimento}'.")       
    if not os.path.exists(pasta_conhecimento)       #teste pra ver se a pasta existe mesmo.
        print("Erro: a pasta '{pasta_conhecimento}' não foi encontrada.")
        return
    
    loader = DirectoryLoader(pasta_conhecimento, glob="**/*.yml", loader_cls=TextLoader)             #carrega todos os arquivos .yml da pasta
    documentos = loader.load()
    print(f" -> {len(documentos)} arquivos carregados com sucesso.")

    print("ii) iniciando embeddings:")  #modelo de vetorização
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")               #precisei usar esse modelo agora porque ele roda no meu notebook

    print("iii) convertendo textos em vetores e salvando no ChromaDB:")
    Chroma.from_documents(                  #cria o banco e salva na pasta física './chroma_db'
        documents=documentos, 
        embedding=embeddings, 
        persist_directory=pasta_banco
    )
    print(f"Banco vetorial criado com sucesso na pasta {pasta_banco}.")

if __name__ == "__main__":
    criar_banco_chroma()