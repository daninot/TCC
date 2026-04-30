import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

def criar_banco_chroma():
    print("i) carregando as 50 regras da pasta 'rag_knowledge':")
    loader = DirectoryLoader('./rag_knowledge', glob="**/*.yml", loader_cls=TextLoader)             #carrega todos os arquivos .yml da pasta
    documentos = loader.load()
    print(f" -> {len(documentos)} arquivos carregados com sucesso.")

    print("ii) iniciando embeddings:")  #modelo de vetorização
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")               #precisei usar esse modelo agora porque ele roda no meu notebook

    print("iii) convertendo textos em vetores e salvando no ChromaDB:")
    Chroma.from_documents(                  #cria o banco e salva na pasta física './chroma_db'
        documents=documentos, 
        embedding=embeddings, 
        persist_directory="./chroma_db"
    )
    print("Banco vetorial criado com sucesso na pasta './chroma_db'.")

if __name__ == "__main__":
    criar_banco_chroma()