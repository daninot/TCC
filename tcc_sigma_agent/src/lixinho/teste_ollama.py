from langchain_community.chat_models import ChatOllama

llm = ChatOllama(model="qwen2.5:1.5b", temperature=0)   #conexão com o modelo que baixamos

resposta = llm.invoke("Escreva a estrutura básica de um arquivo YAML em 3 linhas.")     #teste
print(resposta.content)