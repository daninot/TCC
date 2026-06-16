import pandas as pd

# 1. Carregar os ficheiros de Excel
# Carregamos a Regras Sigma usando a linha 1 como cabeçalho para ter os nomes das IAs
df_sigma = pd.read_excel("Regras Sigma.xlsx", header=1)

# Carregamos a Resultados sem cabeçalho para preservar a estrutura dupla (linha 0 e linha 1) e processar a partir da linha 2
df_resultados = pd.read_excel("Resultados.xlsx", header=None)

# Função para formatar o nome das IAs bonitinho
def formatar_nome_ia(nome_bruto):
    nome = str(nome_bruto).split('.')[0].strip().upper()
    if nome == "CHATGPT": return "ChatGPT"
    return nome.capitalize()

# 2. Criar o "Gabarito" (Dicionários de mapeamento a partir da Regras Sigma)
# Estrutura: gabarito_stage1["nome_da_regra"] = {'A': 'Deepseek', 'B': 'Copilot', ...}
gabarito_stage1 = {}
gabarito_stage2 = {}

for index, row in df_sigma.iterrows():
    regra = str(row.iloc[1]).strip()
    if pd.isna(regra) or regra == 'nan': 
        continue
    
    # Mapear as opções do Stage 1 (Colunas de índice 2 a 6)
    map_s1 = {}
    for col_idx in range(2, 7):
        letra = str(row.iloc[col_idx]).strip()
        nome_ia = formatar_nome_ia(df_sigma.columns[col_idx])
        if letra != 'nan':
            map_s1[letra] = nome_ia
    gabarito_stage1[regra] = map_s1
    
    # Mapear as opções do Stage 2 (Colunas de índice 8 a 12)
    map_s2 = {}
    for col_idx in range(8, 13):
        letra = str(row.iloc[col_idx]).strip()
        nome_ia = formatar_nome_ia(df_sigma.columns[col_idx])
        if letra != 'nan':
            map_s2[letra] = nome_ia
    gabarito_stage2[regra] = map_s2

# 3. Fazer a substituição automática na folha Resultados
# As linhas de dados começam no índice 2.
# As colunas de "prompt 1" são os índices pares: 2, 4, 6, 8, 10
# As colunas de "prompt 2" são os índices ímpares: 3, 5, 7, 9, 11

for i in range(2, len(df_resultados)):
    regra = str(df_resultados.iloc[i, 0]).strip()
    
    # Se a regra existir no gabarito, fazemos a tradução
    if regra in gabarito_stage1 and regra in gabarito_stage2:
        
        # Traduzir Prompt 1 (Stage 1)
        for col_idx in [2, 4, 6, 8, 10]:
            letra_escolhida = str(df_resultados.iloc[i, col_idx]).strip()
            # Se a letra escolhida estiver no gabarito (A, B, C, D, E), substitui pelo nome da IA
            if letra_escolhida in gabarito_stage1[regra]:
                df_resultados.iloc[i, col_idx] = gabarito_stage1[regra][letra_escolhida]
                
        # Traduzir Prompt 2 (Stage 2)
        for col_idx in [3, 5, 7, 9, 11]:
            letra_escolhida = str(df_resultados.iloc[i, col_idx]).strip()
            # Se a letra escolhida estiver no gabarito, substitui pelo nome da IA
            if letra_escolhida in gabarito_stage2[regra]:
                df_resultados.iloc[i, col_idx] = gabarito_stage2[regra][letra_escolhida]

# 4. Guardar o resultado final num novo ficheiro
df_resultados.to_excel("Resultados_Automatizados_Final.xlsx", index=False, header=False)

print("Tradução automática concluída! Ficheiro 'Resultados_Automatizados_Final.xlsx' gerado com sucesso.")