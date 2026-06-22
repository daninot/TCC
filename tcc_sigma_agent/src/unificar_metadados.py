"""
================================================================================
01_unificar_metadados.py

Objetivo
--------
Unir os 5 arquivos `metadados_geracao_*.csv` produzidos pelas 5 execuções em
lote do agente (sigma_agent_v17_geracao_automatica.py) em um único CSV
consolidado, `metadados_unificado.csv`, que será a base de dados primária de
todas as análises do Capítulo 5 da monografia.

Por que existe este script
--------------------------
A execução foi dividida em 5 lotes de 10 cenários × 3 prompts cada (= 30 linhas
por arquivo) por restrição de hardware. Para a análise, precisamos dos 150
registros em um único DataFrame.

O que o script faz
------------------
1. Localiza os 5 arquivos CSV na pasta de entrada (`PASTA_ENTRADA`).
2. Verifica que todos têm exatamente o mesmo cabeçalho (proteção contra
   versões divergentes do agente entre lotes).
3. Carrega cada CSV, adiciona uma coluna `lote_origem` (rede de segurança),
   e concatena tudo em um único DataFrame.
4. Valida a integridade do resultado: 150 linhas, 50 cenários únicos,
   3 prompts por cenário, nenhuma duplicação.
5. Salva o CSV unificado em `PASTA_SAIDA/metadados_unificado.csv`.
6. Imprime um relatório-resumo no terminal e salva em
   `PASTA_SAIDA/01_relatorio_unificacao.txt`.

Como executar
-------------
    $ python3 01_unificar_metadados.py

Saídas
------
- metadados_unificado.csv         : DataFrame consolidado (150 linhas)
- 01_relatorio_unificacao.txt     : Relatório textual do que foi feito

Dependências
------------
    pandas (>= 1.3)
================================================================================
"""

import os
import sys
from pathlib import Path
from datetime import datetime

import pandas as pd

# =============================================================================
# CONFIGURAÇÕES — AJUSTE OS CAMINHOS CONFORME SEU AMBIENTE
# =============================================================================

# Pasta onde estão os 5 arquivos metadados_geracao_*.csv
PASTA_ENTRADA = Path("/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/test_cases/metadados")

# Pasta onde o CSV unificado e o relatório serão salvos
PASTA_SAIDA = Path("/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/analises")

# Padrão de nome dos arquivos de entrada (5 arquivos esperados)
# Vai casar com: metadados_geracao_1.csv, metadados_geracao_2.csv, ...
PADRAO_ARQUIVO = "metadados_geracao_*.csv"

# Número esperado de cenários totais e prompts por cenário
NUM_CENARIOS_ESPERADO = 50
NUM_PROMPTS_POR_CENARIO = 3
NUM_LINHAS_ESPERADO = NUM_CENARIOS_ESPERADO * NUM_PROMPTS_POR_CENARIO   # = 150

# Colunas obrigatórias no CSV (devem existir em todos os 5 arquivos).
# Esta lista espelha a definição de `campos` em sigma_agent_v17_geracao_automatica.py.
COLUNAS_ESPERADAS = [
    "cenario_id", "prompt_usado", "status", "tentativas", "tempo_total_s",
    "usou_web_search", "tipo_input", "contexto_pobre",
    "erro_validacao_final", "veredito_juiz",
    "juiz_logsource", "juiz_modifiers", "juiz_condition",
    "juiz_structure", "juiz_semantic_alignment", "juiz_invented_filters",
    "motivo_reprovacao",
    "regra_referencia", "arquivo_regra_gerada", "arquivo_parecer",
]


# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

def localizar_csvs(pasta: Path, padrao: str) -> list[Path]:
    """Retorna a lista ordenada de CSVs encontrados na pasta."""
    arquivos = sorted(pasta.glob(padrao))
    if not arquivos:
        raise FileNotFoundError(
            f"Nenhum arquivo encontrado em '{pasta}' com o padrão '{padrao}'."
        )
    return arquivos


def validar_cabecalho(arquivo: Path) -> tuple[bool, list[str]]:
    """Lê só a primeira linha do CSV e verifica se tem as colunas esperadas.

    Retorna (eh_valido, colunas_encontradas). Se eh_valido for False, o chamador
    deve abortar — pois colunas divergentes indicam que o agente foi rodado
    com versões diferentes, e qualquer concatenação produziria dados sujos.
    """
    df_amostra = pd.read_csv(arquivo, nrows=0)   # nrows=0 lê só o header
    colunas_encontradas = list(df_amostra.columns)
    eh_valido = colunas_encontradas == COLUNAS_ESPERADAS
    return eh_valido, colunas_encontradas


def carregar_lote(arquivo: Path, numero_lote: int) -> pd.DataFrame:
    """Carrega um CSV e adiciona a coluna `lote_origem`."""
    df = pd.read_csv(arquivo)
    df["lote_origem"] = numero_lote
    return df


def relatar_problema_de_cabecalho(arquivo: Path, colunas_lidas: list[str]) -> str:
    """Monta uma mensagem clara explicando o que está diferente."""
    faltando = set(COLUNAS_ESPERADAS) - set(colunas_lidas)
    sobrando = set(colunas_lidas) - set(COLUNAS_ESPERADAS)
    msg = f"  Arquivo: {arquivo.name}\n"
    if faltando:
        msg += f"    Colunas FALTANDO: {sorted(faltando)}\n"
    if sobrando:
        msg += f"    Colunas SOBRANDO: {sorted(sobrando)}\n"
    return msg


def validar_integridade(df: pd.DataFrame) -> list[str]:
    """Roda checagens lógicas sobre o DataFrame unificado.

    Retorna uma lista de mensagens de erro. Se a lista vier vazia, está tudo OK.
    Não levanta exceção — preferimos relatar tudo de uma vez para a usuária
    poder corrigir todos os problemas numa só passada.
    """
    problemas = []

    # 1) Total de linhas
    if len(df) != NUM_LINHAS_ESPERADO:
        problemas.append(
            f"Total de linhas é {len(df)}, esperado {NUM_LINHAS_ESPERADO} "
            f"(= {NUM_CENARIOS_ESPERADO} cenários × {NUM_PROMPTS_POR_CENARIO} prompts)."
        )

    # 2) Número de cenários únicos
    cenarios_unicos = df["cenario_id"].nunique()
    if cenarios_unicos != NUM_CENARIOS_ESPERADO:
        problemas.append(
            f"Número de cenários únicos é {cenarios_unicos}, esperado {NUM_CENARIOS_ESPERADO}."
        )

    # 3) Cada cenário deve ter exatamente 3 prompts (prompt1, prompt2, prompt3)
    contagem_por_cenario = df.groupby("cenario_id")["prompt_usado"].nunique()
    cenarios_incompletos = contagem_por_cenario[
        contagem_por_cenario != NUM_PROMPTS_POR_CENARIO
    ]
    if not cenarios_incompletos.empty:
        problemas.append(
            "Cenários sem os 3 prompts esperados:\n"
            + cenarios_incompletos.to_string()
        )

    # 4) Combinação (cenario_id, prompt_usado) deve ser ÚNICA — nenhuma duplicata
    duplicatas = df[df.duplicated(subset=["cenario_id", "prompt_usado"], keep=False)]
    if not duplicatas.empty:
        problemas.append(
            f"Existem {len(duplicatas)} linhas duplicadas em (cenario_id, prompt_usado):\n"
            + duplicatas[["cenario_id", "prompt_usado", "lote_origem"]].to_string()
        )

    # 5) Valores válidos em prompt_usado
    valores_prompt = set(df["prompt_usado"].unique())
    valores_esperados = {"prompt1", "prompt2", "prompt3"}
    if valores_prompt != valores_esperados:
        problemas.append(
            f"Valores em prompt_usado: {valores_prompt} (esperado: {valores_esperados})."
        )

    # 6) Valores válidos em status
    valores_status = set(df["status"].unique())
    valores_esperados_status = {"APROVADO", "REPROVADO", "ERRO_EXECUCAO"}
    valores_inesperados = valores_status - valores_esperados_status
    if valores_inesperados:
        problemas.append(
            f"Valores inesperados em status: {valores_inesperados}."
        )

    return problemas


def montar_relatorio(arquivos: list[Path], df: pd.DataFrame, problemas: list[str]) -> str:
    """Monta a string do relatório textual final."""
    linhas = []
    linhas.append("=" * 70)
    linhas.append("RELATÓRIO DE UNIFICAÇÃO DE METADADOS")
    linhas.append(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    linhas.append("=" * 70)
    linhas.append("")
    linhas.append(f"Arquivos de entrada: {len(arquivos)}")
    for i, arq in enumerate(arquivos, start=1):
        linhas.append(f"  [lote {i}] {arq.name}")
    linhas.append("")
    linhas.append(f"Total de linhas no DataFrame unificado: {len(df)}")
    linhas.append(f"Cenários únicos:                       {df['cenario_id'].nunique()}")
    linhas.append(f"Prompts distintos:                     {sorted(df['prompt_usado'].unique())}")
    linhas.append("")
    linhas.append("Distribuição de `status`:")
    for s, n in df["status"].value_counts().items():
        pct = 100.0 * n / len(df)
        linhas.append(f"  {s:<20s} {n:>4d}   ({pct:5.1f}%)")
    linhas.append("")
    linhas.append("Distribuição de `veredito_juiz` (parecer do nó 6):")
    for v, n in df["veredito_juiz"].fillna("(vazio)").value_counts().items():
        pct = 100.0 * n / len(df)
        linhas.append(f"  {v:<30s} {n:>4d}   ({pct:5.1f}%)")
    linhas.append("")
    linhas.append("Distribuição de linhas por lote:")
    for lote, n in df["lote_origem"].value_counts().sort_index().items():
        linhas.append(f"  lote {lote}: {n} linhas")
    linhas.append("")
    if problemas:
        linhas.append("PROBLEMAS DE INTEGRIDADE DETECTADOS:")
        for p in problemas:
            linhas.append(f"  - {p}")
    else:
        linhas.append("INTEGRIDADE: OK (nenhum problema detectado).")
    linhas.append("=" * 70)
    return "\n".join(linhas)


# =============================================================================
# EXECUÇÃO PRINCIPAL
# =============================================================================

def main() -> int:
    # 1) Garante que a pasta de saída existe
    PASTA_SAIDA.mkdir(parents=True, exist_ok=True)

    # 2) Localiza os CSVs
    print(f"-> Procurando CSVs em '{PASTA_ENTRADA}' (padrão: {PADRAO_ARQUIVO})...")
    try:
        arquivos = localizar_csvs(PASTA_ENTRADA, PADRAO_ARQUIVO)
    except FileNotFoundError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 1

    print(f"   Encontrados {len(arquivos)} arquivo(s):")
    for arq in arquivos:
        print(f"     {arq.name}")

    # 3) Valida cabeçalhos antes de carregar tudo na memória
    print("\n-> Validando cabeçalhos...")
    erros_cabecalho = []
    for arq in arquivos:
        eh_valido, colunas = validar_cabecalho(arq)
        if not eh_valido:
            erros_cabecalho.append(relatar_problema_de_cabecalho(arq, colunas))
    if erros_cabecalho:
        print("ERRO: cabeçalhos divergentes — não posso unificar com segurança.")
        print("\n".join(erros_cabecalho), file=sys.stderr)
        return 2
    print("   OK — todos os arquivos têm o cabeçalho esperado.")

    # 4) Carrega cada lote e concatena
    print("\n-> Carregando e concatenando...")
    dfs = []
    for i, arq in enumerate(arquivos, start=1):
        df_lote = carregar_lote(arq, numero_lote=i)
        print(f"   lote {i}: {len(df_lote)} linhas carregadas de {arq.name}")
        dfs.append(df_lote)
    df_unificado = pd.concat(dfs, ignore_index=True)

    # 5) Ordena para facilitar inspeção (cenário, depois prompt)
    df_unificado = df_unificado.sort_values(
        by=["cenario_id", "prompt_usado"], kind="stable"
    ).reset_index(drop=True)

    # 6) Valida integridade lógica
    print("\n-> Validando integridade...")
    problemas = validar_integridade(df_unificado)
    if problemas:
        print("ATENÇÃO: problemas detectados:")
        for p in problemas:
            print(f"  - {p}")
        print("(O CSV unificado será salvo mesmo assim, para inspeção manual.)")
    else:
        print("   OK — nenhum problema detectado.")

    # 7) Salva CSV unificado
    caminho_csv = PASTA_SAIDA / "metadados_unificado.csv"
    df_unificado.to_csv(caminho_csv, index=False, encoding="utf-8")
    print(f"\n-> CSV unificado salvo em: {caminho_csv}")

    # 8) Salva relatório textual
    relatorio = montar_relatorio(arquivos, df_unificado, problemas)
    caminho_relatorio = PASTA_SAIDA / "01_relatorio_unificacao.txt"
    caminho_relatorio.write_text(relatorio, encoding="utf-8")
    print(f"-> Relatório salvo em:     {caminho_relatorio}")

    # 9) Imprime relatório no terminal
    print("\n" + relatorio)

    return 0 if not problemas else 3


if __name__ == "__main__":
    sys.exit(main())
