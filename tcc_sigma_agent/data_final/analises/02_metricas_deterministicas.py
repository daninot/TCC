"""
================================================================================
02_metricas_deterministicas.py

Objetivo
--------
Calcular os indicadores quantitativos do desempenho determinístico do agente
(Bloco B, seções 5.2.1 a 5.2.4 da monografia) a partir do CSV unificado
produzido pelo Script 1.

Subseções produzidas
--------------------
  5.2.1 Taxa de aprovação sintática (global e por prompt)
  5.2.2 Esforço de autocorreção: distribuição de tentativas e tempo
  5.2.3 Modos de falha: categorização do erro_validacao_final
  5.2.4 Influência das decisões iniciais (tipo_input, contexto_pobre,
        usou_web_search) sobre o status final

Saídas
------
Para cada subseção:
  - CSV bruto (para conferência rápida)
  - Tabela em LaTeX (booktabs, pronta para \\input{} dentro de um table)
  - Gráficos em pgfplots/TikZ (.tex), pronto para \\input{} dentro de um figure
Além disso:
  - 02_relatorio_bloco_b.txt           : relatório textual de tudo
  - 02_preambulo_recomendado.tex       : pacotes que devem ir no preâmbulo
                                         do .tex principal da monografia

Dependências
------------
    pandas, numpy
================================================================================
"""

import csv
import re
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")   # backend sem display, ideal para scripts
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

# =============================================================================
# CONFIGURAÇÕES — AJUSTE OS CAMINHOS CONFORME SEU AMBIENTE
# =============================================================================

ARQUIVO_ENTRADA = Path(
    "/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/analises/metadados_unificado.csv"
)
PASTA_SAIDA = Path("/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/analises/B")

# Número esperado de execuções (50 cenários x 3 prompts)
N_ESPERADO = 150


# =============================================================================
# CATEGORIZAÇÃO DOS MODOS DE FALHA (regex sobre erro_validacao_final)
# =============================================================================
# Ordem importa: a primeira categoria que casar vence. As regex foram derivadas
# das mensagens reais geradas pelo validador em sigma_agent_v17 (linhas 706-782).

CATEGORIAS_ERRO = [
    ("Parsing YAML", [
        r"1/3\s*falhou",
        r"sintaxe\s*YAML",
        r"Falha\s*ao\s*separar",
        r"Nenhum\s*documento\s*YAML",
        r"n[ãa]o\s*é\s*um\s*YAML",
    ]),
    ("Campo obrigatório ausente", [
        r"faltou\s*campo\s*obrigat[óo]rio",
    ]),
    ("Tag MITRE inválida", [
        r"tags\s*n[ãa]o\s*existem",
        r"taxonomia\s*MITRE",
    ]),
    ("Semântica pySigma", [
        r"3/3\s*falhou",
        r"pySigma\s*relata",
        r"erro\s*de\s*sem[âa]ntica",
        r"Etapa\s*3\s*falhou",
    ]),
]


def categorizar_erro(msg) -> str:
    """Classifica uma mensagem de erro em uma das 4 categorias previstas,
    ou retorna 'outros' se nenhuma regex casar.

    Aceita NaN/None/string vazia (retorna '(sem erro registrado)')."""
    if msg is None or (isinstance(msg, float) and np.isnan(msg)):
        return "(sem erro registrado)"
    msg = str(msg).strip()
    if not msg:
        return "(sem erro registrado)"
    for categoria, padroes in CATEGORIAS_ERRO:
        for p in padroes:
            if re.search(p, msg, flags=re.IGNORECASE):
                return categoria
    return "outros"


# =============================================================================
# GERADORES DE LaTeX
# =============================================================================

def fmt_num(x, casas=1) -> str:
    """Formata número com vírgula decimal (padrão pt-BR)."""
    if isinstance(x, (int, np.integer)):
        return f"{x}"
    return f"{x:.{casas}f}".replace(".", ",")


def escapar_latex(s: str) -> str:
    """Escapa caracteres especiais do LaTeX em strings."""
    return (str(s)
            .replace("\\", r"\textbackslash{}")
            .replace("&", r"\&").replace("%", r"\%")
            .replace("$", r"\$").replace("#", r"\#")
            .replace("_", r"\_").replace("{", r"\{").replace("}", r"\}"))


def gerar_tabela_latex(df: pd.DataFrame, alinhamento: str,
                       cabecalhos_latex: list[str] | None = None) -> str:
    """Gera código `tabular` com booktabs.

    Parâmetros:
        df             : DataFrame com os dados
        alinhamento    : string de alinhamento por coluna (ex: 'lrrr')
        cabecalhos_latex: cabeçalhos formatados (LaTeX); se None, usa df.columns
    """
    if cabecalhos_latex is None:
        cabecalhos_latex = [escapar_latex(c) for c in df.columns]

    linhas = [
        r"\begin{tabular}{" + alinhamento + "}",
        r"\toprule",
        " & ".join(cabecalhos_latex) + r" \\",
        r"\midrule",
    ]
    for _, row in df.iterrows():
        celulas = []
        for v in row.values:
            if isinstance(v, str):
                celulas.append(escapar_latex(v))
            elif isinstance(v, (int, np.integer)):
                celulas.append(f"{v}")
            elif isinstance(v, float):
                celulas.append(fmt_num(v, casas=1))
            else:
                celulas.append(escapar_latex(str(v)))
        linhas.append(" & ".join(celulas) + r" \\")
    linhas.append(r"\bottomrule")
    linhas.append(r"\end{tabular}")
    return "\n".join(linhas) + "\n"


def gerar_histograma_png(valores: list[int], titulo_eixo_x: str,
                         caminho: Path, titulo_eixo_y: str = "Frequência") -> None:
    """Histograma de variável inteira (ex: número de tentativas)."""
    cont = Counter(valores)
    if not cont:
        return
    valores_eixo = sorted(cont.keys())
    freqs = [cont[v] for v in valores_eixo]

    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=200)
    bars = ax.bar(valores_eixo, freqs,
                  color="#4472C4", edgecolor="#2E4D8B", width=0.7)
    ax.set_xlabel(titulo_eixo_x)
    ax.set_ylabel(titulo_eixo_y)
    ax.set_xticks(valores_eixo)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    # rótulos de valor no topo de cada barra
    for b, f in zip(bars, freqs):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + max(freqs)*0.01,
                str(f), ha="center", va="bottom", fontsize=10)
    ax.set_ylim(0, max(freqs) * 1.12)
    fig.tight_layout()
    fig.savefig(caminho, bbox_inches="tight")
    plt.close(fig)


def gerar_boxplot_png(grupos: dict[str, list[float]], titulo_eixo_y: str,
                      caminho: Path) -> None:
    """Boxplot com múltiplos grupos lado a lado."""
    nomes = list(grupos.keys())
    dados = [np.array([v for v in grupos[n] if not (isinstance(v, float) and np.isnan(v))])
             for n in nomes]
    # remove grupos vazios
    nomes_validos = [n for n, d in zip(nomes, dados) if len(d) > 0]
    dados_validos = [d for d in dados if len(d) > 0]
    if not dados_validos:
        return

    fig, ax = plt.subplots(figsize=(7, 5), dpi=200)
    bp = ax.boxplot(dados_validos, tick_labels=nomes_validos,
                    patch_artist=True, showmeans=True,
                    meanprops=dict(marker="D", markerfacecolor="white",
                                   markeredgecolor="black", markersize=7),
                    medianprops=dict(color="black", linewidth=1.5),
                    flierprops=dict(marker="o", markerfacecolor="#2E4D8B",
                                    markeredgecolor="#2E4D8B", markersize=4))
    for patch in bp["boxes"]:
        patch.set_facecolor("#BDD7EE")
        patch.set_edgecolor("#2E4D8B")
    ax.set_ylabel(titulo_eixo_y)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(caminho, bbox_inches="tight")
    plt.close(fig)


def gerar_barras_png(categorias: list[str], valores: list[int],
                     caminho: Path, titulo_eixo_y: str = "Frequência") -> None:
    """Gráfico de barras verticais para variável categórica."""
    if not categorias:
        return
    fig, ax = plt.subplots(figsize=(8, 5), dpi=200)
    bars = ax.bar(range(len(categorias)), valores,
                  color="#E07B7B", edgecolor="#A04040", width=0.7)
    ax.set_xticks(range(len(categorias)))
    ax.set_xticklabels(categorias, rotation=20, ha="right")
    ax.set_ylabel(titulo_eixo_y)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    max_v = max(valores) if valores else 1
    for b, v in zip(bars, valores):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + max_v*0.01,
                str(v), ha="center", va="bottom", fontsize=10)
    ax.set_ylim(0, max_v * 1.12)
    fig.tight_layout()
    fig.savefig(caminho, bbox_inches="tight")
    plt.close(fig)


# =============================================================================
# SUBSEÇÃO 5.2.1 — TAXA DE APROVAÇÃO SINTÁTICA
# =============================================================================

def calcular_5_2_1(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Calcula taxa de aprovação global e por prompt, com ERRO_EXECUCAO
    incluído no denominador (decisão metodológica: o sistema é avaliado
    como um todo, sem isolar instabilidades técnicas)."""
    linhas = []
    for grupo, sub in [("global", df)] + [
        (p, df[df["prompt_usado"] == p]) for p in sorted(df["prompt_usado"].unique())
    ]:
        n_total = len(sub)
        n_aprov = int((sub["status"] == "APROVADO").sum())
        n_reprov = int((sub["status"] == "REPROVADO").sum())
        n_erro = int((sub["status"] == "ERRO_EXECUCAO").sum())
        taxa = 100.0 * n_aprov / n_total if n_total else 0.0
        linhas.append({
            "Grupo": grupo,
            "N": n_total,
            "APROVADO": n_aprov,
            "REPROVADO": n_reprov,
            "ERRO_EXECUCAO": n_erro,
            "Taxa de aprovação (%)": taxa,
        })
    tabela = pd.DataFrame(linhas)

    resumo = {
        "n_total": int(len(df)),
        "n_aprov_global": int((df["status"] == "APROVADO").sum()),
        "taxa_global": 100.0 * (df["status"] == "APROVADO").sum() / len(df),
        "n_erro_execucao": int((df["status"] == "ERRO_EXECUCAO").sum()),
    }
    return tabela, resumo


# =============================================================================
# SUBSEÇÃO 5.2.2 — TENTATIVAS E TEMPO
# =============================================================================

def calcular_5_2_2(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Estatísticas de tentativas e tempo, considerando todas as execuções
    (decisão metodológica: incluir ERRO_EXECUCAO)."""
    linhas = []
    for grupo, sub in [("global", df)] + [
        (p, df[df["prompt_usado"] == p]) for p in sorted(df["prompt_usado"].unique())
    ]:
        tent = sub["tentativas"].dropna().astype(int)
        temp = sub["tempo_total_s"].dropna().astype(float)
        linhas.append({
            "Grupo": grupo,
            "N": len(sub),
            "Tentativas (média)": tent.mean() if len(tent) else 0.0,
            "Tentativas (mediana)": int(tent.median()) if len(tent) else 0,
            "Tempo médio (s)": temp.mean() if len(temp) else 0.0,
            "Tempo mediano (s)": temp.median() if len(temp) else 0.0,
            "Tempo máximo (s)": temp.max() if len(temp) else 0.0,
        })
    tabela = pd.DataFrame(linhas)

    # Tempo por status (para boxplot)
    grupos_tempo = {}
    for s in ["APROVADO", "REPROVADO", "ERRO_EXECUCAO"]:
        vals = df[df["status"] == s]["tempo_total_s"].dropna().tolist()
        if vals:
            grupos_tempo[s] = vals

    contexto = {
        "tentativas_distribuicao": df["tentativas"].dropna().astype(int).tolist(),
        "grupos_tempo": grupos_tempo,
    }
    return tabela, contexto


# =============================================================================
# SUBSEÇÃO 5.2.3 — MODOS DE FALHA
# =============================================================================

def calcular_5_2_3(df: pd.DataFrame) -> pd.DataFrame:
    """Categoriza erros das execuções com status REPROVADO ou ERRO_EXECUCAO."""
    df_falhas = df[df["status"].isin(["REPROVADO", "ERRO_EXECUCAO"])].copy()
    df_falhas["categoria_erro"] = df_falhas["erro_validacao_final"].apply(categorizar_erro)
    cont = Counter(df_falhas["categoria_erro"])
    total = sum(cont.values())
    linhas = [
        {
            "Categoria do erro": cat,
            "Quantidade": qtd,
            "Percentual": 100.0 * qtd / total if total else 0.0,
        }
        for cat, qtd in cont.most_common()
    ]
    return pd.DataFrame(linhas)


# =============================================================================
# SUBSEÇÃO 5.2.4 — DECISÕES INICIAIS
# =============================================================================

def calcular_5_2_4(df: pd.DataFrame) -> tuple[list[pd.DataFrame], list[str]]:
    """Tabelas cruzadas: cada decisão inicial vs. status final.

    Retorna também uma lista de avisos sobre variáveis com variância zero
    (que não podem ser usadas como fator explicativo)."""
    tabelas = []
    avisos = []
    for col in ["tipo_input", "contexto_pobre", "usou_web_search"]:
        if col not in df.columns:
            continue
        n_valores_unicos = df[col].nunique(dropna=False)
        if n_valores_unicos < 2:
            valor_unico = df[col].iloc[0]
            avisos.append(
                f"A variável '{col}' assumiu valor constante '{valor_unico}' em "
                f"todas as {len(df)} execuções. Não pode ser usada como fator "
                f"explicativo do desempenho."
            )
            continue
        # Construir tabela: linhas = valores da decisão, colunas = status
        tabela = pd.crosstab(df[col].fillna("(vazio)"), df["status"],
                             margins=True, margins_name="Total")
        tabela["Taxa aprov. (%)"] = 100.0 * tabela.get("APROVADO", 0) / tabela["Total"]
        tabela = tabela.reset_index()
        tabela.insert(0, "Decisão", col)
        tabelas.append(tabela)
    return tabelas, avisos


# =============================================================================
# RELATÓRIO TEXTUAL
# =============================================================================

def gerar_relatorio_texto(t1, r1, t2, c2, t3, tabelas_524, avisos_524) -> str:
    L = []
    L.append("=" * 72)
    L.append("BLOCO B — MÉTRICAS DETERMINÍSTICAS DO AGENTE")
    L.append(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("=" * 72)

    L.append("\n5.2.1  TAXA DE APROVAÇÃO SINTÁTICA")
    L.append("-" * 72)
    L.append(t1.to_string(index=False, float_format=lambda x: f"{x:.1f}"))
    L.append(f"\n  Resumo: {r1['n_aprov_global']}/{r1['n_total']} execuções "
             f"aprovadas — taxa global de {r1['taxa_global']:.1f}%.")
    L.append(f"  ERRO_EXECUCAO: {r1['n_erro_execucao']} ocorrência(s).")

    L.append("\n\n5.2.2  TENTATIVAS E TEMPO")
    L.append("-" * 72)
    L.append(t2.to_string(index=False, float_format=lambda x: f"{x:.2f}"))
    if c2["tentativas_distribuicao"]:
        dist = Counter(c2["tentativas_distribuicao"])
        L.append(f"\n  Distribuição de tentativas: "
                 + ", ".join(f"{v}={dist[v]}" for v in sorted(dist)))

    L.append("\n\n5.2.3  MODOS DE FALHA")
    L.append("-" * 72)
    if t3.empty:
        L.append("  (Nenhuma falha registrada.)")
    else:
        L.append(t3.to_string(index=False, float_format=lambda x: f"{x:.1f}"))

    L.append("\n\n5.2.4  INFLUÊNCIA DAS DECISÕES INICIAIS")
    L.append("-" * 72)
    if avisos_524:
        L.append("AVISOS:")
        for a in avisos_524:
            L.append(f"  ! {a}")
        L.append("")
    for t in tabelas_524:
        L.append(t.to_string(index=False, float_format=lambda x: f"{x:.1f}"))
        L.append("")

    return "\n".join(L)


# =============================================================================
# PREÂMBULO LaTeX RECOMENDADO
# =============================================================================

PREAMBULO_LATEX = r"""% =============================================================
% Pacotes necessários para usar as tabelas e gráficos gerados
% pelo script 02_metricas_deterministicas.py
% =============================================================
\usepackage{booktabs}      % tabelas profissionais (toprule, midrule, bottomrule)
\usepackage{graphicx}      % para incluir os gráficos PNG

% Exemplo de uso de uma tabela:
%
% \begin{table}[ht]
%   \centering
%   \caption{Taxa de aprovação sintática do agente.}
%   \label{tab:taxa_aprovacao}
%   \input{caminho/02_5_2_1_taxa_aprovacao.tex}
% \end{table}
%
% Exemplo de uso de um gráfico:
%
% \begin{figure}[ht]
%   \centering
%   \includegraphics[width=0.85\textwidth]{caminho/02_5_2_2_histograma_tentativas.png}
%   \caption{Distribuição do número de tentativas até a aprovação.}
%   \label{fig:hist_tentativas}
% \end{figure}
"""


# =============================================================================
# EXECUÇÃO PRINCIPAL
# =============================================================================

def main() -> int:
    PASTA_SAIDA.mkdir(parents=True, exist_ok=True)

    # 1) Carrega o CSV
    print(f"-> Carregando '{ARQUIVO_ENTRADA}'...")
    if not ARQUIVO_ENTRADA.is_file():
        print(f"ERRO: arquivo não encontrado.", file=sys.stderr)
        return 1
    df = pd.read_csv(ARQUIVO_ENTRADA)
    print(f"   {len(df)} linhas carregadas.")
    if len(df) != N_ESPERADO:
        print(f"   AVISO: o esperado eram {N_ESPERADO} linhas.")

    # 2) Calcula cada subseção
    print("\n-> Calculando 5.2.1 (taxa de aprovação)...")
    t1, r1 = calcular_5_2_1(df)
    print("-> Calculando 5.2.2 (tentativas e tempo)...")
    t2, c2 = calcular_5_2_2(df)
    print("-> Calculando 5.2.3 (modos de falha)...")
    t3 = calcular_5_2_3(df)
    print("-> Calculando 5.2.4 (decisões iniciais)...")
    tabelas_524, avisos_524 = calcular_5_2_4(df)

    # 3) Exporta CSVs
    print("\n-> Exportando CSVs...")
    t1.to_csv(PASTA_SAIDA / "02_5_2_1_taxa_aprovacao.csv", index=False, encoding="utf-8")
    t2.to_csv(PASTA_SAIDA / "02_5_2_2_tentativas_e_tempo.csv", index=False, encoding="utf-8")
    t3.to_csv(PASTA_SAIDA / "02_5_2_3_modos_de_falha.csv", index=False, encoding="utf-8")
    for i, t in enumerate(tabelas_524, start=1):
        t.to_csv(PASTA_SAIDA / f"02_5_2_4_decisao_{i}.csv", index=False, encoding="utf-8")

    # 4) Exporta tabelas LaTeX
    print("-> Exportando tabelas LaTeX...")
    (PASTA_SAIDA / "02_5_2_1_taxa_aprovacao.tex").write_text(
        gerar_tabela_latex(t1, "lrrrrr"), encoding="utf-8")
    (PASTA_SAIDA / "02_5_2_2_tentativas_e_tempo.tex").write_text(
        gerar_tabela_latex(t2, "lrrrrrr"), encoding="utf-8")
    (PASTA_SAIDA / "02_5_2_3_modos_de_falha.tex").write_text(
        gerar_tabela_latex(t3, "lrr"), encoding="utf-8")
    for i, t in enumerate(tabelas_524, start=1):
        (PASTA_SAIDA / f"02_5_2_4_decisao_{i}.tex").write_text(
            gerar_tabela_latex(t, "l" * (len(t.columns)-1) + "r"), encoding="utf-8")

    # 5) Exporta gráficos PNG
    print("-> Exportando gráficos PNG...")
    gerar_histograma_png(
        c2["tentativas_distribuicao"], "Número de tentativas",
        PASTA_SAIDA / "02_5_2_2_histograma_tentativas.png")
    if c2["grupos_tempo"]:
        gerar_boxplot_png(
            c2["grupos_tempo"], "Tempo total (s)",
            PASTA_SAIDA / "02_5_2_2_boxplot_tempo_por_status.png")
    if not t3.empty:
        gerar_barras_png(
            t3["Categoria do erro"].tolist(),
            t3["Quantidade"].tolist(),
            PASTA_SAIDA / "02_5_2_3_barras_modos_falha.png",
            titulo_eixo_y="Quantidade de execuções")

    # 6) Preâmbulo recomendado
    (PASTA_SAIDA / "02_preambulo_recomendado.tex").write_text(
        PREAMBULO_LATEX, encoding="utf-8")

    # 7) Relatório textual
    print("-> Gerando relatório textual...")
    relatorio = gerar_relatorio_texto(t1, r1, t2, c2, t3, tabelas_524, avisos_524)
    (PASTA_SAIDA / "02_relatorio_bloco_b.txt").write_text(relatorio, encoding="utf-8")

    print("\n" + relatorio)
    print(f"\n-> Todos os artefatos salvos em: {PASTA_SAIDA}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
