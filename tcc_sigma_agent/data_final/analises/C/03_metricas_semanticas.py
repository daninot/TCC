"""
================================================================================
03_metricas_semanticas.py

Objetivo
--------
Calcular os indicadores qualitativos do desempenho do agente segundo a
avaliação do nó 6 (juiz LLM-as-a-judge) — Bloco C, seções 5.3.1 a 5.3.4
da monografia.

Subseções produzidas
--------------------
  5.3.1  Distribuição de vereditos do juiz (global e por prompt)
  5.3.2  Taxa de PASS, WARN, FAIL por dimensão de avaliação
  5.3.3  Delta nó 5 <-> nó 6: cruzamento status sintático x veredito semântico
  5.3.4  Mapa qualitativo dos motivos de reprovação (parser de motivo_reprovacao)

Dependências
------------
    pandas, numpy, matplotlib
================================================================================
"""

import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# =============================================================================
# CONFIGURAÇÕES
# =============================================================================

ARQUIVO_ENTRADA = Path(
    "/home/daniela/Documents/TCC/tcc_sigma_agent/analise/metadados_unificado.csv"
)
PASTA_SAIDA = Path("/home/daniela/Documents/TCC/tcc_sigma_agent/analise")

DIMENSOES_JUIZ = [
    "juiz_logsource",
    "juiz_modifiers",
    "juiz_condition",
    "juiz_structure",
    "juiz_semantic_alignment",
    "juiz_invented_filters",
]

# Mapa nome técnico -> nome para exibição (em pt-BR)
NOMES_DIMENSAO_EXIBICAO = {
    "juiz_logsource":          "logsource",
    "juiz_modifiers":          "modifiers",
    "juiz_condition":          "condition",
    "juiz_structure":          "structure",
    "juiz_semantic_alignment": "semantic\nalignment",
    "juiz_invented_filters":   "invented\nfilters",
}

# Ordem fixa dos vereditos (do melhor ao pior + sentinelas)
ORDEM_VEREDITO = ["APPROVED", "APPROVED_WITH_WARNINGS", "REJECTED", "(não avaliado)"]
ORDEM_STATUS_JUIZ = ["PASS", "WARN", "FAIL", "(vazio)"]

# Cores por veredito (para gráficos empilhados)
CORES_VEREDITO = {
    "APPROVED":               "#2E8B57",  # verde
    "APPROVED_WITH_WARNINGS": "#DAA520",  # amarelo/dourado
    "REJECTED":               "#B22222",  # vermelho
    "(não avaliado)":         "#999999",  # cinza
}

CORES_STATUS = {
    "PASS":    "#2E8B57",
    "WARN":    "#DAA520",
    "FAIL":    "#B22222",
    "(vazio)": "#999999",
}


# =============================================================================
# Geradores LaTeX e PNG (reaproveitados do Script 2)
# =============================================================================

def fmt_num(x, casas=1) -> str:
    if isinstance(x, (int, np.integer)):
        return f"{x}"
    return f"{x:.{casas}f}".replace(".", ",")


def escapar_latex(s: str) -> str:
    return (str(s)
            .replace("\\", r"\textbackslash{}")
            .replace("&", r"\&").replace("%", r"\%")
            .replace("$", r"\$").replace("#", r"\#")
            .replace("_", r"\_").replace("{", r"\{").replace("}", r"\}"))


def gerar_tabela_latex(df: pd.DataFrame, alinhamento: str,
                       cabecalhos_latex: list[str] | None = None) -> str:
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


# =============================================================================
# SUBSEÇÃO 5.3.1 — DISTRIBUIÇÃO DE VEREDITOS
# =============================================================================

def calcular_5_3_1(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Distribuição global e por prompt dos vereditos do juiz."""
    df = df.copy()
    df["veredito_juiz"] = df["veredito_juiz"].fillna("(não avaliado)")
    df.loc[df["veredito_juiz"] == "", "veredito_juiz"] = "(não avaliado)"

    linhas = []
    grupos = [("global", df)] + [
        (p, df[df["prompt_usado"] == p]) for p in sorted(df["prompt_usado"].unique())
    ]
    for grupo, sub in grupos:
        n = len(sub)
        cont = sub["veredito_juiz"].value_counts()
        linha = {"Grupo": grupo, "N": n}
        for v in ORDEM_VEREDITO:
            qtd = int(cont.get(v, 0))
            pct = 100.0 * qtd / n if n else 0.0
            linha[v] = qtd
            linha[f"{v} (%)"] = pct
        linhas.append(linha)
    tabela = pd.DataFrame(linhas)

    # Dados para gráfico empilhado: prompts no eixo x, vereditos empilhados
    dados_grafico = {}
    for p in sorted(df["prompt_usado"].unique()):
        sub = df[df["prompt_usado"] == p]
        dados_grafico[p] = {v: int((sub["veredito_juiz"] == v).sum())
                            for v in ORDEM_VEREDITO}

    return tabela, dados_grafico


def gerar_barras_empilhadas_png(dados: dict, caminho: Path,
                                titulo_eixo_y: str = "Quantidade") -> None:
    """Barras empilhadas: cada barra é um prompt; cada cor é um veredito."""
    prompts = list(dados.keys())
    n_prompts = len(prompts)
    if n_prompts == 0:
        return

    fig, ax = plt.subplots(figsize=(7, 5), dpi=200)
    bottoms = np.zeros(n_prompts)
    for v in ORDEM_VEREDITO:
        valores = [dados[p].get(v, 0) for p in prompts]
        if sum(valores) == 0:
            continue
        bars = ax.bar(prompts, valores, bottom=bottoms,
                      color=CORES_VEREDITO[v], edgecolor="white",
                      width=0.6, label=v)
        # rótulos dentro de cada segmento se for grande o bastante
        for b, val in zip(bars, valores):
            if val >= 5:  # só rotula segmentos >= 5
                ax.text(b.get_x() + b.get_width()/2,
                        b.get_y() + b.get_height()/2,
                        str(val), ha="center", va="center",
                        color="white", fontweight="bold", fontsize=10)
        bottoms += np.array(valores)

    ax.set_ylabel(titulo_eixo_y)
    ax.set_ylim(0, max(bottoms) * 1.05)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.10),
              ncol=2, frameon=False, fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(caminho, bbox_inches="tight")
    plt.close(fig)


# =============================================================================
# SUBSEÇÃO 5.3.2 — TAXA DE PASS/WARN/FAIL POR DIMENSÃO
# =============================================================================

def calcular_5_3_2(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Para cada dimensão do juiz: contagem e percentual de PASS/WARN/FAIL.

    O denominador é o número de regras com a dimensão preenchida (exclui
    casos onde o juiz não emitiu parecer).
    """
    linhas = []
    dados_grafico = {}
    for dim in DIMENSOES_JUIZ:
        # filtra valores válidos (não NaN, não vazio)
        valores = df[dim].fillna("(vazio)").astype(str)
        valores = valores.where(valores != "", "(vazio)")
        cont = Counter(valores)
        avaliadas = sum(v for k, v in cont.items() if k != "(vazio)")
        nome = NOMES_DIMENSAO_EXIBICAO[dim].replace("\n", " ")
        linha = {
            "Dimensão": nome,
            "N avaliado": avaliadas,
            "PASS": int(cont.get("PASS", 0)),
            "WARN": int(cont.get("WARN", 0)),
            "FAIL": int(cont.get("FAIL", 0)),
            "PASS (%)": 100.0 * cont.get("PASS", 0) / avaliadas if avaliadas else 0.0,
            "WARN (%)": 100.0 * cont.get("WARN", 0) / avaliadas if avaliadas else 0.0,
            "FAIL (%)": 100.0 * cont.get("FAIL", 0) / avaliadas if avaliadas else 0.0,
        }
        linhas.append(linha)
        dados_grafico[nome] = {
            "PASS": int(cont.get("PASS", 0)),
            "WARN": int(cont.get("WARN", 0)),
            "FAIL": int(cont.get("FAIL", 0)),
        }
    tabela = pd.DataFrame(linhas)
    # ordena por %PASS decrescente para o leitor enxergar ranking
    tabela = tabela.sort_values("PASS (%)", ascending=False).reset_index(drop=True)
    return tabela, dados_grafico


def gerar_barras_agrupadas_png(dados: dict, caminho: Path,
                               titulo_eixo_y: str = "Quantidade") -> None:
    """Barras agrupadas: para cada dimensão, três barras (PASS/WARN/FAIL)."""
    dims = list(dados.keys())
    n = len(dims)
    if n == 0:
        return
    x = np.arange(n)
    largura = 0.27

    fig, ax = plt.subplots(figsize=(9, 5), dpi=200)
    for i, s in enumerate(["PASS", "WARN", "FAIL"]):
        valores = [dados[d].get(s, 0) for d in dims]
        offset = (i - 1) * largura
        bars = ax.bar(x + offset, valores, largura,
                      color=CORES_STATUS[s], edgecolor="black",
                      linewidth=0.5, label=s)
        max_v = max(max(dados[d].values()) for d in dims)
        for b, v in zip(bars, valores):
            if v > 0:
                ax.text(b.get_x() + b.get_width()/2,
                        b.get_height() + max_v*0.015,
                        str(v), ha="center", va="bottom", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([NOMES_DIMENSAO_EXIBICAO_DICT.get(d, d) for d in dims],
                       rotation=0, fontsize=9)
    ax.set_ylabel(titulo_eixo_y)
    ax.legend(loc="upper right", frameon=False)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(caminho, bbox_inches="tight")
    plt.close(fig)


# precisa estar acessível a partir da função acima
NOMES_DIMENSAO_EXIBICAO_DICT = {
    "logsource": "logsource",
    "modifiers": "modifiers",
    "condition": "condition",
    "structure": "structure",
    "semantic alignment": "semantic\nalignment",
    "invented filters": "invented\nfilters",
}


# =============================================================================
# SUBSEÇÃO 5.3.3 — DELTA NÓ 5 <-> NÓ 6
# =============================================================================

def calcular_5_3_3(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Tabela cruzada status x veredito_juiz: revela o gap entre validação
    sintática e qualidade semântica."""
    df = df.copy()
    df["veredito_juiz"] = df["veredito_juiz"].fillna("(não avaliado)")
    df.loc[df["veredito_juiz"] == "", "veredito_juiz"] = "(não avaliado)"

    tabela = pd.crosstab(
        df["status"], df["veredito_juiz"],
        margins=True, margins_name="Total"
    )
    # garante ordem das colunas
    cols_existentes = [c for c in ORDEM_VEREDITO if c in tabela.columns]
    tabela = tabela[cols_existentes + ["Total"]]
    tabela = tabela.reset_index()

    # Resumo numérico para o relatório textual
    n5_aprov = (df["status"] == "APROVADO").sum()
    n5_reprov = (df["status"] == "REPROVADO").sum()
    if n5_aprov:
        sub = df[df["status"] == "APROVADO"]
        approved_no_6 = (sub["veredito_juiz"] == "APPROVED").sum()
        warn_no_6 = (sub["veredito_juiz"] == "APPROVED_WITH_WARNINGS").sum()
        rejected_no_6 = (sub["veredito_juiz"] == "REJECTED").sum()
    else:
        approved_no_6 = warn_no_6 = rejected_no_6 = 0

    resumo = {
        "n5_aprov": int(n5_aprov),
        "n5_reprov": int(n5_reprov),
        "aprovadas_e_perfeitas": int(approved_no_6),
        "aprovadas_com_ressalvas": int(warn_no_6),
        "aprovadas_mas_rejeitadas_pelo_juiz": int(rejected_no_6),
        "pct_perfeitas_sobre_aprovadas": (
            100.0 * approved_no_6 / n5_aprov if n5_aprov else 0.0),
        "pct_aprov_no_5_e_rejeitadas_no_6": (
            100.0 * rejected_no_6 / n5_aprov if n5_aprov else 0.0),
    }
    return tabela, resumo


# =============================================================================
# SUBSEÇÃO 5.3.4 — MAPA QUALITATIVO DOS MOTIVOS
# =============================================================================

# Regex para parsear motivo_reprovacao:
# Formato observado: "[no_5_validador] <msg> || [no_6_juiz/<veredito>] dim[STATUS]: coment | dim[STATUS]: coment ..."
REGEX_NO5 = re.compile(r"\[no_5_validador\]\s*(.+?)\s*\|\|", re.DOTALL)
REGEX_NO6_HEADER = re.compile(r"\[no_6_juiz/(\w+)\]\s*(.*)", re.DOTALL)
# Cada comentário tem o formato: <dim>[STATUS]: <texto>
# Vamos extrair: (dim, status, texto até o próximo "| <dim>[" ou fim)
REGEX_COMENTARIO = re.compile(
    r"(\w+)\[(\w+)\]:\s*(.+?)(?=\s*\|\s*\w+\[\w+\]:|$)",
    re.DOTALL
)


def parsear_motivo(texto: str) -> dict:
    """Recebe a string de motivo_reprovacao e devolve um dict com:
        - msg_no5            : str
        - veredito_no6       : str
        - comentarios        : list[dict(dim, status, texto)]
    """
    if not isinstance(texto, str) or not texto.strip():
        return {"msg_no5": "", "veredito_no6": "", "comentarios": []}

    m5 = REGEX_NO5.search(texto)
    msg_no5 = m5.group(1).strip() if m5 else ""

    veredito = ""
    comentarios = []
    m6_idx = texto.find("[no_6_juiz/")
    if m6_idx >= 0:
        bloco6 = texto[m6_idx:]
        # cabeçalho
        m6h = re.match(r"\[no_6_juiz/(\w+)\]\s*(.*)", bloco6, re.DOTALL)
        if m6h:
            veredito = m6h.group(1)
            corpo = m6h.group(2)
            for mc in REGEX_COMENTARIO.finditer(corpo):
                comentarios.append({
                    "dim": mc.group(1),
                    "status": mc.group(2),
                    "texto": mc.group(3).strip()[:300],   # trunca a 300 chars
                })
    return {"msg_no5": msg_no5, "veredito_no6": veredito,
            "comentarios": comentarios}


def calcular_5_3_4(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Extrai comentários do juiz e produz duas tabelas:
        - tabela_resumo:  contagem de WARN+FAIL por dimensão
        - tabela_amostras: amostras de comentários para categorização manual
    """
    comentarios_por_dim = defaultdict(list)
    contagem_por_dim_status = defaultdict(Counter)
    for _, row in df.iterrows():
        info = parsear_motivo(row.get("motivo_reprovacao", ""))
        for c in info["comentarios"]:
            comentarios_por_dim[c["dim"]].append({
                "cenario_id": row["cenario_id"],
                "prompt": row["prompt_usado"],
                "status_no5": row["status"],
                "veredito_no6": info["veredito_no6"],
                "status_dim": c["status"],
                "comentario": c["texto"],
            })
            contagem_por_dim_status[c["dim"]][c["status"]] += 1

    # Tabela-resumo: dimensão x status, com contagens
    linhas = []
    for dim in sorted(comentarios_por_dim.keys()):
        c = contagem_por_dim_status[dim]
        linhas.append({
            "Dimensão": dim,
            "PASS": int(c.get("PASS", 0)),
            "WARN": int(c.get("WARN", 0)),
            "FAIL": int(c.get("FAIL", 0)),
            "Total comentários": sum(c.values()),
        })
    tabela_resumo = pd.DataFrame(linhas).sort_values(
        "Total comentários", ascending=False).reset_index(drop=True)

    # Tabela-amostras: para cada dimensão, até 6 comentários (3 FAIL + 3 WARN)
    linhas_am = []
    for dim, comentarios in comentarios_por_dim.items():
        fails = [c for c in comentarios if c["status_dim"] == "FAIL"][:3]
        warns = [c for c in comentarios if c["status_dim"] == "WARN"][:3]
        for c in fails + warns:
            linhas_am.append({
                "Dimensão": dim,
                "Status": c["status_dim"],
                "Cenário": c["cenario_id"],
                "Prompt": c["prompt"],
                "Comentário": c["comentario"][:200],
            })
    tabela_amostras = pd.DataFrame(linhas_am)
    return tabela_resumo, tabela_amostras


# =============================================================================
# RELATÓRIO TEXTUAL
# =============================================================================

def gerar_relatorio_texto(t1, dg1, t2, dg2, t3, r3, t4r, t4a) -> str:
    L = []
    L.append("=" * 72)
    L.append("BLOCO C — MÉTRICAS SEMÂNTICAS (NÓ 6 / JUIZ)")
    L.append(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("=" * 72)

    L.append("\n5.3.1  DISTRIBUIÇÃO DE VEREDITOS DO JUIZ")
    L.append("-" * 72)
    L.append(t1.to_string(index=False, float_format=lambda x: f"{x:.1f}"))

    L.append("\n\n5.3.2  TAXA DE PASS/WARN/FAIL POR DIMENSÃO")
    L.append("-" * 72)
    L.append(t2.to_string(index=False, float_format=lambda x: f"{x:.1f}"))

    L.append("\n\n5.3.3  DELTA NÓ 5 ↔ NÓ 6")
    L.append("-" * 72)
    L.append(t3.to_string(index=False))
    L.append(f"""
  Achados-chave (sobre as {r3['n5_aprov']} regras aprovadas pelo nó 5):
   - {r3['aprovadas_e_perfeitas']} ({r3['pct_perfeitas_sobre_aprovadas']:.1f}%) receberam APPROVED do juiz
   - {r3['aprovadas_com_ressalvas']} foram APPROVED_WITH_WARNINGS
   - {r3['aprovadas_mas_rejeitadas_pelo_juiz']} ({r3['pct_aprov_no_5_e_rejeitadas_no_6']:.1f}%) foram REJEITADAS pelo juiz
   
  Leitura: validação sintática é condição necessária mas não suficiente
  para qualidade semântica.""")

    L.append("\n\n5.3.4  MOTIVOS DE REPROVAÇÃO POR DIMENSÃO (tabela-resumo)")
    L.append("-" * 72)
    L.append(t4r.to_string(index=False))
    L.append("\n  (Amostras detalhadas em 03_5_3_4_amostras_comentarios.csv)")

    return "\n".join(L)


# =============================================================================
# EXECUÇÃO PRINCIPAL
# =============================================================================

def main() -> int:
    PASTA_SAIDA.mkdir(parents=True, exist_ok=True)

    print(f"-> Carregando '{ARQUIVO_ENTRADA}'...")
    if not ARQUIVO_ENTRADA.is_file():
        print(f"ERRO: arquivo não encontrado.", file=sys.stderr)
        return 1
    df = pd.read_csv(ARQUIVO_ENTRADA)
    print(f"   {len(df)} linhas carregadas.")

    print("\n-> Calculando 5.3.1 (distribuição de vereditos)...")
    t1, dg1 = calcular_5_3_1(df)
    print("-> Calculando 5.3.2 (taxa por dimensão)...")
    t2, dg2 = calcular_5_3_2(df)
    print("-> Calculando 5.3.3 (delta nó 5 <-> nó 6)...")
    t3, r3 = calcular_5_3_3(df)
    print("-> Calculando 5.3.4 (motivos de reprovação)...")
    t4r, t4a = calcular_5_3_4(df)

    print("\n-> Exportando CSVs e tabelas LaTeX...")
    t1.to_csv(PASTA_SAIDA / "03_5_3_1_vereditos.csv", index=False, encoding="utf-8")
    t2.to_csv(PASTA_SAIDA / "03_5_3_2_dimensoes.csv", index=False, encoding="utf-8")
    t3.to_csv(PASTA_SAIDA / "03_5_3_3_delta_no5_no6.csv", index=False, encoding="utf-8")
    t4r.to_csv(PASTA_SAIDA / "03_5_3_4_motivos_resumo.csv", index=False, encoding="utf-8")
    t4a.to_csv(PASTA_SAIDA / "03_5_3_4_amostras_comentarios.csv",
               index=False, encoding="utf-8")

    # Tabelas LaTeX simplificadas (versões enxutas para a monografia)
    # 5.3.1 — só colunas de quantidade (sem %), para a tabela ficar curta
    t1_latex = t1[["Grupo", "N"] + [v for v in ORDEM_VEREDITO if v in t1.columns]]
    (PASTA_SAIDA / "03_5_3_1_vereditos.tex").write_text(
        gerar_tabela_latex(t1_latex, "lr" + "r"*len(ORDEM_VEREDITO)),
        encoding="utf-8")

    # 5.3.2 — exporta a versão com %
    t2_latex = t2[["Dimensão", "N avaliado", "PASS", "WARN", "FAIL",
                   "PASS (%)", "WARN (%)", "FAIL (%)"]]
    (PASTA_SAIDA / "03_5_3_2_dimensoes.tex").write_text(
        gerar_tabela_latex(t2_latex, "lrrrrrrr"), encoding="utf-8")

    # 5.3.3 — cross-tab
    (PASTA_SAIDA / "03_5_3_3_delta_no5_no6.tex").write_text(
        gerar_tabela_latex(t3, "l" + "r"*(len(t3.columns)-1)), encoding="utf-8")

    # 5.3.4 — resumo
    (PASTA_SAIDA / "03_5_3_4_motivos_resumo.tex").write_text(
        gerar_tabela_latex(t4r, "lrrrr"), encoding="utf-8")

    print("-> Exportando gráficos PNG...")
    gerar_barras_empilhadas_png(dg1, PASTA_SAIDA / "03_5_3_1_vereditos_por_prompt.png",
                                titulo_eixo_y="Quantidade de regras")
    gerar_barras_agrupadas_png(dg2, PASTA_SAIDA / "03_5_3_2_dimensoes.png",
                               titulo_eixo_y="Quantidade de regras")

    print("-> Gerando relatório textual...")
    relatorio = gerar_relatorio_texto(t1, dg1, t2, dg2, t3, r3, t4r, t4a)
    (PASTA_SAIDA / "03_relatorio_bloco_c.txt").write_text(relatorio, encoding="utf-8")

    print("\n" + relatorio)
    print(f"\n-> Todos os artefatos salvos em: {PASTA_SAIDA}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
