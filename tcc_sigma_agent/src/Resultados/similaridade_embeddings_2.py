"""
================================================================================
04_similaridade_embeddings.py

Objetivo
--------
Calcular as métricas de proximidade entre as regras geradas pelos 4 estágios
e as regras-gabarito (Estágio 1) — Bloco D, seções 5.4.1 e 5.4.2 da monografia.

Subseções produzidas
--------------------
  5.4.1  Similaridade semântica de cosseno entre embeddings
          a) sobre o YAML inteiro     (similaridade global)
          b) sobre o bloco detection  (similaridade da detecção)
  5.4.2  Correspondência estrutural entre regras geradas e gabarito,
         em cinco campos categóricos:
            - logsource.category, logsource.product, logsource.service (match exato)
            - tags (Jaccard, após normalização MITRE)
            - level (match exato)

Grupos comparados (todos contra o Estágio 1 / gabarito)
-------------------------------------------------------
  E2          Zero-shot filtrado (best-of-N por LLM-as-a-judge)
  E3          Prompt engineering filtrado (best-of-N por LLM-as-a-judge)
  E4-prompt1  Agente, variante prompt1
  E4-prompt2  Agente, variante prompt2
  E4-prompt3  Agente, variante prompt3 (configuração principal)

Saídas geradas
--------------
  - 04_relatorio_bloco_d.txt
  - 04_5_4_1_similaridade_estatisticas.csv / .tex
  - 04_5_4_1_similaridade_pareada.csv          (matriz cenário × grupo)
  - 04_5_4_1_boxplot_global.png
  - 04_5_4_1_boxplot_detection.png
  - 04_5_4_2_correspondencia_estrutural.csv / .tex
  - 04_5_4_2_validade_yaml.csv / .tex          (controle: % YAML válidos)

Dependências
------------
    pandas, numpy, matplotlib, pyyaml, sentence-transformers, torch
================================================================================
"""

import csv
import re
import sys
import yaml
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# =============================================================================
# CONFIGURAÇÕES — AJUSTE OS CAMINHOS CONFORME SEU AMBIENTE
# =============================================================================

# Pasta-raiz com os 50 cenários (subpastas), gabaritos e regras do Estágio 4
PASTA_TEST_CASES2 = Path(
    "/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/test_cases2")

# Pasta com as 50 regras filtradas do Estágio 2 (zero-shot)
PASTA_REGRAS_E2 = Path(
    "/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/Regras_Prompt1")

# Pasta com as 50 regras filtradas do Estágio 3 (prompt engineering)
PASTA_REGRAS_E3 = Path(
    "/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/Regras_Prompt2")

# Pasta onde os artefatos do Bloco D serão salvos
PASTA_SAIDA = Path(
    "/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/analises/D")

# Modelo de embedding (mesmo usado no RAG do agente)
NOME_MODELO_EMBEDDING = "BAAI/bge-small-en-v1.5"

# Ordem fixa dos grupos (define a ordem das colunas em todas as saídas)
ORDEM_GRUPOS = ["E2", "E3", "E4-p1", "E4-p2", "E4-p3"]

# Cores das caixas/pontos para cada grupo (mesma paleta do experimento)
CORES_GRUPO = {
    "E2":     "#6BAED6",
    "E3":     "#3182BD",
    "E4-p1":  "#BCBDDC",
    "E4-p2":  "#807DBA",
    "E4-p3":  "#54278F",
}

# Sufixos das regras do Estágio 4 dentro de cada pasta de cenário
SUFIXOS_E4 = {
    "E4-p1": "_prompt1",
    "E4-p2": "_prompt2",
    "E4-p3": "_prompt3",
}

# Normalização MITRE (mesma do Script 00 — coerência entre blocos)
MAPA_NORMALIZACAO_MITRE = {
    "stealth":            "defense-evasion",
    "defense-impairment": "defense-evasion",
}


# =============================================================================
# FUNÇÕES AUXILIARES — LaTeX
# =============================================================================

def fmt_num(x, casas=3) -> str:
    if isinstance(x, (int, np.integer)):
        return f"{x}"
    if pd.isna(x):
        return "—"
    return f"{x:.{casas}f}".replace(".", ",")


def escapar_latex(s: str) -> str:
    return (str(s)
            .replace("\\", r"\textbackslash{}")
            .replace("&", r"\&").replace("%", r"\%")
            .replace("$", r"\$").replace("#", r"\#")
            .replace("_", r"\_").replace("{", r"\{").replace("}", r"\}"))


def gerar_tabela_latex(df: pd.DataFrame, alinhamento: str,
                       cabecalhos_latex: list[str] | None = None,
                       casas_decimais: int = 3) -> str:
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
                celulas.append(fmt_num(v, casas=casas_decimais))
            else:
                celulas.append(escapar_latex(str(v)))
        linhas.append(" & ".join(celulas) + r" \\")
    linhas.append(r"\bottomrule")
    linhas.append(r"\end{tabular}")
    return "\n".join(linhas) + "\n"


# =============================================================================
# DESCOBERTA E PAREAMENTO DE ARQUIVOS
# =============================================================================

def listar_subpastas_cenarios(pasta_raiz: Path) -> list[Path]:
    """Cada cenário é uma subpasta de test_cases2."""
    if not pasta_raiz.is_dir():
        raise FileNotFoundError(f"Pasta não encontrada: {pasta_raiz}")
    return sorted(p for p in pasta_raiz.iterdir() if p.is_dir())


def extrair_numero_cenario_da_pasta(nome_pasta: str) -> tuple[int | None, str]:
    """Extrai o número e o 'slug' do nome de uma subpasta de cenário.

    Padrão esperado: "N nome..." (espaço como separador), ex: "5 win_firewall...".
    Retorna (numero, slug) ou (None, nome_pasta) se não casar.
    """
    m = re.match(r"^(\d+)\s+(.+)$", nome_pasta.strip())
    if m:
        return int(m.group(1)), m.group(2).strip()
    return None, nome_pasta


def extrair_numero_cenario_do_arquivo(nome_arquivo: str) -> tuple[int | None, str]:
    """Extrai o número e o 'slug' do nome de um arquivo em Regras_Prompt1/2.

    Padrão esperado: "N nome.yml" (espaço como separador), igual ao das
    subpastas de test_cases2. Exemplo: "5 win_firewall_as_add_rule_wmiprvse.yml".
    Retorna (numero, slug) ou (None, stem) se não casar.
    """
    stem = re.sub(r"\.ya?ml$", "", nome_arquivo, flags=re.IGNORECASE)
    m = re.match(r"^(\d+)\s+(.+)$", stem)
    if m:
        return int(m.group(1)), m.group(2).strip()
    return None, stem


def slugs_consistentes(s1: str, s2: str) -> bool:
    """Verificação fraca: compartilham pelo menos uma palavra significativa
    (>=4 caracteres), ignorando case e separadores."""
    def tokens(s):
        return {p for p in re.split(r"[^a-z0-9]+", s.lower()) if len(p) >= 4}
    return bool(tokens(s1) & tokens(s2))


def localizar_arquivos_cenario(subpasta: Path) -> dict[str, Path | None]:
    """Dentro da subpasta de um cenário, identifica:
        - gabarito (.yml sem sufixo _prompt*)
        - E4-p1, E4-p2, E4-p3
    """
    arquivos = {nome: None for nome in ["gabarito", "E4-p1", "E4-p2", "E4-p3"]}
    for arq in subpasta.iterdir():
        if arq.suffix.lower() not in (".yml", ".yaml"):
            continue
        stem = arq.stem
        casou_e4 = False
        for grupo, sufixo in SUFIXOS_E4.items():
            if stem.endswith(sufixo):
                arquivos[grupo] = arq
                casou_e4 = True
                break
        if not casou_e4 and arquivos["gabarito"] is None:
            arquivos["gabarito"] = arq
    return arquivos


def indexar_pasta_por_numero(pasta: Path) -> tuple[dict[int, Path], list[str]]:
    """Lê os .yml de uma pasta plana (Regras_Prompt1/2) e indexa por
    número de cenário extraído do nome do arquivo.
    Retorna (indice, avisos)."""
    indice: dict[int, Path] = {}
    avisos: list[str] = []
    if not pasta.is_dir():
        raise FileNotFoundError(f"Pasta não encontrada: {pasta}")
    for arq in sorted(pasta.iterdir()):
        if arq.suffix.lower() not in (".yml", ".yaml"):
            continue
        numero, _ = extrair_numero_cenario_do_arquivo(arq.name)
        if numero is None:
            avisos.append(
                f"Arquivo '{arq.name}' em '{pasta.name}' não bate com o padrão "
                f"'N_nome.yml' — ignorado."
            )
            continue
        if numero in indice:
            avisos.append(
                f"Cenário {numero} duplicado em '{pasta.name}': "
                f"'{indice[numero].name}' e '{arq.name}'. Mantido o primeiro."
            )
            continue
        indice[numero] = arq
    return indice, avisos


def montar_inventario(
    pasta_test_cases: Path, pasta_e2: Path, pasta_e3: Path
) -> tuple[list[dict], list[str]]:
    """Constrói uma lista de cenários, cada um com os caminhos dos 5 arquivos
    (gabarito + 4 grupos comparados). Reporta avisos para arquivos faltantes.

    Estratégia de pareamento:
      - Cenários de test_cases2: chave = número extraído do nome da pasta
        (padrão 'N nome' com espaço).
      - Regras_Prompt1/Regras_Prompt2: chave = número extraído do nome do
        arquivo (padrão 'N_nome.yml' com underscore).
    """
    avisos: list[str] = []
    indice_e2, av_e2 = indexar_pasta_por_numero(pasta_e2)
    indice_e3, av_e3 = indexar_pasta_por_numero(pasta_e3)
    avisos.extend(av_e2)
    avisos.extend(av_e3)

    cenarios = []
    for subpasta in listar_subpastas_cenarios(pasta_test_cases):
        numero, slug_pasta = extrair_numero_cenario_da_pasta(subpasta.name)
        if numero is None:
            avisos.append(
                f"Subpasta '{subpasta.name}' não bate com o padrão "
                f"'N nome' — ignorada."
            )
            continue

        arqs_locais = localizar_arquivos_cenario(subpasta)
        gabarito = arqs_locais["gabarito"]
        if gabarito is None:
            avisos.append(f"Sem gabarito em '{subpasta.name}'; cenário ignorado.")
            continue

        arq_e2 = indice_e2.get(numero)
        arq_e3 = indice_e3.get(numero)

        # Verificação fraca: o slug do arquivo E2/E3 bate com o slug da pasta?
        if arq_e2 is not None:
            _, slug_e2 = extrair_numero_cenario_do_arquivo(arq_e2.name)
            if not slugs_consistentes(slug_pasta, slug_e2):
                avisos.append(
                    f"Cenário {numero}: nomes divergentes entre pasta "
                    f"('{slug_pasta}') e E2 ('{slug_e2}'). Verificar manualmente."
                )
        else:
            avisos.append(f"E2 ausente para cenário {numero} ('{slug_pasta}').")

        if arq_e3 is not None:
            _, slug_e3 = extrair_numero_cenario_do_arquivo(arq_e3.name)
            if not slugs_consistentes(slug_pasta, slug_e3):
                avisos.append(
                    f"Cenário {numero}: nomes divergentes entre pasta "
                    f"('{slug_pasta}') e E3 ('{slug_e3}'). Verificar manualmente."
                )
        else:
            avisos.append(f"E3 ausente para cenário {numero} ('{slug_pasta}').")

        for g in ["E4-p1", "E4-p2", "E4-p3"]:
            if arqs_locais[g] is None:
                avisos.append(f"{g} ausente em '{subpasta.name}'.")

        cenarios.append({
            "subpasta": subpasta,
            "cenario": subpasta.name,
            "numero": numero,
            "gabarito": gabarito,
            "E2": arq_e2,
            "E3": arq_e3,
            "E4-p1": arqs_locais["E4-p1"],
            "E4-p2": arqs_locais["E4-p2"],
            "E4-p3": arqs_locais["E4-p3"],
        })
    return cenarios, avisos


# =============================================================================
# PARSING DE REGRAS E EXTRAÇÃO DE TEXTO
# =============================================================================

def ler_texto_yml(caminho: Path | None) -> str:
    """Retorna o texto bruto do .yml ou string vazia se inexistente/ilegível."""
    if caminho is None or not caminho.is_file():
        return ""
    try:
        return caminho.read_text(encoding="utf-8")
    except Exception:
        return ""


def parsear_yml(caminho: Path | None) -> dict | None:
    """Tenta parsear o YAML. Retorna o dict ou None em caso de erro."""
    if caminho is None or not caminho.is_file():
        return None
    try:
        doc = yaml.safe_load(caminho.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except Exception:
        return None


def extrair_texto_detection(doc: dict | None) -> str:
    """Serializa apenas o bloco 'detection' como YAML. Vazio se ausente."""
    if not doc or "detection" not in doc:
        return ""
    try:
        return yaml.safe_dump(
            doc["detection"], sort_keys=False, allow_unicode=True,
            default_flow_style=False
        )
    except Exception:
        return ""


# =============================================================================
# NORMALIZAÇÃO MITRE + EXTRAÇÃO DE CAMPOS ESTRUTURAIS
# =============================================================================

REGEX_TECNICA_MITRE = re.compile(r"^attack\.t\d+", re.IGNORECASE)
REGEX_TATICA_MITRE = re.compile(r"^attack\.([a-z][a-z\-]*)$", re.IGNORECASE)


def normalizar_tags_mitre(tags) -> set[str]:
    """Devolve o conjunto de tags MITRE normalizadas — táticas e técnicas
    juntas. Tags não-MITRE são ignoradas."""
    if not tags:
        return set()
    out = set()
    for t in tags:
        t = str(t).strip().lower()
        if REGEX_TECNICA_MITRE.match(t):
            out.add(t)   # técnicas ficam como estão
            continue
        m = REGEX_TATICA_MITRE.match(t)
        if m:
            tatica = m.group(1)
            tatica = MAPA_NORMALIZACAO_MITRE.get(tatica, tatica)
            out.add(f"attack.{tatica}")
    return out


def extrair_campos_estruturais(doc: dict | None) -> dict:
    """Extrai os campos categóricos usados na correspondência estrutural."""
    if not isinstance(doc, dict):
        return {"category": "", "product": "", "service": "",
                "tags": set(), "level": "", "yaml_valido": False}
    logsource = doc.get("logsource", {}) or {}
    return {
        "category": str(logsource.get("category", "") or "").lower().strip(),
        "product":  str(logsource.get("product",  "") or "").lower().strip(),
        "service":  str(logsource.get("service",  "") or "").lower().strip(),
        "tags":     normalizar_tags_mitre(doc.get("tags", [])),
        "level":    str(doc.get("level", "") or "").lower().strip(),
        "yaml_valido": True,
    }


# =============================================================================
# CÁLCULO DE EMBEDDINGS
# =============================================================================

def carregar_modelo_embedding(nome: str):
    """Carrega o sentence-transformers. Falha controlada se não instalado."""
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("ERRO: sentence-transformers não está instalado.", file=sys.stderr)
        print("Instale com: pip install sentence-transformers", file=sys.stderr)
        sys.exit(2)
    print(f"-> Carregando modelo de embedding '{nome}'...")
    print("   (pode demorar alguns minutos na primeira execução)")
    return SentenceTransformer(nome)


def calcular_embeddings(modelo, textos: list[str]) -> np.ndarray:
    """Calcula embeddings em batch. Textos vazios viram vetor zero — assim
    sua similaridade com qualquer outro vetor fica 0 (perda controlada)."""
    indices_nao_vazios = [i for i, t in enumerate(textos) if t.strip()]
    if not indices_nao_vazios:
        return np.zeros((len(textos), modelo.get_sentence_embedding_dimension()))
    textos_validos = [textos[i] for i in indices_nao_vazios]
    embs_validos = modelo.encode(
        textos_validos, normalize_embeddings=True,
        show_progress_bar=False, batch_size=16
    )
    dim = embs_validos.shape[1]
    out = np.zeros((len(textos), dim))
    for i_dest, i_src in enumerate(indices_nao_vazios):
        out[i_src] = embs_validos[i_dest]
    return out


def cosine_pareada(a: np.ndarray, b: np.ndarray) -> float:
    """Cosseno entre dois vetores já normalizados (= produto interno).
    Retorna 0.0 se algum vetor for nulo."""
    if np.allclose(a, 0) or np.allclose(b, 0):
        return 0.0
    return float(np.dot(a, b))


# =============================================================================
# SUBSEÇÃO 5.4.1 — SIMILARIDADE SEMÂNTICA
# =============================================================================

def calcular_5_4_1(cenarios: list[dict], modelo) -> tuple[
        pd.DataFrame, pd.DataFrame, dict[str, list[float]], dict[str, list[float]],
        dict[str, list[bool]]]:
    """Para cada cenário e cada grupo: cosseno do YAML inteiro e cosseno só
    do bloco detection contra o gabarito.

    Retorna:
        tabela_stats:    estatísticas (média, mediana, DP) por grupo
        tabela_pareada:  matriz cenário × grupo (uma coluna por grupo, por métrica)
        sims_global:     {grupo: [50 valores]}
        sims_detection:  {grupo: [50 valores]}
        det_validas:     {grupo: [50 bools]} — True se ambos gabarito e regra do
                         grupo têm bloco `detection` não-vazio. Usado para gerar
                         tabelas complementares filtradas apenas a casos válidos.
    """
    # ----- 1) Coleta os textos (YAML inteiro e bloco detection) -----
    print("-> Lendo arquivos e extraindo textos...")
    textos_yml = {"gabarito": []}
    textos_det = {"gabarito": []}
    for g in ORDEM_GRUPOS:
        textos_yml[g] = []
        textos_det[g] = []
    nomes_cenarios = []
    for cen in cenarios:
        nomes_cenarios.append(cen["cenario"])
        doc_g = parsear_yml(cen["gabarito"])
        textos_yml["gabarito"].append(ler_texto_yml(cen["gabarito"]))
        textos_det["gabarito"].append(extrair_texto_detection(doc_g))
        for g in ORDEM_GRUPOS:
            doc_g_grupo = parsear_yml(cen[g])
            textos_yml[g].append(ler_texto_yml(cen[g]))
            textos_det[g].append(extrair_texto_detection(doc_g_grupo))

    # ----- 2) Calcula embeddings em batch (mais eficiente) -----
    print("-> Calculando embeddings dos YAMLs completos...")
    embs_yml = {}
    for grp_nome, textos in textos_yml.items():
        embs_yml[grp_nome] = calcular_embeddings(modelo, textos)

    print("-> Calculando embeddings dos blocos detection...")
    embs_det = {}
    for grp_nome, textos in textos_det.items():
        embs_det[grp_nome] = calcular_embeddings(modelo, textos)

    # ----- 3) Para cada cenário e cada grupo, calcula cosseno e máscara -----
    sims_global = {g: [] for g in ORDEM_GRUPOS}
    sims_detection = {g: [] for g in ORDEM_GRUPOS}
    det_validas = {g: [] for g in ORDEM_GRUPOS}

    for i in range(len(cenarios)):
        gabarito_tem_det = bool(textos_det["gabarito"][i].strip())
        for g in ORDEM_GRUPOS:
            s_yml = cosine_pareada(embs_yml["gabarito"][i], embs_yml[g][i])
            s_det = cosine_pareada(embs_det["gabarito"][i], embs_det[g][i])
            sims_global[g].append(s_yml)
            sims_detection[g].append(s_det)
            grupo_tem_det = bool(textos_det[g][i].strip())
            det_validas[g].append(gabarito_tem_det and grupo_tem_det)

    # ----- 4) Tabela de estatísticas (uma linha por grupo) -----
    linhas = []
    for g in ORDEM_GRUPOS:
        arr_g = np.array(sims_global[g])
        arr_d = np.array(sims_detection[g])
        linhas.append({
            "Grupo": g,
            "Sim. global (média)":   arr_g.mean(),
            "Sim. global (mediana)": np.median(arr_g),
            "Sim. global (DP)":      arr_g.std(),
            "Sim. detection (média)":   arr_d.mean(),
            "Sim. detection (mediana)": np.median(arr_d),
            "Sim. detection (DP)":      arr_d.std(),
        })
    tabela_stats = pd.DataFrame(linhas)

    # ----- 5) Matriz pareada cenário × grupo (para uso futuro nos testes) -----
    dados_pareados = {"cenario": nomes_cenarios}
    for g in ORDEM_GRUPOS:
        dados_pareados[f"sim_global_{g}"] = sims_global[g]
    for g in ORDEM_GRUPOS:
        dados_pareados[f"sim_detection_{g}"] = sims_detection[g]
    for g in ORDEM_GRUPOS:
        dados_pareados[f"detection_valida_{g}"] = det_validas[g]
    tabela_pareada = pd.DataFrame(dados_pareados)

    return tabela_stats, tabela_pareada, sims_global, sims_detection, det_validas


def calcular_estatisticas_detection_validas(
    sims_detection: dict[str, list[float]],
    det_validas: dict[str, list[bool]],
) -> pd.DataFrame:
    """Recalcula estatísticas da similaridade de detection considerando
    apenas cenários onde ambos os YAMLs (gabarito e regra do grupo)
    tinham bloco `detection` extraível.

    Esta tabela complementa a 5.4.1 ao isolar o efeito de regras com
    YAML inválido (que entram com cosseno 0 e enviesam a média).
    """
    linhas = []
    for g in ORDEM_GRUPOS:
        sims = np.array(sims_detection[g])
        mask = np.array(det_validas[g])
        n_validas = int(mask.sum())
        if n_validas == 0:
            linhas.append({
                "Grupo": g, "N (válidos)": 0,
                "Média": float("nan"), "Mediana": float("nan"),
                "DP": float("nan"),
            })
            continue
        arr = sims[mask]
        linhas.append({
            "Grupo": g,
            "N (válidos)": n_validas,
            "Média": arr.mean(),
            "Mediana": float(np.median(arr)),
            "DP": arr.std(),
        })
    return pd.DataFrame(linhas)


def calcular_bimodalidade_detection(
    sims_detection: dict[str, list[float]],
) -> pd.DataFrame:
    """Diagnóstico de bimodalidade da similaridade de detection.

    Conta, para cada grupo, quantos cenários caem em três faixas:
        - "alta similaridade" (> 0,5)
        - "média similaridade" (0,1 – 0,5]
        - "muito baixa ou zero" (≤ 0,1)
    Faixas escolhidas para destacar o padrão "ou acerta ou erra
    completamente" observado nos boxplots.
    """
    linhas = []
    for g in ORDEM_GRUPOS:
        arr = np.array(sims_detection[g])
        n = len(arr)
        n_alta  = int((arr > 0.5).sum())
        n_media = int(((arr > 0.1) & (arr <= 0.5)).sum())
        n_baixa = int((arr <= 0.1).sum())
        linhas.append({
            "Grupo": g, "N": n,
            "Alta (>0,5)":   n_alta,
            "Alta (%)":      100.0 * n_alta  / n if n else 0.0,
            "Média (0,1–0,5]": n_media,
            "Média (%)":       100.0 * n_media / n if n else 0.0,
            "Baixa (≤0,1)": n_baixa,
            "Baixa (%)":    100.0 * n_baixa / n if n else 0.0,
        })
    return pd.DataFrame(linhas)


def gerar_boxplot_com_pontos_png(
    sims: dict[str, list[float]], titulo_eixo_y: str, caminho: Path
) -> None:
    """Boxplot + pontos sobrepostos (jitter), opção 2 escolhida pela usuária."""
    nomes = list(sims.keys())
    vals = [np.array(sims[n]) for n in nomes]
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=200)
    bp = ax.boxplot(
        vals, tick_labels=nomes,
        patch_artist=True, showmeans=True,
        meanprops=dict(marker="D", markerfacecolor="white",
                       markeredgecolor="black", markersize=6),
        medianprops=dict(color="black", linewidth=1.4),
        flierprops=dict(marker="", markersize=0),   # outliers vão como pontos
    )
    for patch, n in zip(bp["boxes"], nomes):
        patch.set_facecolor(CORES_GRUPO[n])
        patch.set_edgecolor("#333")
        patch.set_alpha(0.55)
    rng = np.random.default_rng(seed=12345)
    for i, v in enumerate(vals):
        x = rng.normal(i + 1, 0.06, len(v))
        ax.scatter(x, v, alpha=0.6, s=18,
                   color=CORES_GRUPO[nomes[i]],
                   edgecolor="#222", linewidth=0.4)
    ax.set_ylabel(titulo_eixo_y)
    ax.set_ylim(0.0, 1.05)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    plt.setp(ax.get_xticklabels(), rotation=15, ha="right")
    fig.tight_layout()
    fig.savefig(caminho, bbox_inches="tight")
    plt.close(fig)


# =============================================================================
# SUBSEÇÃO 5.4.2 — CORRESPONDÊNCIA ESTRUTURAL
# =============================================================================

def jaccard(a: set, b: set) -> float:
    """|A ∩ B| / |A ∪ B|. Se ambos vazios, retorna 1.0 (vacuosamente igual);
    se só um vazio, retorna 0.0."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def calcular_5_4_2(cenarios: list[dict]) -> tuple[
        pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Para cada grupo, calcula:
        - taxa de YAML válido
        - taxa de match exato em logsource.category / .product / .service
        - taxa de match exato em level
        - Jaccard médio em tags

    Retorna três tabelas:
        - t_corr_geral:    todas as 50 regras no denominador (YAML inválido
                            entra contando como erro estrutural)
        - t_corr_validos:  apenas regras com YAML válido no denominador
                            (isola o efeito da validade do YAML)
        - t_validade:      contagem de YAML válidos por grupo
    """
    # Pré-calcula campos de cada cenário
    campos = {"gabarito": []}
    for g in ORDEM_GRUPOS:
        campos[g] = []
    for cen in cenarios:
        campos["gabarito"].append(extrair_campos_estruturais(parsear_yml(cen["gabarito"])))
        for g in ORDEM_GRUPOS:
            campos[g].append(extrair_campos_estruturais(parsear_yml(cen[g])))

    # Tabela de validade YAML
    linhas_val = []
    for g in ORDEM_GRUPOS:
        n = len(campos[g])
        validos = sum(1 for c in campos[g] if c["yaml_valido"])
        linhas_val.append({
            "Grupo": g, "N": n, "YAML válidos": validos,
            "Taxa (%)": 100.0 * validos / n if n else 0.0,
        })
    tabela_validade = pd.DataFrame(linhas_val)

    def construir_tabela_corr(filtrar_yaml_valido: bool) -> pd.DataFrame:
        """Constrói tabela de correspondência estrutural. Se
        filtrar_yaml_valido=True, ignora regras com YAML inválido nos
        denominadores."""
        linhas = []
        for g in ORDEM_GRUPOS:
            # Lista de índices a considerar
            if filtrar_yaml_valido:
                idxs = [i for i, c in enumerate(campos[g]) if c["yaml_valido"]]
            else:
                idxs = list(range(len(campos[g])))

            def taxa_match(campo: str) -> float:
                num, den = 0, 0
                for i in idxs:
                    v_gab = campos["gabarito"][i].get(campo, "")
                    v_cmp = campos[g][i].get(campo, "")
                    if not v_gab:
                        continue
                    den += 1
                    if v_gab == v_cmp:
                        num += 1
                return 100.0 * num / den if den else float("nan")

            jaccards = [
                jaccard(campos["gabarito"][i]["tags"], campos[g][i]["tags"])
                for i in idxs
            ]
            jaccard_medio = float(np.mean(jaccards)) if jaccards else float("nan")

            linhas.append({
                "Grupo": g,
                "N considerado": len(idxs),
                "logsource.category (%)": taxa_match("category"),
                "logsource.product (%)":  taxa_match("product"),
                "logsource.service (%)":  taxa_match("service"),
                "tags (Jaccard médio)":   jaccard_medio,
                "level (%)":              taxa_match("level"),
            })
        return pd.DataFrame(linhas)

    tabela_corr_geral   = construir_tabela_corr(filtrar_yaml_valido=False)
    tabela_corr_validos = construir_tabela_corr(filtrar_yaml_valido=True)
    return tabela_corr_geral, tabela_corr_validos, tabela_validade


# =============================================================================
# RELATÓRIO TEXTUAL
# =============================================================================

def gerar_relatorio(avisos, t_stats, t_stats_det_validos, t_bimod,
                    t_corr_geral, t_corr_validos, t_val, n_cenarios) -> str:
    L = []
    L.append("=" * 72)
    L.append("BLOCO D — SIMILARIDADE E CORRESPONDÊNCIA ESTRUTURAL")
    L.append(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("=" * 72)
    L.append(f"\nCenários processados: {n_cenarios}")
    L.append(f"Modelo de embedding:  {NOME_MODELO_EMBEDDING}")

    if avisos:
        L.append(f"\nAVISOS DE PAREAMENTO ({len(avisos)}):")
        for a in avisos[:20]:
            L.append(f"  - {a}")
        if len(avisos) > 20:
            L.append(f"  ... e mais {len(avisos) - 20} avisos.")

    L.append("\n\n5.4.1  ESTATÍSTICAS DE SIMILARIDADE (todas as 50 regras)")
    L.append("-" * 72)
    L.append(t_stats.to_string(index=False, float_format=lambda x: f"{x:.3f}"))

    L.append("\n\n5.4.1 (complementar)  SIMILARIDADE DA DETECTION — APENAS YAML VÁLIDOS")
    L.append("-" * 72)
    L.append("Filtra cenários onde gabarito e regra do grupo têm bloco")
    L.append("'detection' extraível. Isola o efeito da invalidade do YAML.")
    L.append("")
    L.append(t_stats_det_validos.to_string(index=False, float_format=lambda x: f"{x:.3f}"))

    L.append("\n\n5.4.1 (complementar)  BIMODALIDADE DA SIMILARIDADE DA DETECTION")
    L.append("-" * 72)
    L.append("Quantos cenários caem em três faixas de similaridade:")
    L.append("  - Alta:  > 0,5   (detection bem alinhada ao gabarito)")
    L.append("  - Média: 0,1 – 0,5 (detection parcialmente alinhada)")
    L.append("  - Baixa: ≤ 0,1   (detection muito divergente ou ausente)")
    L.append("")
    L.append(t_bimod.to_string(index=False, float_format=lambda x: f"{x:.1f}"))

    L.append("\n\n5.4.2  CORRESPONDÊNCIA ESTRUTURAL (todas as 50 regras)")
    L.append("-" * 72)
    L.append(t_corr_geral.to_string(index=False, float_format=lambda x: f"{x:.2f}"))

    L.append("\n\n5.4.2 (complementar)  CORRESPONDÊNCIA ESTRUTURAL — APENAS YAML VÁLIDOS")
    L.append("-" * 72)
    L.append("Mesma análise, mas com denominador restrito às regras que")
    L.append("efetivamente parsearam. Mostra a capacidade do grupo quando")
    L.append("a barreira sintática é vencida.")
    L.append("")
    L.append(t_corr_validos.to_string(index=False, float_format=lambda x: f"{x:.2f}"))

    L.append("\nValidade YAML por grupo:")
    L.append(t_val.to_string(index=False, float_format=lambda x: f"{x:.1f}"))
    return "\n".join(L)


# =============================================================================
# EXECUÇÃO PRINCIPAL
# =============================================================================

def main() -> int:
    PASTA_SAIDA.mkdir(parents=True, exist_ok=True)

    # 1) Monta inventário
    print(f"-> Indexando arquivos...")
    cenarios, avisos = montar_inventario(
        PASTA_TEST_CASES2, PASTA_REGRAS_E2, PASTA_REGRAS_E3
    )
    print(f"   {len(cenarios)} cenários encontrados em test_cases2.")
    if avisos:
        print(f"   {len(avisos)} avisos de pareamento (ver relatório).")

    # 2) Carrega modelo
    modelo = carregar_modelo_embedding(NOME_MODELO_EMBEDDING)

    # 3) 5.4.1 — Similaridades
    print("\n-> Calculando 5.4.1 (similaridades de cosseno)...")
    t_stats, t_pareada, sims_global, sims_det, det_validas = \
        calcular_5_4_1(cenarios, modelo)
    t_stats_det_validos = calcular_estatisticas_detection_validas(
        sims_det, det_validas)
    t_bimod = calcular_bimodalidade_detection(sims_det)

    # 4) 5.4.2 — Correspondência estrutural (geral + complementar)
    print("\n-> Calculando 5.4.2 (correspondência estrutural)...")
    t_corr_geral, t_corr_validos, t_val = calcular_5_4_2(cenarios)

    # 5) Exporta CSVs
    print("\n-> Exportando CSVs...")
    t_stats.to_csv(PASTA_SAIDA / "04_5_4_1_similaridade_estatisticas.csv",
                   index=False, encoding="utf-8")
    t_stats_det_validos.to_csv(
        PASTA_SAIDA / "04_5_4_1_similaridade_detection_validos.csv",
        index=False, encoding="utf-8")
    t_bimod.to_csv(PASTA_SAIDA / "04_5_4_1_bimodalidade_detection.csv",
                   index=False, encoding="utf-8")
    t_pareada.to_csv(PASTA_SAIDA / "04_5_4_1_similaridade_pareada.csv",
                     index=False, encoding="utf-8")
    t_corr_geral.to_csv(PASTA_SAIDA / "04_5_4_2_correspondencia_estrutural.csv",
                        index=False, encoding="utf-8")
    t_corr_validos.to_csv(
        PASTA_SAIDA / "04_5_4_2_correspondencia_validos.csv",
        index=False, encoding="utf-8")
    t_val.to_csv(PASTA_SAIDA / "04_5_4_2_validade_yaml.csv",
                 index=False, encoding="utf-8")

    # 6) Tabelas LaTeX
    print("-> Exportando tabelas LaTeX...")
    (PASTA_SAIDA / "04_5_4_1_similaridade_estatisticas.tex").write_text(
        gerar_tabela_latex(t_stats, "lrrrrrr"), encoding="utf-8")

    # Helper para formatar tabelas de correspondência (% com 1 casa, Jaccard 3)
    def formatar_corr(t: pd.DataFrame) -> pd.DataFrame:
        t_fmt = t.copy()
        for col in t_fmt.columns:
            if col == "Grupo" or col == "N considerado":
                continue
            if "%" in col:
                t_fmt[col] = t_fmt[col].apply(
                    lambda x: "—" if pd.isna(x) else f"{x:.1f}".replace(".", ","))
            elif "Jaccard" in col:
                t_fmt[col] = t_fmt[col].apply(
                    lambda x: "—" if pd.isna(x) else f"{x:.3f}".replace(".", ","))
        return t_fmt

    (PASTA_SAIDA / "04_5_4_2_correspondencia_estrutural.tex").write_text(
        gerar_tabela_latex(formatar_corr(t_corr_geral), "lrrrrrr"),
        encoding="utf-8")
    (PASTA_SAIDA / "04_5_4_2_correspondencia_validos.tex").write_text(
        gerar_tabela_latex(formatar_corr(t_corr_validos), "lrrrrrr"),
        encoding="utf-8")
    (PASTA_SAIDA / "04_5_4_2_validade_yaml.tex").write_text(
        gerar_tabela_latex(t_val, "lrrr"), encoding="utf-8")

    # Tabela LaTeX para a 5.4.1 complementar (detection-válidos)
    (PASTA_SAIDA / "04_5_4_1_similaridade_detection_validos.tex").write_text(
        gerar_tabela_latex(t_stats_det_validos, "lrrrr"),
        encoding="utf-8")

    # Tabela LaTeX para bimodalidade — formata % com 1 casa
    t_bimod_fmt = t_bimod.copy()
    for col in t_bimod_fmt.columns:
        if "%" in col:
            t_bimod_fmt[col] = t_bimod_fmt[col].apply(
                lambda x: f"{x:.1f}".replace(".", ","))
    (PASTA_SAIDA / "04_5_4_1_bimodalidade_detection.tex").write_text(
        gerar_tabela_latex(t_bimod_fmt, "lrrrrrrr"),
        encoding="utf-8")

    # 7) Gráficos PNG (boxplot + pontos)
    print("-> Exportando gráficos PNG...")
    gerar_boxplot_com_pontos_png(
        sims_global, "Similaridade de cosseno (YAML completo)",
        PASTA_SAIDA / "04_5_4_1_boxplot_global.png")
    gerar_boxplot_com_pontos_png(
        sims_det, "Similaridade de cosseno (bloco detection)",
        PASTA_SAIDA / "04_5_4_1_boxplot_detection.png")

    # 8) Relatório textual
    print("-> Gerando relatório textual...")
    relatorio = gerar_relatorio(
        avisos, t_stats, t_stats_det_validos, t_bimod,
        t_corr_geral, t_corr_validos, t_val, len(cenarios))
    (PASTA_SAIDA / "04_relatorio_bloco_d.txt").write_text(relatorio, encoding="utf-8")

    print("\n" + relatorio)
    print(f"\n-> Todos os artefatos salvos em: {PASTA_SAIDA}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
