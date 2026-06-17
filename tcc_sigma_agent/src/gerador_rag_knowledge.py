import os
import random
import shutil
import yaml
from collections import Counter

# ============================================================
# CONFIGURAÇÕES
# ============================================================
SIGMA_REPO_DIR  = "/home/daniela/Documents/TCC/sigma/"
TRAIN_DIR       = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/rag_knowledge/"
TEST_DIR        = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/test_cases/"
EXTRA_TEST_DIR  = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/extra_test_cases/"

TRAIN_PERCENTAGE  = 0.85

DIRETORIOS_PERMITIDOS = [
    'rules',
    'rules-compliance',
    'rules-emerging-threats',
    'rules-placeholder',
    'rules-threat-hunting'
]

random.seed(42)


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def get_logsource_key(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and 'logsource' in doc:
                    logsource = doc['logsource']
                    category = logsource.get('category', 'any')
                    product  = logsource.get('product',  'any')
                    service  = logsource.get('service',  'any')
                    return f"{category}_{product}_{service}"
    except Exception:
        pass
    return "unknown"


def get_safe_filename(rule_path):
    caminho_relativo = os.path.relpath(rule_path, SIGMA_REPO_DIR)
    return caminho_relativo.replace(os.sep, '_')


def copy_files_to_dir(file_list, dest_dir):
    count = 0
    for src_path in file_list:
        safe_name = get_safe_filename(src_path)
        dst_path  = os.path.join(dest_dir, safe_name)
        shutil.copy2(src_path, dst_path)
        count += 1
    return count


def selecionar_round_robin(regras_por_categoria, quantidade):
    """Seleciona 'quantidade' regras distribuindo uniformemente entre categorias."""
    selecionadas = []
    lista_categorias = [cat for cat in regras_por_categoria if regras_por_categoria[cat]]
    random.shuffle(lista_categorias)

    while len(selecionadas) < quantidade and lista_categorias:
        for cat in list(lista_categorias):
            if len(selecionadas) >= quantidade:
                break
            if regras_por_categoria[cat]:
                escolhida = random.choice(regras_por_categoria[cat])
                selecionadas.append(escolhida)
                regras_por_categoria[cat].remove(escolhida)
            if not regras_por_categoria[cat]:
                lista_categorias.remove(cat)

    return selecionadas


def relatorio_distribuicao(nome_dataset, lista_regras, top_n=10):
    print(f"\n--- Distribuição de '{nome_dataset}' ({len(lista_regras)} regras) ---")
    if not lista_regras:
        print("   (vazio)")
        return

    categorias = Counter(get_logsource_key(r) for r in lista_regras)
    total_cats = len(categorias)
    print(f"   Categorias distintas representadas: {total_cats}")
    print(f"   Top {min(top_n, total_cats)} categorias mais frequentes:")
    for cat, count in categorias.most_common(top_n):
        pct = (count / len(lista_regras)) * 100
        barra = '█' * int(pct / 2)
        print(f"     {count:>5}  ({pct:5.1f}%)  {barra} {cat}")


# ============================================================
# FLUXO PRINCIPAL — APENAS rag_knowledge
# ============================================================

def main():

    # ----------------------------------------------------------
    # PASSO 1 — Varrer o repositório Sigma
    # ----------------------------------------------------------
    print("=" * 85)
    print("PASSO 1: Lendo o repositório Sigma...")
    print("=" * 85)

    all_valid_rules = []
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):
        if root == SIGMA_REPO_DIR:
            dirs[:] = [d for d in dirs if d in DIRETORIOS_PERMITIDOS]
            continue
        for file in files:
            if file.endswith('.yml'):
                all_valid_rules.append(os.path.join(root, file))

    total_repo = len(all_valid_rules)
    print(f" -> {total_repo} regras válidas encontradas no repositório.")

    if total_repo == 0:
        print("ERRO: nenhuma regra encontrada. Verifique SIGMA_REPO_DIR.")
        return

    # ----------------------------------------------------------
    # PASSO 2 — Mapear arquivos PRESERVADOS (test_cases + extra_test_cases)
    #           Ambos precisam ser excluídos do pool para evitar
    #           data leakage no RAG.
    # ----------------------------------------------------------
    print("\n" + "=" * 85)
    print("PASSO 2: Mapeando conjuntos preservados...")
    print("=" * 85)

    nomes_em_test = set()
    if os.path.exists(TEST_DIR):
        nomes_em_test = set(f for f in os.listdir(TEST_DIR) if f.endswith('.yml'))
    print(f" -> test_cases:       {len(nomes_em_test)} arquivos.")

    nomes_em_extra = set()
    if os.path.exists(EXTRA_TEST_DIR):
        nomes_em_extra = set(f for f in os.listdir(EXTRA_TEST_DIR) if f.endswith('.yml'))
    print(f" -> extra_test_cases: {len(nomes_em_extra)} arquivos.")

    nomes_preservados = nomes_em_test | nomes_em_extra

    paths_preservados = set()
    for rule_path in all_valid_rules:
        if get_safe_filename(rule_path) in nomes_preservados:
            paths_preservados.add(rule_path)

    print(f" -> {len(paths_preservados)} regras preservadas localizadas no repositório.")
    nao_mapeadas = len(nomes_preservados) - len(paths_preservados)
    if nao_mapeadas > 0:
        print(f"   AVISO: {nao_mapeadas} arquivo(s) preservado(s) não encontrado(s) no repositório atual.")

    # ----------------------------------------------------------
    # PASSO 3 — Construir pool disponível e agrupar por categoria
    # ----------------------------------------------------------
    print("\n" + "=" * 85)
    print("PASSO 3: Construindo pool disponível...")
    print("=" * 85)

    available_pool = [r for r in all_valid_rules if r not in paths_preservados]
    total_disponivel = len(available_pool)
    print(f" -> {total_disponivel} regras disponíveis")
    print(f"    ({total_repo} total − {len(paths_preservados)} preservadas)")

    regras_por_categoria = {}
    for rule_path in available_pool:
        key = get_logsource_key(rule_path)
        regras_por_categoria.setdefault(key, []).append(rule_path)

    print(f" -> {len(regras_por_categoria)} categorias distintas no pool.")

    # ----------------------------------------------------------
    # PASSO 4 — Selecionar 75% do pool para rag_knowledge (round-robin)
    # ----------------------------------------------------------
    print("\n" + "=" * 85)
    print(f"PASSO 4: Selecionando {int(TRAIN_PERCENTAGE*100)}% do pool para rag_knowledge...")
    print("=" * 85)

    target_train = int(total_disponivel * TRAIN_PERCENTAGE)

    print(f" -> Total de regras Sigma no repositório:  {total_repo}")
    print(f"    (−) test_cases preservados:            {len(nomes_em_test)}")
    print(f"    (−) extra_test_cases preservados:      {len(nomes_em_extra)}")
    print(f"    (=) Pool disponível para o RAG:        {total_disponivel}")
    print(f" -> Quantidade esperada ({int(TRAIN_PERCENTAGE*100)}% do pool):  {target_train}")

    train_set = selecionar_round_robin(regras_por_categoria, target_train)

    print(f" -> Quantidade efetivamente selecionada:   {len(train_set)}")
    if len(train_set) < target_train:
        diff = target_train - len(train_set)
        print(f"   AVISO: faltaram {diff} regra(s) — pool insuficiente em alguma categoria.")

    # ----------------------------------------------------------
    # PASSO 5 — Gravar rag_knowledge em disco
    # ----------------------------------------------------------
    print("\n" + "=" * 85)
    print("PASSO 5: Gravando rag_knowledge em disco...")
    print("=" * 85)

    if os.path.exists(TRAIN_DIR):
        shutil.rmtree(TRAIN_DIR)
        print(f" -> rag_knowledge antiga removida.")
    os.makedirs(TRAIN_DIR, exist_ok=True)

    copiadas_treino = copy_files_to_dir(train_set, TRAIN_DIR)
    print(f" -> {copiadas_treino} regras copiadas para rag_knowledge.")

    # ----------------------------------------------------------
    # PASSO 6 — Relatório de distribuição (AUDITORIA)
    # ----------------------------------------------------------
    print("\n" + "=" * 85)
    print("PASSO 6: Relatório de distribuição (auditoria de viés)")
    print("=" * 85)

    relatorio_distribuicao("REPOSITÓRIO COMPLETO", all_valid_rules, top_n=10)
    relatorio_distribuicao("rag_knowledge", train_set, top_n=10)

    # ----------------------------------------------------------
    # RESUMO FINAL
    # ----------------------------------------------------------
    print("\n" + "=" * 85)
    print("CONCLUÍDO")
    print("=" * 85)
    print(f"  test_cases       (INTOCADO):  {len(nomes_em_test)} regras")
    print(f"  extra_test_cases (INTOCADO):  {len(nomes_em_extra)} regras")
    print(f"  rag_knowledge    (RECRIADA):  {copiadas_treino} regras")
    print("=" * 85  )


if __name__ == "__main__":
    main()
