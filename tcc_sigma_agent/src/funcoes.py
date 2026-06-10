import re
import requests
import json
import os
from urllib.parse import urlparse

#função para encontrar todas as menções de CVE e CWE em qualquer texto:
def extrair_referencias(texto: str):
    cves = set(m.group().upper() for m in re.finditer(r"CVE-\d{4}-\d+", texto, re.IGNORECASE))
    cwes = set(m.group().upper() for m in re.finditer(r"CWE-\d+", texto, re.IGNORECASE))
    return cves, cwes

#função para extrair palavras significativas do caminho de uma URL. usado quando a página fica inacessível:
def extrair_palavras_chave_url(url:str):
    caminho = urlparse(url).path
    texto = re.sub(r"[/\-_\.]+", " ", caminho)
    lixo = {"html", "htm", "php", "asp", "aspx", "vuln", "detail", "www"}
    return [
        p.lower() for p in texto.split()
        if len(p) >= 3 and not p.isdigit() and p.lower() not in lixo
    ]

#função pra fazer uma limpa no texto pra levar pro chromadb
def extrair_secoes_tecnicas(texto: str) -> str:
    secoes_alvo = ["threat to detect", "target environment"]
    blocos = re.split(r"^#\s+", texto, flags=re.MULTILINE)
    trechos_relevantes = []
    for bloco in blocos:
        primeira_linha = bloco.split("\n", 1)[0].strip().lower()
        if any(alvo in primeira_linha for alvo in secoes_alvo):
            trechos_relevantes.append(bloco.strip())
    if trechos_relevantes:
        return "\n\n".join(trechos_relevantes)
    return texto

#função para consultar a API do MITRE para um CVE:
def consulta_mitre(cve_id:str):
    try:
        r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=10)
        if r.status_code == 200:
            descricoes = r.json().get("containers",{}).get("cna",{}).get("descriptions",[])
            if descricoes:
                return descricoes[0].get("value", "")   #retorna a descrição ou None
    except requests.exceptions.RequestException:
        pass
    return None


#função que consulta a API do NVD para um CVE:
def consulta_nvd(cve_id:str):
    try:
        url_api = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = requests.get(url_api, timeout=10)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities",[])
            if vulns:
                cve_item = vulns[0].get("cve",{})
                descricao = next(
                    (x["value"] for x in cve_item.get("descriptions",[]) if x.get("lang") == "en"),
                    None
                )
                cwes = [
                    d["value"]
                    for w in cve_item.get("weaknesses",[])
                    for d in w.get("description",[])
                    if d.get("lang") == "en"
                ]
                cvss = None
                for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if chave in cve_item.get("metrics",{}) and cve_item["metrics"][chave]:
                        cvss = cve_item["metrics"][chave][0].get("cvssData", {}).get("baseScore")
                        break
                return {"descricao": descricao, "cwes": cwes, "cvss": cvss}
    except requests.exceptions.RequestException:
        pass
    return None

# ---------- MITRE ATT&CK (validação de tags) ----------

# cache local do conjunto de técnicas válidas (carregado uma vez)
_TECNICAS_ATTACK = None

def _caminho_cache_attack():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "..", "data", "attack_tecnicas.json")


def carregar_tecnicas_attack():
    """
    Carrega o conjunto de IDs de técnicas MITRE ATT&CK válidas.
    Tenta o cache local; se não existir, baixa o STIX oficial uma vez.
    Retorna um set de strings minúsculas no formato 't1190', 't1059.001', etc.
    """
    global _TECNICAS_ATTACK
    if _TECNICAS_ATTACK is not None:
        return _TECNICAS_ATTACK

    cache = _caminho_cache_attack()

    # 1) tenta carregar do cache
    if os.path.exists(cache):
        try:
            with open(cache, "r", encoding="utf-8") as f:
                _TECNICAS_ATTACK = set(json.load(f))
                return _TECNICAS_ATTACK
        except (json.JSONDecodeError, OSError):
            pass  # cache corrompido; rebaixa

    # 2) baixa o STIX oficial (Enterprise ATT&CK)
    url = ("https://raw.githubusercontent.com/mitre/cti/master/"
           "enterprise-attack/enterprise-attack.json")
    tecnicas = set()
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            dados = r.json()
            for obj in dados.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "")
                        if ext_id.startswith("T"):
                            tecnicas.add(ext_id.lower())  # ex: 't1190'
            # salva o cache
            os.makedirs(os.path.dirname(cache), exist_ok=True)
            with open(cache, "w", encoding="utf-8") as f:
                json.dump(sorted(tecnicas), f)
    except requests.exceptions.RequestException:
        pass

    _TECNICAS_ATTACK = tecnicas
    return _TECNICAS_ATTACK


def validar_tags_attack(tags: list):
    """
    Separa as tags Sigma em válidas e inválidas conforme a taxonomia ATT&CK.
    - tags no formato 'attack.tXXXX' são checadas contra a base oficial.
    - tags 'attack.<tatica>' (initial-access, execution...) são aceitas.
    - tags que não começam com 'attack.' são deixadas como estão (não são ATT&CK).
    Retorna (tags_validas, tags_invalidas).
    """
    base_tecnicas = carregar_tecnicas_attack()

    # táticas oficiais do Enterprise ATT&CK (não são técnicas, mas são tags válidas)
    taticas_validas = {
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
    }

    validas, invalidas = [], []
    for tag in tags:
        tag_str = str(tag).strip()
        tl = tag_str.lower()

        if not tl.startswith("attack."):
            validas.append(tag_str)   # não é tag ATT&CK; não validamos aqui
            continue

        sufixo = tl.replace("attack.", "", 1)

        if sufixo.startswith("t"):
            # técnica ou sub-técnica: t1190, t1059.001
            if sufixo in base_tecnicas or sufixo.split(".")[0] in base_tecnicas:
                validas.append(tag_str)
            else:
                invalidas.append(tag_str)
        elif sufixo in taticas_validas:
            validas.append(tag_str)
        else:
            invalidas.append(tag_str)

    return validas, invalidas


# ---------- DuckDuckGo (busca incremental) ----------

def busca_duckduckgo(termo: str, max_resultados: int = 5):
    """
    Faz uma busca livre no DuckDuckGo e retorna um texto consolidado
    com títulos e resumos. Falha graciosamente se a lib não estiver
    instalada ou se houver erro de rede.
    """
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        return None

    try:
        resultados = []
        with DDGS() as ddgs:
            for r in ddgs.text(termo, max_results=max_resultados):
                titulo = r.get("title", "")
                corpo = r.get("body", "")
                resultados.append(f"{titulo}: {corpo}")
        if resultados:
            return "\n".join(resultados)
    except Exception:
        pass
    return None