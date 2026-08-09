"""Extração/enriquecimento a partir do crawl do katana — funções puras e testáveis."""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from math import log2
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit


def url_host(url: str) -> str | None:
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return None
    if not netloc:
        return None
    netloc = netloc.rsplit("@", 1)[-1]          # tira userinfo
    if netloc.startswith("["):                   # IPv6 [::1]:port
        end = netloc.find("]")
        host = netloc[1:end] if end != -1 else netloc
    else:
        host = netloc.split(":", 1)[0]           # tira porta
    return host.lower() or None


def is_js(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs", ".jsx"))


def has_params(url: str) -> bool:
    return bool(urlsplit(url).query)


def param_names(url: str) -> list[str]:
    q = urlsplit(url).query
    if not q:
        return []
    return [k for k, _ in parse_qsl(q, keep_blank_values=True)]


_API_RE = re.compile(
    r"(/api/|/api$|/v[0-9]+/|/graphql|/rest/|/rpc/|/swagger|/openapi|/oauth|/\.well-known/)",
    re.IGNORECASE,
)


def is_api(url: str) -> bool:
    sp = urlsplit(url)
    path = sp.path
    if _API_RE.search(path):
        return True
    return path.lower().endswith(".json")


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            if self._cur is not None:        # flush form ainda aberto (HTML malformado)
                self.forms.append(self._cur)
            self._cur = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name:
                self._cur["inputs"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def find_forms(html: str) -> list[dict]:
    if not html or "<form" not in html.lower():
        return []
    p = _FormParser()
    try:
        p.feed(html)
    except Exception:
        pass
    if p._cur is not None:          # form sem fechamento
        p.forms.append(p._cur)
    return p.forms


# Regras de segredo, ancoradas por prefixo/estrutura p/ ALTO sinal (baixo ruído).
# Cada regra: (nome, regex, severidade). scan_secrets junta TODAS; o caller dedup.
# 'generic_secret' é a única regra de baixo sinal: passa por filtro de entropia +
# denylist de placeholder p/ não inundar o secrets.txt com 'password=changeme'.
SECRET_RULES = [
    # --- cloud / provedores (credenciais diretas) ---
    ("aws_access_key",       re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("aws_secret",           re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "high"),
    ("aws_s3_bucket",        re.compile(r"\b[a-z0-9][a-z0-9.\-]{1,61}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b"), "low"),
    ("google_api_key",       re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("gcp_oauth_client",     re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "medium"),
    ("gcp_service_account",  re.compile(r'"type"\s*:\s*"service_account"'), "high"),
    ("google_oauth_refresh", re.compile(r"\b1//[0-9A-Za-z_\-]{30,}\b"), "medium"),
    ("azure_storage_key",    re.compile(r"AccountKey=[A-Za-z0-9+/]{86,}=="), "high"),
    ("digitalocean_token",   re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b"), "high"),
    # --- SaaS / dev tooling ---
    ("slack_token",          re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("slack_webhook",        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"), "high"),
    ("stripe_key",           re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"), "high"),
    ("github_token",         re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "high"),
    ("github_pat",           re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"), "high"),
    ("gitlab_token",         re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), "high"),
    ("npm_token",            re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"), "high"),
    ("npmrc_authtoken",      re.compile(r"_authToken\s*=\s*[^\s'\"]{16,}"), "high"),
    ("pypi_token",           re.compile(r"\bpypi-AgEIcHlwaS[A-Za-z0-9_\-]{50,}\b"), "high"),
    ("shopify_token",        re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"), "high"),
    ("square_token",         re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}\b"), "high"),
    ("sendgrid_key",         re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"), "high"),
    # 32-hex puro casa md5/GUID/cache-key sem contexto -> 'low' p/ não inflar 'medium'
    ("twilio_key",           re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "low"),
    ("twilio_sid",           re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "low"),
    ("mailgun_key",          re.compile(r"\bkey-[0-9a-f]{32}\b"), "low"),
    ("mapbox_secret",        re.compile(r"\bsk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"), "medium"),
    ("telegram_bot_token",   re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"), "medium"),
    ("discord_webhook",      re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"), "high"),
    ("openai_key",           re.compile(r"\bsk-(?!ant-|proj-)[A-Za-z0-9]{20,}\b"), "high"),
    ("openai_project_key",   re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"), "high"),
    ("anthropic_key",        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high"),
    # --- tokens/credenciais de estrutura conhecida ---
    ("jwt",                  re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    ("private_key",          re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high"),
    ("bearer",               re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"), "medium"),
    ("firebase_db",          re.compile(r"\b[a-z0-9.-]+\.firebaseio\.com\b"), "low"),
    ("db_connection_string", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"), "high"),
    ("basic_auth_url",       re.compile(r"\bhttps?://[^\s:@/]+:[^\s:@/]+@[^\s/]+"), "medium"),
    ("generic_secret",       re.compile(
        r"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
    ), "low"),
]

SECRET_SEVERITY = {name: sev for name, _rx, sev in SECRET_RULES}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

# regras de baixo sinal que passam pelo filtro de entropia/placeholder
_HIGH_NOISE = {"generic_secret"}

# tokens que denunciam placeholder/exemplo — não é segredo de verdade
_PLACEHOLDER_RE = re.compile(
    r"(?i)(?:your[_-]?|example|sample|placeholder|redacted|dummy|changeme|change[_-]me|"
    r"xxxx+|test[_-]?key|secret[_-]?here|<[^>]{1,40}>|\{\{|\}\}|\$\{|todo|fixme)"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * log2(k / n) for k in freq.values())


def _looks_real_secret(value: str) -> bool:
    """Heurística p/ o generic_secret: descarta placeholder e baixa entropia."""
    v = (value or "").strip()
    if len(v) < 8:
        return False
    if _PLACEHOLDER_RE.search(v):
        return False
    if len(set(v)) <= 3:                         # 'aaaaaaaa', 'ababab'
        return False
    return _shannon_entropy(v) >= 3.0


def secret_severity(rule: str) -> str:
    return SECRET_SEVERITY.get(rule, "medium")


def secret_sort_key(rule: str) -> int:
    return _SEV_ORDER.get(secret_severity(rule), 1)


def redact_secret(frag: str, keep: int = 4) -> str:
    """Mascara o miolo p/ exibição ('AKIA…MPLE'). Nunca revela o segredo inteiro."""
    s = (frag or "").strip()
    if len(s) <= keep * 2:
        return (s[:2] + "…") if len(s) > 2 else "…"
    return f"{s[:keep]}…{s[-keep:]}"


def scan_secrets(text: str, max_len: int = 120) -> list[tuple[str, str]]:
    """Retorna [(regra, trecho)] — trecho truncado. Dedup fica a cargo do caller.
    A regra de baixo sinal ('generic_secret') passa por filtro de entropia/placeholder."""
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for name, rx, _sev in SECRET_RULES:
        for m in rx.finditer(text):
            if name in _HIGH_NOISE:
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if not _looks_real_secret(value):
                    continue
            # colapsa whitespace: frag precisa ser 1 LINHA (senão \n/\t quebram o TSV
            # do secrets.txt e partem o registro de um segredo real ao meio).
            frag = " ".join(m.group(0).split())[:max_len]
            out.append((name, frag))
    return out


# --------------------- mineração de endpoints/params em JS -------------------- #
# "APIs escondidas": bundles de JS carregam rotas que nunca aparecem como <a href>.
# Extraímos literais de string que sejam URL absoluta OU caminho absoluto (/...).
# Alto sinal: exigimos estrutura de path/URL e recusamos regex/template/CSS.

# literais entre aspas simples, duplas ou crase (sem quebra de linha)
_QUOTED_RE = re.compile(r"""'([^'\n\r]{2,512})'|"([^"\n\r]{2,512})"|`([^`\n\r]{2,512})`""")
# ruído que denuncia regex/glob/template/seletor no CORPO do path (a query é tratada à parte)
_PATH_NOISE = set("<>{}()|\\^$*?!`")
# no corpo de uma URL a query é permitida; só barramos caracteres claramente inválidos
_URL_NOISE = set("<>{}\\^`")


def _looks_path(s: str) -> bool:
    """Caminho absoluto plausível: '/a/b', '/api/v1/users?id=1', '/x.json'."""
    if len(s) < 2 or len(s) > 300 or s.startswith("//"):
        return False  # '//' é protocol-relative/comentário, não path
    if any(c.isspace() for c in s) or "${" in s:
        return False  # template string, não endpoint literal
    path = s.split("?", 1)[0].split("#", 1)[0]   # valida só o path; ?query pode ter =&
    if any(c in _PATH_NOISE for c in path):
        return False
    if "=" in path:
        return False  # '=' não pertence ao path (padding base64 de __VIEWSTATE etc.)
    if not re.search(r"[A-Za-z0-9]", path[1:]):
        return False  # precisa de conteúdo alfanumérico após a 1ª barra
    # segmento gigante = blob/base64 (ex.: __VIEWSTATE '/wEPDwUK...'), não é rota
    if any(len(seg) > 40 for seg in path.strip("/").split("/")):
        return False
    return True


def _looks_url(s: str) -> bool:
    if any(c.isspace() for c in s) or "${" in s or any(c in _URL_NOISE for c in s):
        return False
    try:
        sp = urlsplit(s)
    except ValueError:
        return False
    return bool(sp.scheme in ("http", "https") and sp.netloc)


def _iter_string_literals(text: str):
    for m in _QUOTED_RE.finditer(text):
        s = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if s:
            yield s


def extract_js_endpoints(text: str) -> set[str]:
    """URLs absolutas e caminhos '/...' embutidos em literais de string do JS/body."""
    out: set[str] = set()
    if not text:
        return out
    for s in _iter_string_literals(text):
        if s.startswith(("http://", "https://")):
            if _looks_url(s):
                out.add(s)
        elif s.startswith("/"):
            if _looks_path(s):
                out.add(s)
    return out


# ------------------------- arquivos/paths "interessantes" -------------------- #
# Alto sinal de exposição: backup/VCS/config/segredo/painel. Usado p/ realçar
# achados do crawl e do fuzz (não é veredito — é priorização de atenção).
_INTERESTING_EXT = re.compile(
    r"\.(?:bak|old|orig|save|swp|swo|tmp|copy|inc|"
    r"zip|tar|gz|tgz|bz2|rar|7z|"
    r"sql|db|sqlite|sqlite3|dump|mdb|"
    r"log|"
    r"env|ini|conf|cfg|config|yml|yaml|toml|properties|"
    r"pem|key|crt|cer|p12|pfx|jks|keystore|"
    r"war|jar|"
    r"git|~)$",
    re.IGNORECASE,
)
_INTERESTING_PATH = re.compile(
    r"(?:/\.git\b|/\.svn\b|/\.hg\b|/\.bzr\b|"
    r"/\.env\b|/\.ds_store\b|/\.aws\b|/\.ssh\b|/\.npmrc\b|/\.htpasswd\b|/\.htaccess\b|"
    r"/web\.config\b|/wp-config\.php|/config\.(?:php|json|ya?ml)|/settings\.py|"
    r"/application\.properties|/appsettings\.json|"
    r"/phpinfo\.php|/info\.php|/server-status\b|/server-info\b|/actuator\b|"
    r"/swagger\b|/openapi\b|/api-docs\b|/graphql\b|/adminer\b|/phpmyadmin\b|"
    r"/\.well-known/security\.txt|"
    r"/id_rsa\b|/id_dsa\b|/credentials\b|/backup\b|/dump\b|/\.bash_history\b)",
    re.IGNORECASE,
)


def is_interesting(url: str) -> bool:
    """True se a URL/path tem cara de arquivo/endpoint sensível (backup/VCS/config/etc.)."""
    s = (url or "").split("?", 1)[0].split("#", 1)[0].rstrip("/")
    if not s:
        return False
    return bool(_INTERESTING_EXT.search(s) or _INTERESTING_PATH.search(s))


def extract_js_params(text: str) -> set[str]:
    """Nomes de parâmetro de query encontrados em literais de string do JS."""
    out: set[str] = set()
    if not text:
        return out
    for s in _iter_string_literals(text):
        # só olhamos literais que tenham query string ('?a=1' ou 'x?a=1&b=2')
        if "?" not in s or any(c.isspace() for c in s):
            continue
        q = s.split("?", 1)[1].split("#", 1)[0]
        if "=" not in q:
            continue
        for pair in re.split(r"[&;]", q):
            name = pair.split("=", 1)[0].strip()
            # nome de param: token simples, sem template/interpolação
            if name and len(name) <= 64 and re.fullmatch(r"[A-Za-z0-9_.\-\[\]]+", name):
                out.add(name)
    return out


# ------------------- rotas em chamadas HTTP do JS (fetch/axios/xhr) ---------- #
# extract_js_endpoints só pega literais que começam com '/' ou 'http'. Muitas rotas
# reais aparecem como argumento RELATIVO de fetch()/axios/$.get()/xhr.open()
# (ex.: 'api/v1/users'). Aqui puxamos o argumento-URL dessas chamadas, com filtro
# de sinal (rejeita template/regex/string qualquer).
_ROUTE_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax)|\.(?:get|post|put|patch|delete|request))"""
    r"""\s*\(\s*["'`]([^"'`\s]{2,300})["'`]""",
    re.IGNORECASE,
)
# xhr.open(METHOD, URL): a URL é o 2º argumento (o 1º é 'GET'/'POST'/…).
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*["'`][A-Za-z]{3,7}["'`]\s*,\s*["'`]([^"'`\s]{2,300})["'`]"""
)


def _accept_route(s: str, out: set) -> None:
    s = (s or "").strip()
    if not s or "${" in s or any(c.isspace() for c in s):
        return
    if s.startswith(("http://", "https://")):
        if _looks_url(s):
            out.add(s)
    elif s.startswith("/"):
        if _looks_path(s):
            out.add(s)
    else:                                        # relativo: exige cara de rota de API
        cand = "/" + s
        if _API_RE.search(cand) and _looks_path(cand):
            out.add(s)


def extract_js_routes(text: str) -> set[str]:
    """Rotas de chamadas HTTP no JS (fetch/axios/$.get/xhr.open), incluindo caminhos
    RELATIVOS com cara de API ('api/v1/x') que extract_js_endpoints não captura."""
    out: set[str] = set()
    if not text:
        return out
    for m in _ROUTE_CALL_RE.finditer(text):
        _accept_route(m.group(1), out)
    for m in _XHR_OPEN_RE.finditer(text):
        _accept_route(m.group(1), out)
    return out


# ----------------------- sourcemaps: recuperar o fonte ----------------------- #
# Bundles de produção costumam apontar (ou deixar adjacente) um .map com
# sourcesContent — o código-fonte ORIGINAL, bem mais rico p/ minerar endpoints e
# segredos que o bundle minificado. Achamos a referência, adivinhamos o candidato
# por convenção e parseamos. O download (ATIVO) fica no comando crawl, gated por scope.
_SOURCEMAP_REF_RE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s'\"*]+)")


def find_sourcemap_refs(js_text: str, js_url: str = "") -> list[str]:
    """URLs de sourcemap referenciadas no JS (//# sourceMappingURL=...), resolvidas
    relativo ao js_url. Ignora data: URIs inline."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _SOURCEMAP_REF_RE.finditer(js_text or ""):
        ref = m.group(1).strip()
        if not ref or ref.startswith("data:"):
            continue
        url = urljoin(js_url, ref) if js_url else ref
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def sourcemap_guess(js_url: str) -> str | None:
    """Candidato .map por convenção ('app.js' -> 'app.js.map'). Só p/ .js/.mjs/.cjs."""
    if not js_url:
        return None
    try:
        sp = urlsplit(js_url)
    except ValueError:
        return None
    if not sp.path.endswith((".js", ".mjs", ".cjs")):
        return None
    return urlunsplit((sp.scheme, sp.netloc, sp.path + ".map", "", ""))


def parse_sourcemap(map_text: str) -> dict:
    """Extrai o fonte recuperado de um sourcemap JSON.
    Retorna {'sources': [...], 'contents': [...], 'recovered': int}."""
    res: dict = {"sources": [], "contents": [], "recovered": 0}
    if not map_text:
        return res
    try:
        data = json.loads(map_text)
    except (ValueError, TypeError):
        return res
    if not isinstance(data, dict):
        return res
    res["sources"] = [str(s) for s in (data.get("sources") or []) if isinstance(s, str)]
    res["contents"] = [c for c in (data.get("sourcesContent") or []) if isinstance(c, str) and c]
    res["recovered"] = len(res["contents"])
    return res
