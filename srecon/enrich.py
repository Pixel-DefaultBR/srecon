"""Extração/enriquecimento a partir do crawl do katana — funções puras e testáveis."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit


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
    return path.endswith(".js") or path.endswith(".mjs")


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


# Regras de segredo de alto sinal (evita ruído). (nome, regex)
SECRET_RULES = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("gcp_oauth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
    ("firebase_db", re.compile(r"\b[a-z0-9.-]+\.firebaseio\.com\b")),
    ("generic_secret", re.compile(
        r"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)"
        r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
    )),
]


def scan_secrets(text: str, max_len: int = 120) -> list[tuple[str, str]]:
    """Retorna [(regra, trecho)] — trecho truncado. Dedup fica a cargo do caller."""
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for name, rx in SECRET_RULES:
        for m in rx.finditer(text):
            out.append((name, m.group(0)[:max_len]))
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
