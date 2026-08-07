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
