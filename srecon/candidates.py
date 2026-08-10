"""Motor de HIPÓTESE DE BUG: transforma superfície coletada (params/URLs/hosts) em
candidatos de classe de vulnerabilidade RANKEADOS por confiança — o pulo do gato
que separa 'scanner de fruta baixa' de recon que aponta bug único.

PASSIVO por default: só classifica/rankeia a partir do dado já coletado (nome do
param + evidência no valor arquivado). A PROVA ativa (payload benigno, checar
reflexão/redirect/CORS/introspection reais) fica no comando, atrás de --active +
scope-gate. Taxonomia CURADA (não exaustiva) p/ manter alto sinal.

Funções puras/testáveis; o I/O de rede das provas ativas fica isolado.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------- #
# Taxonomia de parâmetros. Cada classe: nomes fortes (alta confiança de nome) e
# severidade. A confiança final combina nome + evidência no VALOR arquivado.
# ---------------------------------------------------------------------------- #

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# nomes de param -> forte indício da classe (curado; evita 'todo id é IDOR' vazio)
_SSRF_NAMES = {
    "url", "uri", "dest", "destination", "redirect_uri", "callback", "webhook",
    "target", "feed", "host", "domain", "site", "page_url", "src", "source",
    "load", "proxy", "fetch", "resource", "endpoint", "server", "remote",
    "image_url", "imageurl", "img_url", "avatar_url", "link", "u", "next_url",
    "return_url", "returnurl", "data_url", "path_url", "file_url", "open",
}
_REDIRECT_NAMES = {
    "redirect", "redir", "next", "return", "returnurl", "return_url", "returnto",
    "return_to", "continue", "goto", "dest", "destination", "redirect_uri",
    "redirect_url", "redirecturl", "forward", "out", "to", "rurl", "url", "u",
    "link", "checkout_url", "success_url", "cancel_url", "callback",
}
_IDOR_NAMES = {
    "id", "uid", "userid", "user_id", "user", "account", "acct", "account_id",
    "customer", "customer_id", "order", "order_id", "orderid", "invoice",
    "invoice_id", "doc", "document", "document_id", "file_id", "fileid", "pid",
    "gid", "group_id", "key", "num", "no", "record", "row", "item", "item_id",
    "object_id", "ref", "cart", "cart_id", "profile", "profile_id", "member",
    "member_id", "msg_id", "message_id", "ticket", "ticket_id", "uuid",
}
_LFI_NAMES = {
    "file", "filename", "path", "filepath", "template", "tpl", "page", "include",
    "inc", "doc", "document", "folder", "dir", "download", "load", "read", "view",
    "content", "layout", "style", "lang", "locale", "module", "conf", "config",
    "root", "pg", "cat_file", "meta", "detail",
}
_SQLI_NAMES = {
    "id", "cat", "category", "cid", "page", "sort", "order", "orderby", "order_by",
    "filter", "dir", "sortby", "sort_by", "column", "field", "table", "where",
    "query", "search", "uid", "pid", "product", "product_id", "item", "group",
    "having", "limit", "offset", "year", "month", "day", "status",
}
_XSS_NAMES = {
    "q", "query", "search", "s", "keyword", "kw", "term", "name", "message",
    "msg", "comment", "text", "title", "subject", "body", "content", "lang",
    "callback", "jsonp", "ref", "referrer", "return", "error", "err",
    "description", "feedback", "input", "data", "redirect_to", "q1", "keywords",
}
_SSTI_NAMES = {
    "template", "tpl", "cmd", "exec", "command", "run", "ping", "code", "expr",
    "eval", "preview", "render", "view_template",
}

_CLASS_RULES = [
    # (classe, severidade, nomes, confiança-base do nome)
    ("ssrf", "critical", _SSRF_NAMES, 55),
    ("open_redirect", "high", _REDIRECT_NAMES, 55),
    ("idor", "high", _IDOR_NAMES, 45),
    ("lfi", "high", _LFI_NAMES, 45),
    ("sqli", "high", _SQLI_NAMES, 40),
    ("xss", "medium", _XSS_NAMES, 45),
    ("ssti", "medium", _SSTI_NAMES, 45),
]

CLASS_SEVERITY = {cls: sev for cls, sev, _n, _c in _CLASS_RULES}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HTML_SPECIAL_RE = re.compile(r"[<>\"']|javascript:|data:text/html", re.I)


def _is_numeric(v: str) -> bool:
    return bool(v) and v.lstrip("-").isdigit()


def _is_uuid(v: str) -> bool:
    return bool(_UUID_RE.match(v or ""))


def _is_urlish(v: str) -> bool:
    v = (v or "").strip().lower()
    return v.startswith(("http://", "https://", "//")) or v.startswith(("http%3a", "%2f%2f"))


def _is_pathy(v: str) -> bool:
    v = v or ""
    return v.startswith("/") or "../" in v or "..%2f" in v.lower() or v.endswith((".php", ".jsp", ".asp"))


def _has_html(v: str) -> bool:
    return bool(_HTML_SPECIAL_RE.search(v or ""))


def _value_bonus(cls: str, value: str) -> tuple[int, str]:
    """Evidência no VALOR arquivado eleva a confiança do candidato. (bônus, motivo)."""
    v = value or ""
    if cls in ("ssrf", "open_redirect") and _is_urlish(v):
        return 35, "valor é URL/absoluto"
    if cls == "idor" and (_is_numeric(v) or _is_uuid(v)):
        return 30, "valor numérico/uuid"
    if cls == "sqli" and _is_numeric(v):
        return 20, "valor numérico"
    if cls == "lfi" and _is_pathy(v):
        return 30, "valor com cara de caminho/arquivo"
    if cls == "xss" and _has_html(v):
        return 45, "valor já contém < > \" ' (reflexão provável)"
    return 0, ""


@dataclass
class Candidate:
    vuln_class: str
    severity: str
    param: str
    confidence: int
    example: str = ""
    reason: str = ""
    evidence: dict = field(default_factory=dict)   # p/ prova ativa (verified/details)

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 9), -self.confidence, self.param)


def classify_param(name: str, value: str = "") -> list[Candidate]:
    """Candidatos de classe p/ um par (nome, valor). Um param pode gerar vários."""
    name_l = (name or "").strip().lower()
    if not name_l:
        return []
    out: list[Candidate] = []
    for cls, sev, names, base in _CLASS_RULES:
        if name_l not in names:
            continue
        bonus, why = _value_bonus(cls, value)
        conf = min(100, base + bonus)
        reason = f"nome '{name_l}' típico de {cls}" + (f"; {why}" if why else "")
        out.append(Candidate(cls, sev, name_l, conf, reason=reason))
    return out


def classify_urls(urls, min_confidence: int = 40) -> list[Candidate]:
    """Varre URLs, classifica cada param, DEDUPLICA por (classe, param) mantendo o de
    maior confiança e um exemplo. Retorna candidatos ordenados (sev, -conf)."""
    best: dict = {}
    for u in urls:
        try:
            q = urllib.parse.urlsplit(u).query
        except ValueError:
            continue
        if not q:
            continue
        for name, val in urllib.parse.parse_qsl(q, keep_blank_values=True):
            for c in classify_param(name, val):
                if c.confidence < min_confidence:
                    continue
                key = (c.vuln_class, c.param)
                cur = best.get(key)
                if cur is None or c.confidence > cur.confidence:
                    c.example = u
                    best[key] = c
    return sorted(best.values(), key=lambda c: c.sort_key())


# ---------------------------------------------------------------------------- #
# Subdomain takeover: CNAME pendurado -> serviço reclamável. Tabela de fingerprint
# (fragmento de corpo que o provedor devolve quando o recurso não existe).
# ---------------------------------------------------------------------------- #

@dataclass
class TakeoverFingerprint:
    service: str
    cname_patterns: tuple           # sufixos de CNAME que apontam pro provedor
    body_signatures: tuple          # trechos no corpo que indicam recurso não-reclamado
    severity: str = "high"


TAKEOVER_FINGERPRINTS = [
    TakeoverFingerprint("github-pages", ("github.io",),
                        ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file")),
    TakeoverFingerprint("heroku", ("herokudns.com", "herokuapp.com", "herokussl.com"),
                        ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    TakeoverFingerprint("aws-s3", ("s3.amazonaws.com", "s3-website", ".s3."),
                        ("NoSuchBucket", "The specified bucket does not exist"), "critical"),
    TakeoverFingerprint("azure", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                                  "trafficmanager.net", "blob.core.windows.net", "azureedge.net"),
                        ("404 Web Site not found", "The specified blob does not exist")),
    TakeoverFingerprint("fastly", ("fastly.net",),
                        ("Fastly error: unknown domain",)),
    TakeoverFingerprint("shopify", ("myshopify.com",),
                        ("Sorry, this shop is currently unavailable",)),
    TakeoverFingerprint("surge", ("surge.sh",),
                        ("project not found",)),
    TakeoverFingerprint("bitbucket", ("bitbucket.io",),
                        ("Repository not found",)),
    TakeoverFingerprint("zendesk", ("zendesk.com",),
                        ("Help Center Closed",)),
    TakeoverFingerprint("readthedocs", ("readthedocs.io", "readthedocs.org"),
                        ("Maze Found", "unknown to Read the Docs")),
    TakeoverFingerprint("wordpress", ("wordpress.com",),
                        ("Do you want to register",)),
    TakeoverFingerprint("ghost", ("ghost.io",),
                        ("The thing you were looking for is no longer here",)),
]


def match_cname_service(cname: str) -> Optional[TakeoverFingerprint]:
    """CNAME aponta p/ algum provedor conhecido de takeover?"""
    c = (cname or "").strip().lower().rstrip(".")
    if not c:
        return None
    for fp in TAKEOVER_FINGERPRINTS:
        if any(pat in c for pat in fp.cname_patterns):
            return fp
    return None


def body_indicates_takeover(fp: TakeoverFingerprint, body: str) -> bool:
    """O corpo bate a assinatura de 'recurso não reclamado' do provedor?"""
    if not body:
        return False
    low = body.lower()
    return any(sig.lower() in low for sig in fp.body_signatures)


def assess_takeover(host: str, cname: str, body: Optional[str] = None) -> Optional[Candidate]:
    """Candidato de takeover a partir de host + CNAME (passivo). Se body for dado
    (prova ativa), confirma pela assinatura e sobe a confiança."""
    fp = match_cname_service(cname)
    if not fp:
        return None
    conf = 55
    reason = f"CNAME de {host} -> {cname} (provedor {fp.service})"
    ev = {"service": fp.service, "cname": cname, "verified": False}
    if body is not None:
        if body_indicates_takeover(fp, body):
            conf = 95
            reason += "; corpo bate assinatura de recurso não reclamado"
            ev["verified"] = True
        else:
            conf = 25
            reason += "; corpo NÃO bate assinatura (provavelmente reclamado)"
    return Candidate("subdomain_takeover", fp.severity, host, conf,
                     example=host, reason=reason, evidence=ev)


# ---------------------------------------------------------------------------- #
# Provas ATIVAS (opt-in, o comando gateia por escopo). Payloads BENIGNOS.
# ---------------------------------------------------------------------------- #

_UA = "srecon/candidates"
REDIRECT_CANARY_HOST = "srecon-canary.example"
REDIRECT_CANARY = f"https://{REDIRECT_CANARY_HOST}/x"
CORS_ORIGIN = "https://srecon-cors-probe.example"
XSS_CANARY = "srEc0nXSS9137"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _replace_param(url: str, param: str, value: str) -> str:
    sp = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    new = [(k, value if k == param else v) for k, v in pairs]
    return urllib.parse.urlunsplit(sp._replace(query=urllib.parse.urlencode(new)))


def _open(url: str, timeout: int, data: bytes = None, headers: dict = None,
          follow: bool = True) -> tuple[int, dict, str]:
    """(status, headers_lower, body) — nunca lança; (0, {}, '') em falha."""
    h = {"User-Agent": _UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    handlers = [] if follow else [_NoRedirect]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read(1_000_000).decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1_000_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except Exception:
        return 0, {}, ""


def probe_open_redirect(url: str, param: str, timeout: int = 12) -> dict:
    """Injeta um canário benigno e vê se o Location aponta pro host do canário."""
    target = _replace_param(url, param, REDIRECT_CANARY)
    status, hdrs, _ = _open(target, timeout, follow=False)
    loc = hdrs.get("location", "")
    verified = REDIRECT_CANARY_HOST in loc
    return {"verified": verified, "status": status, "location": loc[:300], "probe": target}


def probe_cors(url: str, timeout: int = 12) -> dict:
    """Reflete Origin arbitrária? ACAO=origin + ACAC=true = misconfig explorável."""
    status, hdrs, _ = _open(url, timeout, headers={"Origin": CORS_ORIGIN})
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "").lower()
    reflects = acao == CORS_ORIGIN or acao == "*"
    verified = reflects and (acac == "true" if acao == CORS_ORIGIN else True)
    return {"verified": bool(acao) and reflects, "exploitable": reflects and acac == "true",
            "status": status, "acao": acao[:200], "acac": acac}


def probe_graphql(url: str, timeout: int = 12) -> dict:
    """Introspection ligada? Se __schema volta, o schema está exposto."""
    payload = json.dumps({"query": "{__schema{queryType{name}}}"}).encode()
    status, _h, body = _open(url, timeout, data=payload,
                             headers={"Content-Type": "application/json"})
    verified = '"__schema"' in body or '"queryType"' in body
    return {"verified": verified, "status": status, "snippet": body[:200]}


def probe_reflection(url: str, param: str, timeout: int = 12) -> dict:
    """Canário refletido SEM encoding no corpo = candidato forte a XSS refletido."""
    target = _replace_param(url, param, XSS_CANARY)
    status, _h, body = _open(target, timeout)
    verified = XSS_CANARY in body
    return {"verified": verified, "status": status, "probe": target}


def fetch_body(url: str, timeout: int = 12) -> Optional[str]:
    """GET simples p/ confirmar takeover pela assinatura de corpo (ATIVO/gated)."""
    status, _h, body = _open(url, timeout)
    return body if status else None


# ------------------------- CNAME p/ takeover (dnsx) ------------------------- #

def resolve_cnames(hosts, timeout: int = 120) -> dict:
    """host -> cname via dnsx (-cname -json). {} se dnsx ausente. Passivo (só DNS)."""
    import subprocess
    from .external import resolve_bin
    dnsx = resolve_bin("dnsx")
    if not dnsx or not hosts:
        return {}
    cmd = [dnsx, "-silent", "-cname", "-json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input="\n".join(hosts) + "\n")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}
    out: dict = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        host = (obj.get("host") or "").strip().lower().rstrip(".")
        cnames = obj.get("cname") or []
        if host and cnames:
            out[host] = str(cnames[0]).strip().lower().rstrip(".")
    return out
