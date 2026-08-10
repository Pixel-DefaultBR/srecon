"""Recon histórico PASSIVO: coleta URLs conhecidas de arquivos públicos (Wayback
Machine CDX + gau, se instalado) e minera parâmetros escondidos.

É OSINT contra terceiros (web.archive.org / fontes do gau) — NUNCA toca no alvo,
por isso não é gated por escopo; apenas ANOTA in/out de escopo como o `subs`.
O valor pra BB: endpoints e parâmetros MORTOS que ainda respondem (superfície que
o crawl ao vivo não vê) + uma wordlist de params reais p/ fuzzing dirigido.

Funções puras/testáveis; o I/O de rede fica isolado em _get_text / run_gau.
"""
from __future__ import annotations

import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from . import enrich, scope as scopemod
from .external import resolve_bin

_UA = "srecon/archive"
WAYBACK_CDX = "http://web.archive.org/cdx/search/cdx"


class ArchiveError(Exception):
    pass


# ------------------------------- Wayback CDX -------------------------------- #

def wayback_cdx_url(domain: str, include_subs: bool = True,
                    limit: Optional[int] = None, status_ok_only: bool = False) -> str:
    """Monta a query da CDX API do Internet Archive (fl=original, dedup por urlkey)."""
    params = [
        ("url", domain),
        ("matchType", "domain" if include_subs else "host"),
        ("fl", "original"),
        ("collapse", "urlkey"),
        ("output", "text"),
    ]
    if status_ok_only:
        params.append(("filter", "statuscode:200"))
    if limit and limit > 0:
        params.append(("limit", str(limit)))
    return WAYBACK_CDX + "?" + urllib.parse.urlencode(params)


def parse_cdx_text(text: str) -> list[str]:
    """Uma URL 'original' por linha (fl=original). Normaliza e descarta lixo."""
    out: list[str] = []
    for line in (text or "").splitlines():
        u = normalize_url(line)
        if u:
            out.append(u)
    return out


def _get_text(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (host fixo)
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise ArchiveError(f"Wayback respondeu HTTP {e.code}.") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ArchiveError(f"falha de rede na Wayback: {e}") from e


def fetch_wayback(domain: str, include_subs: bool = True, limit: Optional[int] = None,
                  status_ok_only: bool = False, timeout: float = 30.0) -> list[str]:
    """Puxa URLs da CDX. Lança ArchiveError em falha de rede (o caller degrada)."""
    url = wayback_cdx_url(domain, include_subs, limit, status_ok_only)
    return parse_cdx_text(_get_text(url, timeout=timeout))


# ---------------------------------- gau ------------------------------------- #

def run_gau(domain: str, include_subs: bool = True, timeout: int = 180) -> tuple[list[str], int]:
    """gau (getallurls), se instalado. rc 127 = binário ausente (caller ignora)."""
    gau = resolve_bin("gau")
    if not gau:
        return [], 127
    cmd = [gau, "--threads", "5"]
    if include_subs:
        cmd.append("--subs")
    cmd.append(domain)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # não descarta o que já saiu (bug histórico do subs no timeout)
        partial = e.stdout if isinstance(e.stdout, str) else ""
        return [u for line in partial.splitlines() if (u := normalize_url(line))], 124
    except FileNotFoundError:
        return [], 127
    urls = [u for line in (proc.stdout or "").splitlines() if (u := normalize_url(line))]
    return urls, proc.returncode


# ------------------------------ normalização -------------------------------- #

def normalize_url(raw: str) -> Optional[str]:
    """URL http(s) com host plausível, sem whitespace. Descarta o resto."""
    u = (raw or "").strip()
    if not u or any(c.isspace() for c in u):
        return None
    if not u.startswith(("http://", "https://")):
        return None
    if enrich.url_host(u) is None:
        return None
    return u


def dedup_urls(urls) -> list[str]:
    return sorted({u for u in urls if u})


# --------------------------- inventário de params --------------------------- #

@dataclass
class ParamStat:
    name: str
    count: int = 0                 # nº de URLs distintas onde aparece
    example: str = ""              # uma URL de amostra
    values: set = field(default_factory=set)   # amostras de valor (p/ heurística depois)


# nome de param plausível: identificador, não símbolo solto. Espelha o filtro do
# enrich (JS) p/ manter params.txt como wordlist de ALTO sinal (anti-ruído: descarta
# '$2', '@_~', ',-' e afins que a Wayback arquiva de URLs quebradas/encodadas).
_PARAM_NAME_RE = re.compile(r"[A-Za-z0-9_.\-\[\]]{1,64}")


def _valid_param_name(name: str) -> bool:
    if not name or len(name) > 64:
        return False
    if not _PARAM_NAME_RE.fullmatch(name):
        return False
    return any(c.isalnum() for c in name)          # precisa de ao menos 1 alfanumérico


def build_param_inventory(urls) -> dict:
    """name -> ParamStat, a partir da query string das URLs. Base p/ fuzzing dirigido
    e p/ a classificação de candidatos (Fase C). Filtra nomes-lixo p/ alto sinal."""
    inv: dict = {}
    for u in urls:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query, keep_blank_values=True)
        seen_here: set = set()
        for name, val in pairs:
            if not _valid_param_name(name) or name in seen_here:
                continue
            seen_here.add(name)
            st = inv.get(name)
            if st is None:
                st = inv[name] = ParamStat(name=name)
            st.count += 1
            if not st.example:
                st.example = u
            if val and len(st.values) < 5:
                st.values.add(val[:64])
    return inv


# --------------------------------- coleta ----------------------------------- #

@dataclass
class UrlsResult:
    domain: str
    urls: list = field(default_factory=list)
    in_scope: list = field(default_factory=list)
    out_scope: list = field(default_factory=list)
    with_params: list = field(default_factory=list)
    api: list = field(default_factory=list)
    interesting: list = field(default_factory=list)
    params: dict = field(default_factory=dict)          # name -> ParamStat
    sources: dict = field(default_factory=dict)          # fonte -> nº bruto
    errors: list = field(default_factory=list)           # (fonte, msg)

    @property
    def param_names(self) -> list:
        return sorted(self.params)


def partition_scope(urls, scope_entries) -> tuple[list, list]:
    """(in_scope, out_scope) por host da URL. Sem escopo carregado -> tudo out."""
    in_s, out_s = [], []
    for u in urls:
        host = enrich.url_host(u)
        if host and scopemod.match(host, scope_entries):
            in_s.append(u)
        else:
            out_s.append(u)
    return in_s, out_s


def collect(domain: str, scope_entries, use_wayback: bool = True, use_gau: bool = True,
            include_subs: bool = True, limit: Optional[int] = None,
            status_ok_only: bool = False, wayback_timeout: float = 30.0,
            gau_timeout: int = 180) -> UrlsResult:
    """Orquestra as fontes passivas, deduplica e classifica. Degrada por fonte:
    se a Wayback cair, ainda tenta o gau (e vice-versa)."""
    dom = (domain or "").strip().lower().rstrip(".")
    if not dom:
        raise ValueError(f"domínio inválido: {domain!r}")

    res = UrlsResult(domain=dom)
    raw: list[str] = []

    if use_wayback:
        try:
            wb = fetch_wayback(dom, include_subs, limit, status_ok_only, wayback_timeout)
            res.sources["wayback"] = len(wb)
            raw += wb
        except ArchiveError as e:
            res.errors.append(("wayback", str(e)))

    if use_gau:
        gau_urls, rc = run_gau(dom, include_subs, gau_timeout)
        if rc == 127:
            pass                                   # gau não instalado — silencioso
        else:
            res.sources["gau"] = len(gau_urls)
            raw += gau_urls
            if rc == 124:
                res.errors.append(("gau", "timeout (resultado parcial mantido)"))

    res.urls = dedup_urls(raw)
    res.in_scope, res.out_scope = partition_scope(res.urls, scope_entries)
    res.with_params = [u for u in res.urls if enrich.has_params(u)]
    res.api = [u for u in res.urls if enrich.is_api(u)]
    res.interesting = [u for u in res.urls if enrich.is_interesting(u)]
    res.params = build_param_inventory(res.urls)
    return res
