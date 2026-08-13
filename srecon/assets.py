"""Asset pivoting PASSIVO: descobre ativos interligados ao alvo por fontes de
terceiros (Certificate Transparency via crt.sh + ASN/netblock via RIPEstat).
Opcionalmente pivota por favicon hash no Shodan (--shodan, gasta credit).

Filosofia: fontes GRÁTIS e passivas primeiro (não tocam o alvo, não gastam
credit). O favicon->Shodan é opt-in. Como o `subs`/`urls`, anota in/out de
escopo e nunca bloqueia. Funções puras/testáveis; I/O de rede isolado.

O favicon hash usa o MESMO cálculo do Shodan (mmh3 de 32 bits sobre o favicon
codificado em base64.encodebytes), implementado em Python puro p/ não exigir a
lib mmh3 — mantém a tool só-stdlib.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from . import scope as scopemod

_UA = "srecon/assets"
CRTSH = "https://crt.sh/"
RIPESTAT = "https://stat.ripe.net/data"   # bgpview.io saiu do ar (NXDOMAIN); RIPEstat é o substituto passivo


class AssetsError(Exception):
    pass


def _get(url: str, timeout: float = 20.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (host fixo, https)
            return resp.read()
    except urllib.error.HTTPError as e:
        raise AssetsError(f"HTTP {e.code} em {urllib.parse.urlsplit(url).netloc}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise AssetsError(f"falha de rede: {e}") from e


# ------------------------ Certificate Transparency -------------------------- #

import re as _re
_HOST_RE = _re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def _clean_host(h: str) -> Optional[str]:
    h = (h or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    return h if h and _HOST_RE.match(h) else None


def crtsh_url(domain: str) -> str:
    return CRTSH + "?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})


def parse_crtsh_json(raw: bytes | str) -> set[str]:
    """Extrai hostnames do JSON do crt.sh (campo name_value pode ter várias linhas)."""
    out: set[str] = set()
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return out
    if not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict):
            continue
        for field_key in ("name_value", "common_name"):
            val = row.get(field_key) or ""
            for part in str(val).splitlines():
                h = _clean_host(part)
                if h:
                    out.add(h)
    return out


_sleep = time.sleep       # hook p/ testes (monkeypatch -> no-op)


def fetch_crtsh(domain: str, timeout: float = 30.0, retries: int = 2,
                backoff: float = 2.0) -> set[str]:
    """crt.sh é notoriamente instável (502/503 sob carga). Tenta de novo com backoff
    antes de desistir — a maioria dos 5xx é transitória."""
    last: Optional[AssetsError] = None
    for attempt in range(retries + 1):
        try:
            return parse_crtsh_json(_get(crtsh_url(domain), timeout=timeout))
        except AssetsError as e:
            last = e
            if attempt < retries:
                _sleep(backoff * (attempt + 1))
    raise last if last else AssetsError("crt.sh: falha desconhecida")


# ------------------------------ ASN / netblock ------------------------------ #

@dataclass
class AsnInfo:
    ip: str
    asn: Optional[int] = None
    asn_name: str = ""
    org: str = ""
    prefix: str = ""            # netblock que contém o IP (ex: 203.0.113.0/24)
    country: str = ""


def parse_ripestat_prefix(raw: bytes | str, ip: str) -> Optional[AsnInfo]:
    """Parseia RIPEstat prefix-overview: prefixo + ASN + holder numa só resposta.
    Holder vem como 'AS263449 - THINK IT LTDA.'; separamos o número do nome."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("status") not in (None, "ok"):
        return None
    d = data.get("data") or {}
    if not isinstance(d, dict):
        return None
    info = AsnInfo(ip=ip)
    info.prefix = str(d.get("resource") or "")
    asns = d.get("asns") or []
    if asns and isinstance(asns, list):
        first = asns[0] or {}
        if isinstance(first, dict):
            try:
                info.asn = int(first.get("asn")) if first.get("asn") is not None else None
            except (ValueError, TypeError):
                info.asn = None
            holder = str(first.get("holder") or "")
            # 'AS263449 - THINK IT LTDA.' -> nome legível após o ' - '
            name = holder.split(" - ", 1)[1] if " - " in holder else holder
            info.asn_name = name
            info.org = name
    return info


def fetch_asn(ip: str, timeout: float = 20.0) -> Optional[AsnInfo]:
    url = f"{RIPESTAT}/prefix-overview/data.json?resource={ip}"
    return parse_ripestat_prefix(_get(url, timeout=timeout), ip)


# --------------------------------- favicon ---------------------------------- #

def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 assinado — mesmo hash que o Shodan usa em http.favicon.hash."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = int.from_bytes(data[i:i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(favicon_bytes: bytes) -> int:
    """Receita do Shodan: mmh3 sobre o favicon em base64.encodebytes (com os \\n)."""
    return mmh3_32(base64.encodebytes(favicon_bytes))


def fetch_favicon_bytes(url: str, timeout: int = 15) -> Optional[bytes]:
    """GET binário SEM seguir redirect (preso ao host). ATIVO: o caller deve gatear
    por escopo antes de chamar. Retorna None em qualquer falha."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read(2_000_000)
    except Exception:
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# --------------------------------- coleta ----------------------------------- #

@dataclass
class AssetsResult:
    domain: str
    ct_hosts: list = field(default_factory=list)         # hostnames do CT
    in_scope: list = field(default_factory=list)
    out_scope: list = field(default_factory=list)
    asn: Optional[AsnInfo] = None
    favicon: dict = field(default_factory=dict)          # {hash, url, shodan_count, shodan_hosts}
    errors: list = field(default_factory=list)           # (fonte, msg)


def partition_scope(hosts, scope_entries) -> tuple[list, list]:
    in_s, out_s = [], []
    for h in hosts:
        (in_s if scopemod.match(h, scope_entries) else out_s).append(h)
    return sorted(in_s), sorted(out_s)


def collect(domain: str, scope_entries, target_ip: Optional[str] = None,
            do_ct: bool = True, do_asn: bool = True,
            timeout: float = 30.0) -> AssetsResult:
    """Fontes grátis/passivas: CT (crt.sh) + ASN/netblock (RIPEstat). Degrada por fonte.
    O pivot Shodan (favicon) é feito à parte pelo caller (opt-in)."""
    dom = (domain or "").strip().lower().rstrip(".")
    if not dom:
        raise ValueError(f"domínio inválido: {domain!r}")
    res = AssetsResult(domain=dom)

    if do_ct:
        try:
            hosts = fetch_crtsh(dom, timeout=timeout)
            res.ct_hosts = sorted(hosts)
            res.in_scope, res.out_scope = partition_scope(res.ct_hosts, scope_entries)
        except AssetsError as e:
            res.errors.append(("crt.sh", str(e)))

    if do_asn and target_ip:
        try:
            res.asn = fetch_asn(target_ip, timeout=timeout)
        except AssetsError as e:
            res.errors.append(("ripestat", str(e)))

    return res


def shodan_favicon_pivot(client, favicon_hash_value: int, list_hosts: int = 20) -> dict:
    """Pivot OPT-IN: quantos hosts o Shodan vê com o mesmo favicon (dork
    http.favicon.hash:N). Usa count (não gasta result credits) + search opcional."""
    query = f"http.favicon.hash:{favicon_hash_value}"
    out: dict = {"hash": favicon_hash_value, "query": query}
    try:
        c = client.count(query)
        out["shodan_count"] = int(c.get("total", 0)) if isinstance(c, dict) else 0
    except Exception as e:  # noqa: BLE001 (o caller reporta; não deve derrubar o comando)
        out["error"] = str(e)
        return out
    if list_hosts and out.get("shodan_count"):
        try:
            sr = client.search(query, limit=list_hosts)
            out["shodan_hosts"] = sorted({m.ip for m in getattr(sr, "matches", []) if getattr(m, "ip", None)})
        except Exception as e:  # noqa: BLE001
            out["search_error"] = str(e)
    return out
