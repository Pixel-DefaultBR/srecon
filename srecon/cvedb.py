"""Cliente da CVEDB do Shodan (https://cvedb.shodan.io) — GRÁTIS, sem API key e
sem gastar query credits. Usa só a stdlib (urllib) para não depender de extras.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import CveDetail

CVEDB_BASE = "https://cvedb.shodan.io"
_UA = "srecon/cvedb"


class CvedbError(Exception):
    pass


def _get_json(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (host fixo, https)
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise CvedbError("CVE não encontrada na CVEDB (404).") from e
        raise CvedbError(f"CVEDB respondeu HTTP {e.code}.") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CvedbError(f"falha de rede ao consultar a CVEDB: {e}") from e
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise CvedbError(f"resposta inválida da CVEDB: {e}") from e
    if not isinstance(data, dict):
        raise CvedbError("formato inesperado da CVEDB.")
    return data


def get_cve(cve_id: str, timeout: float = 15.0) -> CveDetail:
    cid = (cve_id or "").strip().upper()
    return CveDetail.from_api(_get_json(f"{CVEDB_BASE}/cve/{cid}", timeout=timeout))
