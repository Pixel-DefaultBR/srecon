from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .. import cvedb
from ..models import CveDetail, HostReport


def lookup(cve_ids, timeout: float = 15.0):
    """Consulta cada CVE na CVEDB. Retorna (detalhes, erros)."""
    details: list[CveDetail] = []
    errors: list = []
    seen: set = set()
    for cid in cve_ids:
        cu = (cid or "").strip().upper()
        if not cu or cu in seen:
            continue
        seen.add(cu)
        try:
            details.append(cvedb.get_cve(cu, timeout=timeout))
        except cvedb.CvedbError as e:
            errors.append((cu, str(e)))
    return details, errors


@dataclass
class VulnAgg:
    cve: str
    max_cvss: float | None = None
    verified: bool = False
    count: int = 0
    hosts: list = field(default_factory=list)


def aggregate_reports(reports_dir: Path, min_cvss: float = 0.0) -> list[VulnAgg]:
    """Varre reports/**/host.json e agrega CVEs por host (sem API, sem credits)."""
    agg: dict = {}
    if not reports_dir.is_dir():
        return []
    for p in sorted(reports_dir.glob("**/host.json")):
        try:
            rep = HostReport.model_validate_json(p.read_text(errors="ignore"))
        except (OSError, ValueError):
            continue
        host = rep.ip or p.parent.name
        for v in rep.vulns:
            c = v.cve.upper()
            e = agg.get(c)
            if e is None:
                e = agg[c] = VulnAgg(cve=c)
            if v.cvss is not None and (e.max_cvss is None or v.cvss > e.max_cvss):
                e.max_cvss = v.cvss
            e.verified = e.verified or v.verified
            if host not in e.hosts:
                e.hosts.append(host)
                e.count += 1
    out = [e for e in agg.values() if (e.max_cvss or 0.0) >= min_cvss]
    out.sort(key=lambda e: (-(e.max_cvss or 0.0), -e.count, e.cve))
    return out
