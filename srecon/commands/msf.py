from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import HostReport
from ..msf import MsfIndex, MsfModule


@dataclass
class CveHit:
    cve: str
    cvss: Optional[float]
    modules: list = field(default_factory=list)   # MsfModule, rank desc


@dataclass
class ProductHit:
    product: str
    version: Optional[str]
    ports: list = field(default_factory=list)
    modules: list = field(default_factory=list)   # candidatos por palavra-chave


@dataclass
class MsfMatchResult:
    target: Optional[str] = None
    rhosts: Optional[str] = None
    cve_hits: list = field(default_factory=list)
    product_hits: list = field(default_factory=list)

    @property
    def total_cve_modules(self) -> int:
        return sum(len(h.modules) for h in self.cve_hits)

    def module_names(self) -> list[str]:
        """Nomes únicos de módulos casados por CVE (alta precisão), rank desc, para o .rc."""
        seen: set = set()
        out: list[str] = []
        for h in self.cve_hits:
            for m in h.modules:
                if m.fullname not in seen:
                    seen.add(m.fullname)
                    out.append(m.fullname)
        return out


def _filter(mods: list[MsfModule], types, min_rank: int) -> list[MsfModule]:
    out = mods
    if types:
        tset = set(types)
        out = [m for m in out if m.mtype in tset]
    if min_rank:
        out = [m for m in out if m.rank >= min_rank]
    return out


def match_cves(index: MsfIndex, cves, types=("exploit", "auxiliary"),
               cvss_by_cve: Optional[dict] = None) -> list[CveHit]:
    """CVE -> módulos (alta precisão via references). Rank NÃO é filtrado aqui."""
    cvss_by_cve = cvss_by_cve or {}
    hits: list[CveHit] = []
    seen: set = set()
    for c in cves:
        cu = (c or "").strip().upper()
        if not cu or cu in seen:
            continue
        seen.add(cu)
        mods = _filter(index.by_cve(cu), types, 0)
        hits.append(CveHit(cve=cu, cvss=cvss_by_cve.get(cu), modules=mods))
    # ordena por (tem módulo, cvss) desc — o que importa primeiro
    hits.sort(key=lambda h: (len(h.modules) > 0, h.cvss or 0.0), reverse=True)
    return hits


def match_products(index: MsfIndex, products, types=("exploit", "auxiliary"),
                   min_rank: int = 0) -> list[ProductHit]:
    """products: iterável de (product, version, ports:list)."""
    hits: list[ProductHit] = []
    for product, version, ports in products:
        if not product:
            continue
        mods = _filter(index.by_keyword(product, types=types, min_rank=min_rank),
                       types, min_rank)
        hits.append(ProductHit(product=product, version=version,
                               ports=sorted(ports or []), modules=mods))
    hits.sort(key=lambda h: len(h.modules), reverse=True)
    return hits


def _collect_cves(report: HostReport) -> dict:
    """CVE(upper) -> maior cvss visto (nível host + por serviço)."""
    out: dict = {}
    for v in report.vulns:
        c = v.cve.upper()
        if c not in out or (v.cvss or 0) > (out[c] or 0):
            out[c] = v.cvss
    for s in report.services:
        for v in s.vulns:
            c = v.cve.upper()
            if c not in out or (v.cvss or 0) > (out[c] or 0):
                out[c] = v.cvss
    return out


def _collect_products(report: HostReport):
    agg: dict = {}
    for s in report.services:
        if not s.product:
            continue
        e = agg.setdefault(s.product, {"versions": set(), "ports": set()})
        if s.version:
            e["versions"].add(s.version)
        if s.port:
            e["ports"].add(s.port)
    for prod, e in agg.items():
        yield prod, (", ".join(sorted(e["versions"])) or None), e["ports"]


def match_host(index: MsfIndex, report: HostReport, types=("exploit", "auxiliary"),
               min_rank: int = 0) -> MsfMatchResult:
    cvss_map = _collect_cves(report)
    cve_hits = match_cves(index, list(cvss_map.keys()), types=types, cvss_by_cve=cvss_map)
    product_hits = match_products(index, _collect_products(report),
                                  types=types, min_rank=min_rank)
    return MsfMatchResult(target=report.ip, rhosts=report.ip,
                          cve_hits=cve_hits, product_hits=product_hits)
