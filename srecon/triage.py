"""Triagem/ranking: consolida TODOS os artefatos de um alvo (candidates, host/CVEs,
urls, assets) numa única lista de LEADS rankeada por impacto potencial — pra você
atacar o que importa primeiro em vez de afogar no ruído dos relatórios soltos.

Núcleo puro/testável: converte cada artefato (já parseado) em Leads e rankeia. O
I/O (achar/ler os relatórios em reports/) fica no comando.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# peso por severidade + confiança (0-100) + bônus de verificação = prioridade.
SEV_WEIGHT = {"critical": 400, "high": 300, "medium": 200, "low": 100, "info": 50}
VERIFIED_BONUS = 60


@dataclass
class Lead:
    category: str          # bug | cve | takeover | surface | asset
    title: str
    severity: str
    source: str            # de qual artefato veio
    confidence: int = 50
    verified: bool = False
    detail: str = ""

    @property
    def score(self) -> int:
        return (SEV_WEIGHT.get(self.severity, 50) + int(self.confidence)
                + (VERIFIED_BONUS if self.verified else 0))

    def sort_key(self):
        return (-self.score, self.category, self.title)


def cvss_severity(cvss) -> str:
    try:
        v = float(cvss)
    except (TypeError, ValueError):
        return "medium"
    if v != v:                       # NaN: comparações são todas False -> default medium
        return "medium"
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "medium"
    return "low"


def leads_from_candidates(data) -> list[Lead]:
    """data = lista de dicts do candidates.json."""
    out: list[Lead] = []
    for c in data or []:
        if not isinstance(c, dict):
            continue
        cls = str(c.get("class") or "?")
        ev = c.get("evidence") or {}
        cat = "takeover" if cls == "subdomain_takeover" else "bug"
        out.append(Lead(
            category=cat,
            title=f"{cls}: {c.get('param', '?')}",
            severity=str(c.get("severity") or "medium"),
            source="candidates",
            confidence=int(c.get("confidence") or 50),
            verified=bool(ev.get("verified")),
            detail=str(c.get("example") or c.get("reason") or ""),
        ))
    return out


def leads_from_host(data) -> list[Lead]:
    """data = dict do host.json (ip + vulns[{cve,cvss,verified}])."""
    out: list[Lead] = []
    if not isinstance(data, dict):
        return out
    ip = str(data.get("ip") or "?")
    for v in data.get("vulns") or []:
        if not isinstance(v, dict):
            continue
        cvss = v.get("cvss")
        sev = cvss_severity(cvss)
        out.append(Lead(
            category="cve",
            title=f"{v.get('cve', '?')} @ {ip}",
            severity=sev,
            source="host",
            confidence=80 if v.get("verified") else 55,
            verified=bool(v.get("verified")),
            detail=f"CVSS {cvss}" if cvss is not None else "",
        ))
    return out


def leads_from_urls_interesting(paths, source: str = "urls") -> list[Lead]:
    """paths = lista de URLs 'interessantes' (backup/config/VCS/painel)."""
    out: list[Lead] = []
    for u in paths or []:
        u = (u or "").strip()
        if u:
            out.append(Lead("surface", f"arquivo/endpoint sensível", "medium",
                            source, confidence=50, detail=u))
    return out


def leads_from_assets_outscope(hosts, source: str = "assets") -> list[Lead]:
    """hosts = ativos descobertos FORA de escopo — reporte ao programa p/ expandir."""
    out: list[Lead] = []
    for h in hosts or []:
        h = (h or "").strip()
        if h:
            out.append(Lead("asset", f"ativo fora de escopo: {h}", "info",
                            source, confidence=40,
                            detail="descoberto por CT/arquivo; pedir inclusão no escopo"))
    return out


def rank(leads) -> list[Lead]:
    return sorted(leads, key=lambda l: l.sort_key())


def summarize(leads) -> dict:
    """Contagem por severidade e por categoria."""
    by_sev: dict = {}
    by_cat: dict = {}
    for l in leads:
        by_sev[l.severity] = by_sev.get(l.severity, 0) + 1
        by_cat[l.category] = by_cat.get(l.category, 0) + 1
    return {"total": len(leads), "by_severity": by_sev, "by_category": by_cat}
