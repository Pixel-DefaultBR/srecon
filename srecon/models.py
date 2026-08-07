from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


def _to_float(x) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _preview(data, n: int = 200) -> Optional[str]:
    if not data:
        return None
    s = " ".join(str(data).split())
    return s[:n] + ("…" if len(s) > n else "")


class Vuln(BaseModel):
    cve: str
    cvss: Optional[float] = None
    verified: bool = False
    summary: Optional[str] = None


class Service(BaseModel):
    port: Optional[int] = None
    transport: str = "tcp"
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: list[str] = Field(default_factory=list)
    module: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    ssl_versions: list[str] = Field(default_factory=list)
    data_preview: Optional[str] = None
    vulns: list[Vuln] = Field(default_factory=list)


class HostReport(BaseModel):
    ip: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    org: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    os: Optional[str] = None
    last_update: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    vulns: list[Vuln] = Field(default_factory=list)

    @classmethod
    def from_shodan(cls, data: dict) -> "HostReport":
        services: list[Service] = []
        agg: dict[str, Vuln] = {}
        for item in data.get("data", []) or []:
            svc_vulns: list[Vuln] = []
            for cve, meta in (item.get("vulns", {}) or {}).items():
                is_dict = isinstance(meta, dict)
                v = Vuln(
                    cve=cve,
                    cvss=_to_float(meta.get("cvss")) if is_dict else None,
                    verified=bool(meta.get("verified")) if is_dict else False,
                    summary=(meta.get("summary") if is_dict else None),
                )
                svc_vulns.append(v)
                # keep the richer copy if we already saw the CVE
                if cve not in agg or (v.cvss is not None and agg[cve].cvss is None):
                    agg[cve] = v
            ssl = item.get("ssl", {}) or {}
            services.append(
                Service(
                    port=item.get("port"),
                    transport=item.get("transport", "tcp"),
                    product=item.get("product"),
                    version=item.get("version"),
                    cpe=item.get("cpe23") or item.get("cpe") or [],
                    module=(item.get("_shodan", {}) or {}).get("module"),
                    hostnames=item.get("hostnames", []) or [],
                    ssl_versions=ssl.get("versions", []) or [],
                    data_preview=_preview(item.get("data")),
                    vulns=svc_vulns,
                )
            )
        return cls(
            ip=data.get("ip_str"),
            hostnames=data.get("hostnames", []) or [],
            org=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            country=data.get("country_name"),
            city=data.get("city"),
            os=data.get("os"),
            last_update=data.get("last_update"),
            tags=data.get("tags", []) or [],
            ports=sorted(data.get("ports", []) or []),
            services=sorted(services, key=lambda s: s.port or 0),
            vulns=sorted(agg.values(), key=lambda v: (-(v.cvss or 0.0), v.cve)),
        )


class SearchMatch(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    transport: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    org: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    timestamp: Optional[str] = None
    data_preview: Optional[str] = None

    @classmethod
    def from_match(cls, m: dict) -> "SearchMatch":
        loc = m.get("location", {}) or {}
        return cls(
            ip=m.get("ip_str"),
            port=m.get("port"),
            transport=m.get("transport"),
            hostnames=m.get("hostnames", []) or [],
            org=m.get("org"),
            product=m.get("product"),
            version=m.get("version"),
            country=loc.get("country_name") or m.get("country_name"),
            asn=m.get("asn"),
            timestamp=m.get("timestamp"),
            data_preview=_preview(m.get("data")),
        )


class FacetItem(BaseModel):
    value: str
    count: int


class SearchResult(BaseModel):
    query: str
    total: int = 0
    matches: list[SearchMatch] = Field(default_factory=list)
    facets: dict[str, list[FacetItem]] = Field(default_factory=dict)


class PlanInfo(BaseModel):
    plan: Optional[str] = None
    query_credits: Optional[int] = None
    scan_credits: Optional[int] = None
    monitored_ips: Optional[int] = None
    unlocked: Optional[bool] = None
    https: Optional[bool] = None
    telnet: Optional[bool] = None
