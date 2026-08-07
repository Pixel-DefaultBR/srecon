from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# domínio com pelo menos um ponto e TLD alfabético; prefixo curinga opcional
DOMAIN_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)
CIDR_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass
class ScopeEntry:
    source: Path
    domains: set = field(default_factory=set)   # domínios base; '*.x' guardado como 'x'
    cidrs: list = field(default_factory=list)   # ipaddress networks (v4 e v6)
    ips: set = field(default_factory=set)       # endereços normalizados (str(ip_address))

    def is_empty(self) -> bool:
        return not (self.domains or self.cidrs or self.ips)


# Marcadores de negação/exclusão: uma linha com qualquer um deles NÃO autoriza nada.
# (Bug histórico: findall no blob inteiro autorizava domínios citados em notas de
# "fora de escopo" — o gate alimenta scans ATIVOS, então isso era grave.)
NEGATION_RE = re.compile(
    r"fora\s+de\s+escopo|exclu[ií]|n[ãa]o\s+tocar|out[\s-]?of[\s-]?scope|"
    r"\bexclude\b|\bexcluded\b|\bdeny\b|\bblock(?:ed|list)?\b|\bNOT\b",
    re.IGNORECASE,
)


def _absorb_line(line: str, entry: ScopeEntry) -> None:
    # IPv4 CIDRs primeiro, depois IPv4 avulsos
    for m in CIDR_RE.findall(line):
        try:
            entry.cidrs.append(ipaddress.ip_network(m, strict=False))
        except ValueError:
            pass
    line_wo_cidr = CIDR_RE.sub(" ", line)
    for m in IP_RE.findall(line_wo_cidr):
        try:
            entry.ips.add(str(ipaddress.ip_address(m)))
        except ValueError:
            pass

    # IPv6 (endereços e CIDRs): varre tokens com >=2 ':'
    for tok in re.split(r"[\s,;]+", line):
        host = tok.strip().strip("[]")
        if host.count(":") < 2:
            continue
        if "/" in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
                if net.version == 6:
                    entry.cidrs.append(net)
            except ValueError:
                pass
        else:
            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 6:
                    entry.ips.add(str(ip))
            except ValueError:
                pass

    for m in DOMAIN_RE.findall(line):
        d = m.lower()
        if d.startswith("*."):
            d = d[2:]
        entry.domains.add(d)


def parse_scope_text(text: str, source: Path) -> ScopeEntry:
    """Autoriza SÓ o que está em linhas de allow. Linhas de comentário (#, //) ou
    com marcador de negação são ignoradas por completo — nada nelas autoriza."""
    entry = ScopeEntry(source=source)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if NEGATION_RE.search(line):
            continue
        _absorb_line(line, entry)
    return entry


def load_scopes(scope_directory: Path) -> list[ScopeEntry]:
    entries: list[ScopeEntry] = []
    if not scope_directory.is_dir():
        return entries
    for f in sorted(scope_directory.glob("*.txt")):
        try:
            entries.append(parse_scope_text(f.read_text(errors="ignore"), f))
        except OSError:
            continue
    return entries


def load_scope_file(path: Path) -> ScopeEntry:
    if not path.is_file():
        raise ValueError(f"arquivo de escopo não encontrado: {path}")
    try:
        text = path.read_text(errors="ignore")
    except OSError as e:
        raise ValueError(f"não consegui ler o escopo {path}: {e}") from e
    return parse_scope_text(text, path)


def _domain_matches(target: str, scope_domain: str) -> bool:
    target = target.lower().rstrip(".")
    return target == scope_domain or target.endswith("." + scope_domain)


def _normalize_host(target: str) -> str:
    """Extrai host de URL/host:port, ciente de IPv6 ([::1], [::1]:443)."""
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0]        # tira path
    target = target.split("?", 1)[0].split("#", 1)[0]  # tira query/fragment sem '/'
    target = target.rsplit("@", 1)[-1]      # tira userinfo
    if target.startswith("["):              # [ipv6] ou [ipv6]:port
        end = target.find("]")
        return target[1:end] if end != -1 else target.strip("[]")
    if target.count(":") == 1:              # host:port (IPv4/domínio)
        return target.split(":", 1)[0]
    return target                           # bare IPv6 (múltiplos ':') ou host puro


def match(target: str, entries: list[ScopeEntry]) -> Optional[ScopeEntry]:
    """Retorna a ScopeEntry que autoriza `target`, ou None."""
    target = (target or "").strip()
    if not target:
        return None
    # Host com whitespace OU vírgula embutida é malformado/perigoso (a vírgula vira
    # múltiplos seeds no katana/httpx): jamais autoriza.
    if re.search(r"[\s,]", target):
        return None

    host = _normalize_host(target)
    if not host:
        return None

    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    for e in entries:
        if ip_obj is not None:
            if str(ip_obj) in e.ips:
                return e
            if any(ip_obj in net for net in e.cidrs):
                return e
        else:
            if any(_domain_matches(host, d) for d in e.domains):
                return e
    return None
