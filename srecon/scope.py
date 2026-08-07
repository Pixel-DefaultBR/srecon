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
    cidrs: list = field(default_factory=list)   # ipaddress networks
    ips: set = field(default_factory=set)

    def is_empty(self) -> bool:
        return not (self.domains or self.cidrs or self.ips)


def parse_scope_text(text: str, source: Path) -> ScopeEntry:
    entry = ScopeEntry(source=source)
    for m in CIDR_RE.findall(text):
        try:
            entry.cidrs.append(ipaddress.ip_network(m, strict=False))
        except ValueError:
            pass
    text_wo_cidr = CIDR_RE.sub(" ", text)
    for m in IP_RE.findall(text_wo_cidr):
        try:
            ipaddress.ip_address(m)
            entry.ips.add(m)
        except ValueError:
            pass
    for m in DOMAIN_RE.findall(text):
        d = m.lower()
        if d.startswith("*."):
            d = d[2:]
        entry.domains.add(d)
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


def match(target: str, entries: list[ScopeEntry]) -> Optional[ScopeEntry]:
    """Retorna a ScopeEntry que autoriza `target`, ou None."""
    target = (target or "").strip()
    if not target:
        return None
    # Host com whitespace embutido (newline/tab/espaço) é malformado/suspeito:
    # jamais autoriza — senão um hostname 'evil\ncortex.escopo' vazaria o gate.
    if re.search(r"\s", target):
        return None
    # normaliza URL -> host
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0].split(":", 1)[0]

    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        ip_obj = None

    for e in entries:
        if ip_obj is not None:
            if target in e.ips:
                return e
            if any(ip_obj in net for net in e.cidrs):
                return e
        else:
            if any(_domain_matches(target, d) for d in e.domains):
                return e
    return None
