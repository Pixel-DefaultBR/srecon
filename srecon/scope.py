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
    # DENY: hosts EXPLICITAMENTE fora de escopo. Avaliados globalmente ANTES dos allows
    # (ver match): um allow wildcard/CIDR NÃO pode re-autorizar o que caiu aqui.
    deny_domains: set = field(default_factory=set)
    deny_cidrs: list = field(default_factory=list)
    deny_ips: set = field(default_factory=set)

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


def _absorb_line(line: str, domains: set, cidrs: list, ips: set) -> None:
    """Extrai domínios/IPs/CIDRs da linha para as coleções passadas (allow OU deny)."""
    # IPv4 CIDRs primeiro, depois IPv4 avulsos
    for m in CIDR_RE.findall(line):
        try:
            cidrs.append(ipaddress.ip_network(m, strict=False))
        except ValueError:
            pass
    line_wo_cidr = CIDR_RE.sub(" ", line)
    for m in IP_RE.findall(line_wo_cidr):
        try:
            ips.add(str(ipaddress.ip_address(m)))
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
                    cidrs.append(net)
            except ValueError:
                pass
        else:
            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 6:
                    ips.add(str(ip))
            except ValueError:
                pass

    for m in DOMAIN_RE.findall(line):
        d = m.lower()
        if d.startswith("*."):
            d = d[2:]
        domains.add(d)


def parse_scope_text(text: str, source: Path) -> ScopeEntry:
    """Separa ALLOW de DENY. Uma linha de allow autoriza; uma linha com marcador de
    negação (ou dentro de uma seção de exclusão) alimenta o DENY — que em match()
    prevalece sobre qualquer allow. Cabeçalhos de comentário (#, //) não absorvem
    hosts do próprio texto, mas um cabeçalho com marcador de negação ('# Out of
    scope:') ABRE uma seção de exclusão que dura até a próxima linha em branco."""
    entry = ScopeEntry(source=source)
    deny_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            deny_section = False                     # linha em branco fecha a seção
            continue
        has_neg = bool(NEGATION_RE.search(line))
        if line.startswith("#") or line.startswith("//"):
            # cabeçalho/nota: liga/desliga a seção de exclusão conforme o marcador,
            # mas o texto do comentário em si nunca autoriza NEM nega um host solto.
            deny_section = has_neg
            continue
        if has_neg or deny_section:
            _absorb_line(line, entry.deny_domains, entry.deny_cidrs, entry.deny_ips)
        else:
            _absorb_line(line, entry.domains, entry.cidrs, entry.ips)
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


def _host_in(host: str, ip_obj, domains: set, cidrs: list, ips: set) -> bool:
    """host casa alguma das coleções (usado tanto p/ allow quanto p/ deny)."""
    if ip_obj is not None:
        return str(ip_obj) in ips or any(ip_obj in net for net in cidrs)
    return any(_domain_matches(host, d) for d in domains)


def _prepare_host(target: str):
    """(host, ip_obj) normalizado, ou (None, None) se malformado/vazio.
    Host com whitespace OU vírgula é perigoso (vira múltiplos seeds): rejeita."""
    target = (target or "").strip()
    if not target or re.search(r"[\s,]", target):
        return None, None
    host = _normalize_host(target)
    if not host:
        return None, None
    try:
        return host, ipaddress.ip_address(host)
    except ValueError:
        return host, None


def is_denied(target: str, entries: list[ScopeEntry]) -> bool:
    """True se `target` casa uma regra de EXCLUSÃO em qualquer entry. Deny é
    autoritativo: um host negado nunca é autorizado, mesmo sob allow wildcard/CIDR."""
    host, ip_obj = _prepare_host(target)
    if host is None:
        return False
    return any(
        _host_in(host, ip_obj, e.deny_domains, e.deny_cidrs, e.deny_ips) for e in entries
    )


def match(target: str, entries: list[ScopeEntry]) -> Optional[ScopeEntry]:
    """Retorna a ScopeEntry que autoriza `target`, ou None. DENY prevalece: se o host
    casa qualquer regra de exclusão (em qualquer arquivo), retorna None mesmo que um
    allow wildcard/CIDR o cubra."""
    host, ip_obj = _prepare_host(target)
    if host is None:
        return None

    # 1) DENY global primeiro — autoritativo sobre todos os allows.
    for e in entries:
        if _host_in(host, ip_obj, e.deny_domains, e.deny_cidrs, e.deny_ips):
            return None

    # 2) allow: primeira entry que cobre o host.
    for e in entries:
        if _host_in(host, ip_obj, e.domains, e.cidrs, e.ips):
            return e
    return None
