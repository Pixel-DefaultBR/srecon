from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .. import scope as scopemod
from ..external import resolve_bin

# host DNS-plausível (defesa: nada de espaço/vírgula que vire múltiplos alvos depois)
import re as _re
_HOST_RE = _re.compile(r"^[A-Za-z0-9._-]{1,253}$")


@dataclass
class SubsResult:
    domain: str
    subdomains: list = field(default_factory=list)      # todos (subfinder + o próprio)
    resolved: list = field(default_factory=list)        # (host, [ips]) — só os que resolvem
    in_scope: list = field(default_factory=list)
    out_scope: list = field(default_factory=list)
    subfinder_rc: Optional[int] = None
    dnsx_rc: Optional[int] = None

    @property
    def live_hosts(self) -> list:
        return [h for h, _ in self.resolved]


def _run(cmd: list, timeout: int, input_text: Optional[str] = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=input_text)
    except subprocess.TimeoutExpired:
        return 124, ""
    except FileNotFoundError:
        return 127, ""
    return proc.returncode, proc.stdout or ""


def _clean(h: str) -> Optional[str]:
    h = (h or "").strip().lower().rstrip(".")
    return h if h and _HOST_RE.match(h) else None


def enumerate_subdomains(domain: str, all_sources: bool = True,
                         timeout: int = 300, extra: Optional[list] = None) -> tuple[list, int]:
    sub = resolve_bin("subfinder")
    if not sub:
        return [], 127
    cmd = [sub, "-d", domain, "-silent"]
    if all_sources:
        cmd.append("-all")
    if extra:
        cmd += extra
    rc, out = _run(cmd, timeout)
    subs = {c for line in out.splitlines() if (c := _clean(line))}
    return sorted(subs), rc


def resolve_hosts(hosts: list, timeout: int = 120) -> tuple[list, int]:
    dnsx = resolve_bin("dnsx")
    if not dnsx:
        return [], 127
    if not hosts:
        return [], 0
    cmd = [dnsx, "-silent", "-a", "-json"]
    rc, out = _run(cmd, timeout, input_text="\n".join(hosts) + "\n")
    resolved: list = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        host = _clean(obj.get("host") or "")
        ips = [str(x) for x in (obj.get("a") or []) if x]
        if host:
            resolved.append((host, sorted(set(ips))))
    resolved.sort()
    return resolved, rc


def run(domain: str, scope_entries: list, all_sources: bool = True,
        do_resolve: bool = True, sub_timeout: int = 300,
        dns_timeout: int = 120) -> SubsResult:
    dom = _clean(domain)
    if not dom:
        raise ValueError(f"domínio inválido: {domain!r}")
    subs, sub_rc = enumerate_subdomains(dom, all_sources, sub_timeout)
    allhosts = sorted(set(subs) | {dom})
    res = SubsResult(domain=dom, subdomains=allhosts, subfinder_rc=sub_rc)

    if do_resolve:
        resolved, dns_rc = resolve_hosts(allhosts, dns_timeout)
        res.resolved = resolved
        res.dnsx_rc = dns_rc
        hosts_for_scope = res.live_hosts or allhosts
    else:
        hosts_for_scope = allhosts

    for h in hosts_for_scope:
        if scopemod.match(h, scope_entries):
            res.in_scope.append(h)
        else:
            res.out_scope.append(h)
    return res
