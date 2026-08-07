from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import subs as subs_cmd
from .. import scope as scopemod
from ..external import (
    StageResult,
    https_targets_from_httpx,
    parse_httpx_urls,
    resolve_bin,
    run_stage,
)
from ..shodan_client import ShodanClient

VALID_STAGES = ("httpx", "nuclei", "testssl")

# Token de host aceitável: letras/dígitos, ponto, hífen, underscore, dois-pontos (IPv6),
# colchetes ([ipv6]). Qualquer whitespace ou caractere estranho é rejeitado — isso impede
# que um hostname malformado do Shodan (ex.: 'evil.com\ncortex.escopo') vire alvo de scan.
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]+$")


@dataclass
class ScopeDecision:
    in_scope: list = field(default_factory=list)
    out_scope: list = field(default_factory=list)
    source: Optional[str] = None            # compat: primeira fonte
    sources: set = field(default_factory=set)
    override: bool = False


def _clean_host(h) -> Optional[str]:
    h = (h or "").strip()
    if not h or len(h) > 253 or not HOST_RE.match(h):
        return None
    return h


def gather_targets(
    client: ShodanClient,
    target: Optional[str],
    from_host: Optional[str],
    from_search: Optional[str],
    search_limit: int,
    from_subs: Optional[str] = None,
    from_file: Optional[Path] = None,
    sub_timeout: int = 300,
    dns_timeout: int = 120,
) -> list:
    raw: list = []
    if target:
        raw.append(target)
    if from_host:
        rep = client.host(from_host)
        if rep.ip:
            raw.append(rep.ip)
        raw.extend(rep.hostnames)
    if from_search:
        res = client.search(from_search, limit=search_limit)
        raw.extend(m.ip for m in res.matches if m.ip)
    if from_subs:
        # subfinder -> dnsx: os hostnames vivos casam com scope wildcard '*.dominio'
        found, _ = subs_cmd.enumerate_subdomains(from_subs, timeout=sub_timeout)
        hosts = sorted(set(found) | {from_subs.strip().lower()})
        resolved, _ = subs_cmd.resolve_hosts(hosts, timeout=dns_timeout)
        raw.extend(h for h, _ in resolved) if resolved else raw.extend(hosts)
    if from_file:
        try:
            for line in Path(from_file).read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    raw.append(line)
        except OSError as e:
            raise ValueError(f"não consegui ler --from-file {from_file}: {e}") from e

    seen: set = set()
    ordered: list = []
    for h in raw:
        clean = _clean_host(h)          # descarta hosts malformados (defesa do gate)
        if clean and clean not in seen:
            seen.add(clean)
            ordered.append(clean)
    return ordered


def decide_scope(
    hosts: list,
    scope_directory: Path,
    scope_file: Optional[Path],
    override: bool,
) -> ScopeDecision:
    if scope_file:
        entries = [scopemod.load_scope_file(scope_file)]
    else:
        entries = scopemod.load_scopes(scope_directory)

    decision = ScopeDecision(override=override)
    for h in hosts:
        hit = scopemod.match(h, entries)
        if hit:
            decision.in_scope.append(h)
            decision.sources.add(str(hit.source))
            if decision.source is None:
                decision.source = str(hit.source)
        elif override:
            decision.in_scope.append(h)
        else:
            decision.out_scope.append(h)
    if override and not decision.sources:
        decision.source = "OVERRIDE (--i-am-authorized)"
        decision.sources.add(decision.source)
    return decision


def run_stages(
    hosts: list,
    outdir: Path,
    stages: list,
    severity: str,
    timeout: int,
    dry_run: bool,
) -> list:
    results: list[StageResult] = []
    hosts_file = outdir / "hosts.txt"
    if not dry_run:
        hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    httpx_out = outdir / "httpx.jsonl"
    live_urls_file = outdir / "live_urls.txt"

    if "httpx" in stages:
        httpx = resolve_bin("httpx")  # -> httpx-toolkit
        cmd = [httpx, "-list", str(hosts_file), "-silent", "-td", "-sc",
               "-title", "-json", "-o", str(httpx_out)]
        results.append(run_stage("httpx-toolkit", cmd, None, timeout, dry_run))
        if not dry_run:
            live = parse_httpx_urls(httpx_out)
            if live:
                live_urls_file.write_text("\n".join(live) + "\n", encoding="utf-8")

    if "nuclei" in stages:
        nuclei = resolve_bin("nuclei")
        target_list = live_urls_file if live_urls_file.is_file() else hosts_file
        nuclei_out = outdir / "nuclei.jsonl"
        cmd = [nuclei, "-list", str(target_list), "-severity", severity,
               "-jsonl", "-o", str(nuclei_out), "-silent"]
        results.append(run_stage("nuclei", cmd, None, timeout, dry_run))

    if "testssl" in stages:
        testssl = resolve_bin("testssl")
        if httpx_out.is_file():
            https = https_targets_from_httpx(httpx_out)
        else:
            https = [f"https://{h}" for h in hosts]
        if not https:
            https = [f"https://{h}" for h in hosts]
        for i, tgt in enumerate(https):
            jf = outdir / f"testssl_{i}.json"
            cmd = [testssl, "--quiet", "--color", "0", "--jsonfile-pretty", str(jf), tgt]
            results.append(run_stage(f"testssl:{tgt}", cmd, None, timeout, dry_run))

    return results
