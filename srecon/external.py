from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Mapa de nomes da casa (Kali renomeia algumas ferramentas ProjectDiscovery).
# Ver /root/audits/README.md.
BINARIES = {
    "httpx": "httpx-toolkit",
    "nuclei": "nuclei",
    "testssl": "testssl",
    "dnsx": "dnsx",
    "subfinder": "subfinder",
    "katana": "katana",
}

# Ferramentas Go vivem em ~/go/bin, que pode não estar no PATH herdado pelo
# venv do pipx. Procuramos aqui como fallback (ver README da casa).
_EXTRA_BIN_DIRS = [
    Path.home() / "go" / "bin",
    Path("/root/go/bin"),
    Path("/usr/local/bin"),
]


# Aliases canônicos por nome lógico: 1º o nome renomeado do Kali, depois o nome
# padrão (go install / git). Assim a tool acha o binário tanto no Kali quanto num
# host onde as ferramentas vieram de `go install` (httpx) ou do repo (testssl.sh).
_ALIASES = {
    "httpx": ["httpx-toolkit", "httpx"],
    "testssl": ["testssl", "testssl.sh"],
}


def _candidates(name: str) -> list:
    cands = list(_ALIASES.get(name, [BINARIES.get(name, name)]))
    if name not in cands:
        cands.append(name)
    seen: set = set()
    out: list = []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def resolve_bin(name: str) -> Optional[str]:
    for real in _candidates(name):
        found = shutil.which(real)
        if found:
            return found
        for d in _EXTRA_BIN_DIRS:
            cand = d / real
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    return None


@dataclass
class StageResult:
    name: str
    cmd: list = field(default_factory=list)
    ran: bool = False
    returncode: Optional[int] = None
    output_file: Optional[Path] = None
    stdout_tail: str = ""
    note: str = ""

    @property
    def cmd_str(self) -> str:
        return " ".join(str(c) for c in self.cmd)


def run_stage(
    name: str,
    cmd: list,
    capture_to: Optional[Path],
    timeout: int,
    dry_run: bool,
) -> StageResult:
    """Executa um estágio. `capture_to` grava o stdout (para ferramentas que
    escrevem em stdout); ferramentas com -o próprio devem passar capture_to=None."""
    if not cmd or cmd[0] is None:
        return StageResult(name=name, cmd=[c for c in cmd if c], note="binário ausente")
    if dry_run:
        return StageResult(name=name, cmd=cmd, ran=False, output_file=capture_to, note="dry-run")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return StageResult(name=name, cmd=cmd, ran=True, returncode=124, note=f"timeout {timeout}s")
    except FileNotFoundError:
        return StageResult(name=name, cmd=cmd, note="binário ausente")
    if capture_to is not None and proc.stdout:
        capture_to.write_text(proc.stdout, encoding="utf-8")
    tail = "\n".join((proc.stdout or "").splitlines()[-12:])
    return StageResult(
        name=name, cmd=cmd, ran=True, returncode=proc.returncode,
        output_file=capture_to, stdout_tail=tail,
    )


def parse_httpx_urls(jsonl_file: Path) -> list[str]:
    """Extrai URLs vivas do JSONL do httpx-toolkit."""
    urls: list[str] = []
    if not jsonl_file.is_file():
        return urls
    for line in jsonl_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        u = obj.get("url") or obj.get("input")
        if u:
            urls.append(u)
    return urls


def https_targets_from_httpx(jsonl_file: Path) -> list[str]:
    return [u for u in parse_httpx_urls(jsonl_file) if u.startswith("https://")]


def parse_httpx_records(jsonl_file: Path) -> list:
    """Records ricos do httpx-toolkit (-json -td): url/status/title/webserver/tech/ips/cdn.
    O httpx já coleta `tech` (fingerprint estilo Wappalyzer) — antes só extraíamos a URL."""
    recs: list = []
    if not jsonl_file.is_file():
        return recs
    for line in jsonl_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        recs.append({
            "url": o.get("url") or o.get("input"),
            "status": o.get("status_code"),
            "title": o.get("title"),
            "webserver": o.get("webserver"),
            "tech": list(o.get("tech") or []),
            "content_length": o.get("content_length"),
            "ips": list(o.get("a") or []),
            "cdn": o.get("cdn_name"),
        })
    return recs


def tech_summary(records: list) -> list:
    """Agrega a contagem de cada tecnologia vista nos records do httpx, desc."""
    counts: dict = {}
    for r in records:
        for t in (r.get("tech") or []):
            counts[t] = counts.get(t, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
