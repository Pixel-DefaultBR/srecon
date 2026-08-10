"""Ponte com o Metasploit — busca OFFLINE no cache de metadata dos módulos.

O msfconsole leva dezenas de segundos para bootar; em vez disso lemos o cache
JSON que o próprio MSF mantém (~/.msf4/store/modules_metadata.json, ~7k módulos)
e indexamos CVE -> módulos + busca por palavra-chave (produto). Tudo local, sem
tocar em rede nem no alvo. Funções puras/testáveis; o I/O de arquivo fica isolado.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_METADATA = Path.home() / ".msf4" / "store" / "modules_metadata.json"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)

# Rank numérico do MSF -> rótulo humano (msf/core/module/rank.rb).
RANK_LABELS = {0: "manual", 100: "low", 200: "average", 300: "normal",
               400: "good", 500: "great", 600: "excellent"}
RANK_FROM_LABEL = {v: k for k, v in RANK_LABELS.items()}


class MsfError(Exception):
    pass


def metadata_path() -> Path:
    env = os.environ.get("SRECON_MSF_METADATA")
    return Path(env) if env else DEFAULT_METADATA


def normalize_cve(s: str) -> Optional[str]:
    """'cve-2021-44228' / 'CVE-2021-44228' -> 'CVE-2021-44228'; senão None."""
    s = (s or "").strip().upper()
    return s if _CVE_RE.match(s) else None


def cves_from_refs(refs) -> list[str]:
    out: list[str] = []
    for r in refs or []:
        c = normalize_cve(str(r))
        if c and c not in out:
            out.append(c)
    return out


@dataclass
class MsfModule:
    fullname: str
    name: str
    mtype: str
    rank: int = 0
    disclosure_date: Optional[str] = None
    cves: list = field(default_factory=list)
    platform: Optional[str] = None

    @property
    def rank_label(self) -> str:
        return RANK_LABELS.get(self.rank, str(self.rank))


def _module_from_meta(m: dict) -> MsfModule:
    return MsfModule(
        fullname=m.get("fullname") or m.get("ref_name") or "?",
        name=m.get("name") or "",
        mtype=m.get("type") or "",
        rank=int(m.get("rank") or 0),
        disclosure_date=(m.get("disclosure_date") or None),
        cves=cves_from_refs(m.get("references")),
        platform=m.get("platform") or None,
    )


class MsfIndex:
    """Índice em memória sobre o metadata do MSF."""

    def __init__(self, data: dict):
        self.modules: list[MsfModule] = []
        self._by_cve: dict[str, list[MsfModule]] = {}
        for _, m in (data or {}).items():
            if not isinstance(m, dict):
                continue
            mod = _module_from_meta(m)
            self.modules.append(mod)
            for c in mod.cves:
                self._by_cve.setdefault(c, []).append(mod)

    def __len__(self) -> int:
        return len(self.modules)

    @staticmethod
    def _sort(mods: list[MsfModule]) -> list[MsfModule]:
        # rank desc, depois nome estável
        return sorted(mods, key=lambda m: (-m.rank, m.fullname))

    def by_cve(self, cve: str) -> list[MsfModule]:
        c = normalize_cve(cve)
        return self._sort(list(self._by_cve.get(c, []))) if c else []

    def by_keyword(self, text: str, types=("exploit", "auxiliary"),
                   min_rank: int = 0) -> list[MsfModule]:
        """Todos os tokens precisam aparecer em fullname+name (case-insensitive)."""
        toks = [t for t in re.split(r"[\s/]+", (text or "").strip().lower()) if t]
        if not toks:
            return []
        hits: list[MsfModule] = []
        for m in self.modules:
            if types and m.mtype not in types:
                continue
            if m.rank < min_rank:
                continue
            hay = (m.fullname + " " + m.name).lower()
            if all(t in hay for t in toks):
                hits.append(m)
        return self._sort(hits)


def load_index(path: Optional[Path] = None) -> MsfIndex:
    p = path or metadata_path()
    if not p.is_file():
        raise MsfError(
            f"cache de metadata do MSF não encontrado em {p}.\n"
            "  - gere-o rodando uma vez:  msfconsole -q -x exit\n"
            "  - ou aponte:  export SRECON_MSF_METADATA=/caminho/modules_metadata.json"
        )
    try:
        data = json.loads(p.read_text(errors="ignore"))
    except (OSError, ValueError) as e:
        raise MsfError(f"falha ao ler o metadata do MSF ({p}): {e}") from e
    if not isinstance(data, dict):
        raise MsfError(f"formato inesperado no metadata do MSF ({p}).")
    return MsfIndex(data)


# ------------------------- geração de resource script ----------------------- #

# RHOSTS entra num .rc lido pelo msfconsole: um '\n' (ou ';') no valor injetaria
# comandos arbitrários no console. Só permitimos tokens de host/IP/CIDR/range e
# separadores seguros; qualquer outra coisa é recusada (falha alto, não silencia).
_RHOSTS_SAFE_RE = re.compile(r"^[A-Za-z0-9 ._:/-]+$")


def sanitize_rhosts(rhosts: str) -> str:
    """Valida RHOSTS p/ o resource script. Aceita hosts/IPs/CIDRs separados por
    espaço/vírgula; rejeita newline e metacaracteres de comando do msfconsole."""
    val = (rhosts or "").strip()
    if not val or "\n" in val or "\r" in val or not _RHOSTS_SAFE_RE.match(val):
        raise ValueError(f"RHOSTS inválido/perigoso para resource script: {rhosts!r}")
    return val


def _rc_use_block(fullname: str, rhosts: str, rport: Optional[int]) -> list[str]:
    lines = [f"use {fullname}", f"setg RHOSTS {rhosts}"]
    if rport:
        lines.append(f"set RPORT {rport}")
    lines.append("info")            # apenas inspeção — NUNCA 'run'/'exploit'
    lines.append("")
    return lines


def build_resource_script(rhosts: str, modules: list[str],
                          rport: Optional[int] = None) -> str:
    """Gera um .rc de TRIAGEM: carrega os módulos com RHOSTS/RPORT e dá 'info'.
    Deliberadamente NÃO inclui 'run'/'exploit' — disparar é ação manual do operador."""
    rhosts = sanitize_rhosts(rhosts)   # barra injeção de comando via newline no .rc
    header = [
        "# srecon -> metasploit resource script (TRIAGEM)",
        "# Revise cada modulo. NAO ha 'run'/'exploit' aqui: rodar e decisao sua.",
        f"# alvo (RHOSTS): {rhosts}",
        "",
    ]
    body: list[str] = []
    for fn in modules:
        body += _rc_use_block(fn, rhosts, rport)
    return "\n".join(header + body).rstrip() + "\n"
