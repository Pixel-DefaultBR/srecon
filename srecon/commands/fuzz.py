from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .. import content, enrich
from ..external import parse_httpx_records, resolve_bin, tech_summary

# rc sintéticos
RC_NO_FFUF = 127
RC_NO_WORDLIST = 126


@dataclass
class FuzzResult:
    target: str
    base_url: str
    mode: str = "dirs"
    wordlist: Optional[str] = None
    hits: list = field(default_factory=list)   # dicts: url,status,length,title,tech,webserver,interesting
    tech: list = field(default_factory=list)   # [(tech, count)]
    ffuf_rc: Optional[int] = None
    probed: bool = False
    wildcard: Optional[dict] = None            # cluster WAF/wildcard descartado, se houve

    @property
    def interesting(self) -> list:
        return [h for h in self.hits if h.get("interesting")]


def base_url(target: str) -> str:
    return target if "://" in target else "http://" + target


def _run(cmd: list, timeout: int) -> int:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return 124
    except FileNotFoundError:
        return RC_NO_FFUF


def run(target: str, run_dir: Path, *, files_mode: bool = False,
        wordlist: Optional[str] = None, extensions: str = "",
        match_codes: str = "200,204,301,302,307,401,403,405,500",
        threads: int = 40, rate: int = 0, timeout_req: int = 10,
        ffuf_timeout: int = 900, probe: bool = True) -> FuzzResult:
    run_dir.mkdir(parents=True, exist_ok=True)
    burl = base_url(target)
    res = FuzzResult(target=target, base_url=burl, mode=("files" if files_mode else "dirs"))

    ffuf = resolve_bin("ffuf")
    if not ffuf:
        res.ffuf_rc = RC_NO_FFUF
        return res

    if files_mode:
        wl = str(content.write_wordlist(content.INTERESTING_FILES, run_dir / "wordlist-files.txt"))
    else:
        wl = wordlist or content.default_wordlist()
    if not wl:
        res.ffuf_rc = RC_NO_WORDLIST
        return res
    res.wordlist = wl

    out_json = run_dir / "ffuf.json"
    cmd = content.build_ffuf_cmd(ffuf, burl, wl, out_json, match_codes=match_codes,
                                 extensions=extensions, threads=threads, rate=rate,
                                 timeout_req=timeout_req)
    res.ffuf_rc = _run(cmd, ffuf_timeout)
    hits = content.parse_ffuf_json(out_json)
    # WAF/wildcard: se ~tudo devolve o mesmo (status,length), descarta o cluster
    # (senão o httpx re-probaria milhares de falsos-positivos — ex.: 403 da Cloudflare).
    hits, res.wildcard = content.drop_wildcard(hits)

    # re-probe os achados com httpx: confirma vivo + puxa tech/title/webserver.
    # (todas as URLs são same-origin do alvo autorizado — não há escape de escopo.)
    recs_by_url: dict = {}
    if probe and hits:
        httpx = resolve_bin("httpx")
        if httpx:
            urls_file = run_dir / "hits-urls.txt"
            urls_file.write_text(
                "\n".join(h["url"] for h in hits if h.get("url")) + "\n", encoding="utf-8")
            rec_out = run_dir / "hits-httpx.jsonl"
            hcmd = [httpx, "-l", str(urls_file), "-silent", "-json", "-td", "-sc",
                    "-title", "-server", "-o", str(rec_out)]
            _run(hcmd, ffuf_timeout)
            recs = parse_httpx_records(rec_out)
            recs_by_url = {r["url"]: r for r in recs}
            res.probed = True
            res.tech = tech_summary(recs)

    for h in hits:
        rec = recs_by_url.get(h.get("url"), {})
        h["title"] = rec.get("title")
        h["tech"] = rec.get("tech") or []
        h["webserver"] = rec.get("webserver")
        # classifica pela URL COMPLETA (com '/'), não pela palavra crua do wordlist —
        # senão '.git/HEAD' (sem barra) não casa _INTERESTING_PATH e o achado se perde.
        h["interesting"] = enrich.is_interesting(h.get("url") or h.get("input") or "")
    res.hits = hits
    return res


def write_artifacts(res: FuzzResult, run_dir: Path) -> None:
    def _w(name, lines):
        (run_dir / name).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    _w("found.txt", [f'{h.get("status")}\t{h.get("length")}\t{h.get("url")}' for h in res.hits])
    _w("interesting.txt", [h.get("url") for h in res.interesting if h.get("url")])
    _w("tech.txt", [f"{t}\t{c}" for t, c in res.tech])
