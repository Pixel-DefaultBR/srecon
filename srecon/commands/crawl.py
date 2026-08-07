from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .. import enrich
from .. import scope as scopemod
from ..external import StageResult, resolve_bin, run_stage
from ..util import utc_stamp

FIELD_SCOPES = ("rdn", "fqdn", "dn")
MAX_SCAN_BYTES = 3_000_000  # teto p/ varredura de forms/segredos por body inline


# ------------------------------ alvo / seeds -------------------------------- #

def extract_host(target: str) -> str:
    t = target
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    t = t.rsplit("@", 1)[-1]
    if t.startswith("["):                      # [ipv6]:port
        end = t.find("]")
        return t[1:end] if end != -1 else t.strip("[]")
    if t.count(":") == 1:                       # host:port
        return t.split(":", 1)[0]
    return t                                     # bare IPv6 ou host puro


def build_seeds(target: str) -> str:
    if "://" in target:
        return target
    return f"https://{target},http://{target}"


def split_extra(extra: Optional[str]) -> list:
    if not extra:
        return []
    try:
        return shlex.split(extra)
    except ValueError:
        return extra.split()


# --------------------------- redação de segredos ---------------------------- #

def strip_userinfo(url: str) -> str:
    """Remove 'user:pass@' de uma URL/seed, preservando esquema, host e path.
    Cobre também o caso sem esquema ('user@host/x') que sanitize_proxy não pegava."""
    if not url or "@" not in url:
        return url
    scheme = ""
    rest = url
    if "://" in url:
        scheme, rest = url.split("://", 1)
        scheme += "://"
    if "/" in rest:
        authority, tail = rest.split("/", 1)
        tail = "/" + tail
    else:
        authority, tail = rest, ""
    if "@" in authority:                       # userinfo só vive na autoridade
        authority = authority.rsplit("@", 1)[-1]
    return scheme + authority + tail


def sanitize_proxy(p: str) -> str:
    if p and "://" in p and "@" in p:
        scheme, rest = p.split("://", 1)
        return f"{scheme}://{rest.rsplit('@', 1)[-1]}"
    return strip_userinfo(p)                    # proxy sem esquema também é redigido


def redact_args(args: list) -> list:
    """Redige valores de -H (cookies/auth), creds em -proxy e userinfo no seed -u."""
    out: list = []
    mode = None
    for a in args:
        if mode == "H":
            out.append("<redacted>")
            mode = None
            continue
        if mode == "proxy":
            out.append(sanitize_proxy(str(a)))
            mode = None
            continue
        if mode == "u":
            # seed pode ser lista separada por vírgula (https://x,http://x)
            out.append(",".join(strip_userinfo(s) for s in str(a).split(",")))
            mode = None
            continue
        out.append(a)
        if a == "-H":
            mode = "H"
        elif a == "-proxy":
            mode = "proxy"
        elif a == "-u":
            mode = "u"
    return out


# --------------------------------- opções ---------------------------------- #

@dataclass
class CrawlOptions:
    depth: int = 3
    rate: int = 20
    host_rate: int = 10
    concurrency: int = 5
    parallelism: int = 2
    timeout: int = 15
    retry: int = 2
    delay: int = 1
    duration: str = "30m"
    field_scope: str = "rdn"
    js: bool = True
    known_files: bool = True
    headless: bool = False
    headers: list = field(default_factory=list)
    proxy: str = ""
    extra: list = field(default_factory=list)
    store_responses: bool = True


def build_katana_args(katana_bin: str, seeds: str, run_dir: Path, opt: CrawlOptions) -> list:
    args = [
        katana_bin,
        "-u", seeds,
        "-d", str(opt.depth),
        "-fs", opt.field_scope,
        "-e", "cdn,private-ips",
        "-c", str(opt.concurrency),
        "-p", str(opt.parallelism),
        "-rl", str(opt.rate),
        "-hrl", str(opt.host_rate),
        "-rd", str(opt.delay),
        "-ct", str(opt.duration),
        "-timeout", str(opt.timeout),
        "-retry", str(opt.retry),
        "-j",
        "-o", str(run_dir / "output.jsonl"),
        "-ncb", "-duc", "-silent", "-nc",
    ]
    if opt.store_responses:
        args += ["-store-response", "-srd", str(run_dir / "responses")]
    if opt.js:
        args += ["-jc"]
    if opt.known_files:
        args += ["-kf", "all"]
    if opt.headless:
        args += ["-hl", "-nos", "-sc", "-xhr"]
    for h in opt.headers:
        if h:
            args += ["-H", h]
    if opt.proxy:
        args += ["-proxy", opt.proxy]
    if opt.extra:
        args += list(opt.extra)
    return args


# ------------------------------- diretórios --------------------------------- #

def previous_run(parent: Path) -> Optional[Path]:
    latest = parent / "latest"
    if latest.is_symlink():
        try:
            tgt = os.readlink(latest)
            p = Path(tgt) if os.path.isabs(tgt) else (parent / tgt)
            if p.is_dir():
                return p.resolve()
        except OSError:
            pass
    if parent.is_dir():                        # fallback: sibling mais recente
        subs = sorted(d for d in parent.iterdir() if d.is_dir() and d.name != "latest")
        if subs:
            return subs[-1].resolve()
    return None


def update_latest(parent: Path, run_dir: Path) -> None:
    # 'latest' e run_dir compartilham o mesmo parent -> link relativo de 1 componente
    # (resolve certo mesmo com SRECON_WORKSPACE relativo ou reports/ movido).
    latest = parent / "latest"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(run_dir.name)
    except OSError:
        pass


# --------------------------------- katana ----------------------------------- #

def harden_dir(path: Path) -> None:
    """0700 no run dir: protege bodies/segredos world-readable mesmo se um writer
    esquecer o modo restrito (defesa em profundidade além do _write_private)."""
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass


def run_katana(args: list) -> int:
    try:
        return subprocess.run(args).returncode
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError:
        return 127


def _write_private(path: Path, content: str) -> None:
    """Escreve com 0600 (manifesto pode conter info sensível mesmo redigida)."""
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        sys.stderr.write(f"[srecon] aviso: falha ao escrever {path}: {e}\n")


def write_meta(run_dir: Path, target: str, seeds: str, katana_bin: str,
               args: list, opt: CrawlOptions) -> None:
    opts = dict(opt.__dict__)
    if opts.get("headers"):
        opts["headers"] = ["<redacted>"] * len(opts["headers"])
    if opts.get("proxy"):
        opts["proxy"] = sanitize_proxy(str(opts["proxy"]))
    safe_args = redact_args(args)
    safe_target = strip_userinfo(target)
    safe_seeds = ",".join(strip_userinfo(s) for s in seeds.split(","))
    meta = {
        "generated_at_utc": utc_stamp(),
        "target": safe_target,
        "seeds": safe_seeds,
        "run_dir": str(run_dir),
        "katana_bin": katana_bin,
        "options": opts,
        "command": safe_args,
    }
    _write_private(run_dir / "run-meta.json", json.dumps(meta, indent=2, default=str))
    lines = [
        "# katana crawl — manifesto",
        f"generated_at_utc : {meta['generated_at_utc']}",
        f"target           : {safe_target}",
        f"seeds            : {safe_seeds}",
        f"run_dir          : {run_dir}",
        f"katana_bin       : {katana_bin}",
        "",
        "## comando exato (creds redigidas)",
        " ".join(shlex.quote(str(a)) for a in safe_args),
        "",
    ]
    _write_private(run_dir / "run-meta.txt", "\n".join(lines) + "\n")


# ----------------------------- pós-processamento ---------------------------- #

@dataclass
class CrawlArtifacts:
    all_urls: list = field(default_factory=list)
    js: list = field(default_factory=list)
    param_urls: list = field(default_factory=list)
    param_names: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    js_endpoints: list = field(default_factory=list)   # rotas mineradas de bodies/JS
    all_params: list = field(default_factory=list)      # união URL+forms+JS (wordlist p/ fuzz)
    interesting: list = field(default_factory=list)     # URLs sensíveis (backup/VCS/config/…)
    forms: list = field(default_factory=list)     # dicts
    secrets: list = field(default_factory=list)    # (rule, frag, url)
    records: int = 0


def process_jsonl(jsonl_path: Path, scan_secrets: bool) -> CrawlArtifacts:
    """Lê o JSONL do katana em STREAMING (bodies inline podem ser enormes)."""
    urls: set = set()
    js: set = set()
    params: set = set()
    pnames: set = set()
    subs: set = set()
    apis: set = set()
    js_eps: set = set()          # rotas escondidas mineradas de bodies (APIs escondidas)
    all_params: set = set()      # união de todos os nomes de param vistos
    forms: list = []
    secrets: set = set()
    records = 0

    art = CrawlArtifacts()
    if not jsonl_path.is_file():
        return art

    with jsonl_path.open("r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            records += 1
            req = obj.get("request") or {}
            resp = obj.get("response") or {}
            ep = req.get("endpoint")
            if isinstance(ep, str) and ep:
                urls.add(ep)
                if enrich.is_js(ep):
                    js.add(ep)
                if enrich.has_params(ep):
                    params.add(ep)
                    pn = enrich.param_names(ep)
                    pnames.update(pn)
                    all_params.update(pn)
                if enrich.is_api(ep):
                    apis.add(ep)
                h = enrich.url_host(ep)
                if h:
                    subs.add(h)
            else:
                ep = ""
            body = resp.get("body")
            if isinstance(body, str) and body:
                snippet = body if len(body) <= MAX_SCAN_BYTES else body[:MAX_SCAN_BYTES]
                for f in enrich.find_forms(snippet):
                    f = dict(f)
                    f["url"] = ep
                    forms.append(f)
                    all_params.update(f.get("inputs", []))   # params de formulário
                # minera rotas/params embutidos no body (bundles JS, <script> inline)
                for e in enrich.extract_js_endpoints(snippet):
                    js_eps.add(e)
                    if enrich.is_api(e):
                        apis.add(e)
                    hh = enrich.url_host(e)
                    if hh:
                        subs.add(hh)
                all_params.update(enrich.extract_js_params(snippet))
                if scan_secrets:
                    for rule, frag in enrich.scan_secrets(snippet):
                        secrets.add((rule, frag, ep))

    art.all_urls = sorted(urls)
    art.js = sorted(js)
    art.param_urls = sorted(params)
    art.param_names = sorted(pnames)
    art.subdomains = sorted(subs)
    art.api_endpoints = sorted(apis)
    art.js_endpoints = sorted(js_eps)
    art.all_params = sorted(all_params)
    art.interesting = sorted(u for u in urls if enrich.is_interesting(u))
    art.forms = forms
    art.secrets = sorted(secrets)
    art.records = records
    return art


def _write_lines(path: Path, items) -> None:
    try:
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"[srecon] aviso: falha ao escrever {path}: {e}\n")


def write_artifacts(art: CrawlArtifacts, run_dir: Path) -> None:
    _write_lines(run_dir / "all-urls.txt", art.all_urls)
    _write_lines(run_dir / "js.txt", art.js)
    _write_lines(run_dir / "endpoints-with-params.txt", art.param_urls)
    _write_lines(run_dir / "param-names.txt", art.param_names)
    _write_lines(run_dir / "params-all.txt", art.all_params)
    _write_lines(run_dir / "subdomains.txt", art.subdomains)
    _write_lines(run_dir / "api-endpoints.txt", art.api_endpoints)
    _write_lines(run_dir / "js-endpoints.txt", art.js_endpoints)
    _write_lines(run_dir / "interesting.txt", art.interesting)
    form_lines = [
        f'{f.get("method", "GET")} {f.get("action", "")}  '
        f'inputs=[{",".join(f.get("inputs", []))}]  (em {f.get("url", "")})'
        for f in art.forms
    ]
    _write_lines(run_dir / "forms.txt", form_lines)
    # segredos são sensíveis: 0600 (não world-readable como os demais artefatos)
    sec_lines = [f"{rule}\t{frag}\t{url}" for (rule, frag, url) in art.secrets]
    _write_private(run_dir / "secrets.txt", "\n".join(sec_lines) + ("\n" if sec_lines else ""))


# ------------------------- blindagem de escopo (ativo) ---------------------- #

def in_scope_host(host: str, entries: list, target_host: str, override: bool) -> bool:
    """Host autorizado a receber tráfego ATIVO? Casa os scope/*.txt; no modo
    --i-am-authorized, restringe ao próprio alvo e seus subdomínios (conservador)."""
    if not host:
        return False
    if entries and scopemod.match(host, entries):
        return True
    if override:
        th = (target_host or "").lower().rstrip(".")
        return bool(th) and (host == th or host.endswith("." + th))
    return False


def scope_partition(art: "CrawlArtifacts", entries: list, target_host: str,
                    override: bool) -> tuple[list, list]:
    """Separa o que foi DESCOBERTO em: URLs in-scope (podem ser probadas) e hosts
    externos (NUNCA tocados). URLs relativas ('/x') são same-origin → in-scope."""
    def ok(h):
        return in_scope_host(h, entries, target_host, override)

    inscope_urls: list = []
    external: set = set()
    for u in art.all_urls:
        h = enrich.url_host(u)
        if h is None or ok(h):        # relativa (None) = same-origin
            inscope_urls.append(u)
        else:
            external.add(h)
    # hosts externos também podem surgir de URLs absolutas mineradas de JS e de subs
    for u in art.js_endpoints:
        if u.startswith(("http://", "https://")):
            h = enrich.url_host(u)
            if h and not ok(h):
                external.add(h)
    for h in art.subdomains:
        if not ok(h):
            external.add(h)
    return inscope_urls, sorted(external)


def write_scope_split(run_dir: Path, inscope_urls: list, external: list) -> None:
    _write_lines(run_dir / "all-urls-inscope.txt", inscope_urls)
    if external:
        header = [
            "# HOSTS DESCOBERTOS FORA DE ESCOPO — a ferramenta NAO os testa.",
            "# Listados so p/ consciencia situacional. Scan ativo aqui exige NOVA autorizacao.",
            "",
        ]
        _write_lines(run_dir / "external-hosts.txt", header + external)


# ----------------------------------- diff ----------------------------------- #

_DIFF_FILES = ["all-urls.txt", "endpoints-with-params.txt", "subdomains.txt",
               "param-names.txt", "api-endpoints.txt", "js-endpoints.txt",
               "params-all.txt", "interesting.txt"]


def _read_set(p: Path) -> set:
    if p and p.is_file():
        return {x for x in p.read_text(errors="ignore").splitlines() if x.strip()}
    return set()


def compute_diff(run_dir: Path, prev_dir: Optional[Path]) -> dict:
    # Guard: run recém-criado no mesmo segundo do anterior -> não diffar contra si mesmo.
    if prev_dir is not None:
        try:
            if prev_dir.resolve() == run_dir.resolve():
                prev_dir = None
        except OSError:
            prev_dir = None
    result: dict = {}
    for name in _DIFF_FILES:
        cur = _read_set(run_dir / name)
        prev = _read_set(prev_dir / name) if prev_dir else set()
        new = sorted(cur - prev)
        result[name] = new
        if prev_dir:
            _write_lines(run_dir / f"diff-new-{name}", new)
    return result


# ------------------------------ httpx / chain ------------------------------- #

def run_probe_and_chain(run_dir: Path, all_urls: Path, do_chain: bool,
                        severity: str, timeout: int, dry_run: bool) -> list:
    results: list = []
    if not all_urls.is_file() or all_urls.stat().st_size == 0:
        results.append(StageResult(name="httpx-toolkit", note="sem URLs para probar"))
        return results
    live = run_dir / "live.txt"
    httpx = resolve_bin("httpx")
    cmd = [httpx, "-silent", "-sc", "-title", "-td",
           "-mc", "200,201,204,301,302,307,308,401,403,405,500",
           "-l", str(all_urls), "-o", str(live)]
    results.append(run_stage("httpx-toolkit", cmd, None, timeout, dry_run))

    if do_chain:
        nuclei = resolve_bin("nuclei")
        target_list = live if (live.is_file() and live.stat().st_size) else all_urls
        out = run_dir / "nuclei.jsonl"
        cmd = [nuclei, "-list", str(target_list), "-severity", severity,
               "-jsonl", "-o", str(out), "-silent"]
        results.append(run_stage("nuclei", cmd, None, timeout, dry_run))
    return results


# --------------------------------- relatório -------------------------------- #

def write_report_md(run_dir: Path, target: str, art: CrawlArtifacts,
                    diff: dict, prev_dir: Optional[Path], stages: list,
                    scope_source: str, external: Optional[list] = None) -> None:
    def cell(s):
        return str(s).replace("|", "/").replace("\n", " ").replace("`", "'")

    external = external or []
    lines = [
        f"# Crawl — {cell(target)}", "",
        f"- **registros JSONL:** {art.records}",
        f"- **URLs:** {len(art.all_urls)}",
        f"- **JS:** {len(art.js)}",
        f"- **endpoints c/ params:** {len(art.param_urls)}",
        f"- **param names únicos:** {len(art.param_names)}",
        f"- **params (todos, p/ fuzz):** {len(art.all_params)}",
        f"- **subdomínios:** {len(art.subdomains)}",
        f"- **API endpoints:** {len(art.api_endpoints)}",
        f"- **JS endpoints (escondidos):** {len(art.js_endpoints)}",
        f"- **arquivos interessantes (sensíveis):** {len(art.interesting)}",
        f"- **forms:** {len(art.forms)}",
        f"- **possíveis segredos:** {len(art.secrets)}",
        f"- **hosts externos (NÃO testados):** {len(external)}",
        f"- **scope:** {cell(scope_source)}",
        "",
    ]
    if external:
        lines += ["## Hosts externos descobertos (fora de escopo — não testados)", ""]
        lines += [f"- `{cell(h)}`" for h in external[:100]]
        lines.append("")
    if diff:
        base = f"vs {prev_dir.name}" if prev_dir else "sem baseline (primeiro run)"
        lines += [f"## Novidades desde o último run ({base})", ""]
        for name, items in diff.items():
            lines.append(f"- **{name}:** +{len(items)}")
        lines.append("")
    if art.interesting:
        lines += ["## Arquivos/paths interessantes (sensíveis)", ""]
        lines += [f"- `{cell(u)}`" for u in art.interesting[:100]]
        lines.append("")
    if art.secrets:
        lines += ["## Possíveis segredos", "", "| regra | trecho | url |", "|---|---|---|"]
        for rule, frag, url in art.secrets[:100]:
            lines.append(f"| {cell(rule)} | `{cell(frag[:80])}` | {cell(url)} |")
        lines.append("")
    if stages:
        lines += ["## Encadeamento", "", "| estágio | rodou | rc | nota |", "|---|---|---|---|"]
        for s in stages:
            lines.append(
                f"| {cell(s.name)} | {'sim' if s.ran else 'não'} | "
                f"{s.returncode if s.returncode is not None else '-'} | {cell(s.note)} |"
            )
        lines.append("")
    _write_lines(run_dir / "crawl-report.md", ["\n".join(lines)])
