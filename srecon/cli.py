from __future__ import annotations

import getpass
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

from . import config, report
from . import cvedb
from . import msf as msfmod
from . import scope as scopemod
from .commands import crawl as crawl_cmd
from .commands import cve as cve_cmd
from .commands import host as host_cmd
from .commands import msf as msf_cmd
from .commands import pipeline as pipeline_cmd
from .commands import search as search_cmd
from .commands import subs as subs_cmd
from .models import HostReport
from .shodan_client import ShodanClient, ShodanClientError
from .util import output_dir, slugify, utc_stamp

app = typer.Typer(
    help="srecon — recon com Shodan para a estação srv1876073.",
    no_args_is_help=True,
    add_completion=False,
    # NUNCA mostrar locals no traceback: `key` da API vive como variável local.
    pretty_exceptions_show_locals=False,
    pretty_exceptions_enable=False,
)
console = Console()
err = Console(stderr=True)


def _client() -> ShodanClient:
    try:
        key = config.resolve_api_key()
    except config.ConfigError as e:
        err.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(code=2)
    return ShodanClient(key)


def _split(csv_opt: Optional[str]) -> list:
    if not csv_opt:
        return []
    return [p.strip() for p in csv_opt.split(",") if p.strip()]


def _die(msg: str, code: int = 1):
    err.print(f"[red]{escape(str(msg))}[/red]")
    raise typer.Exit(code=code)


# --------------------------------- init ------------------------------------ #

@app.command()
def init(
    validate: bool = typer.Option(True, help="Valida a key no Shodan antes de salvar."),
):
    """Configura e salva a API key do Shodan (~/.config/srecon/config.toml, 0600)."""
    key = getpass.getpass("Shodan API key (não vai ecoar): ").strip()
    if not key:
        _die("nenhuma key informada.")
    if validate:
        try:
            info = ShodanClient(key).info()
        except ShodanClientError as e:
            _die(f"key inválida ou erro na API: {e}", code=2)
        console.print(f"[green]key válida[/green] — plano: [cyan]{escape(str(info.plan or '-'))}[/cyan], "
                      f"query credits: {info.query_credits}")
    path = config.save_api_key(key)
    console.print(f"[green]salvo em[/green] {path} (perm 0600)")


# --------------------------------- info ------------------------------------ #

@app.command()
def info():
    """Mostra plano, créditos e limites da conta Shodan."""
    client = _client()
    try:
        report.print_plan(client.info())
    except ShodanClientError as e:
        _die(str(e))


# --------------------------------- host ------------------------------------ #

@app.command()
def host(
    target: str = typer.Argument(..., help="IP ou domínio."),
    history: bool = typer.Option(False, help="Inclui histórico (mais query credits)."),
    save: bool = typer.Option(True, help="Salva JSON+markdown em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru em vez de tabela."),
):
    """Host & vuln intel: portas, serviços, banners e CVEs de um IP/domínio (passivo)."""
    client = _client()
    try:
        rep = host_cmd.run(client, target, history=history)
    except (ShodanClientError, ValueError) as e:
        _die(str(e))
    if as_json:
        console.print_json(rep.model_dump_json())
    else:
        report.print_host(rep)
    if save:
        outdir = output_dir(config.reports_dir(), target)
        report.write_json(rep, outdir / "host.json")
        report.write_host_md(rep, outdir / "host.md")
        console.print(f"[dim]salvo em {outdir}[/dim]")


# -------------------------------- search ----------------------------------- #

@app.command()
def search(
    query: Optional[str] = typer.Argument(None, help='Query Shodan, ex: "org:\\"Empresa\\" port:443".'),
    facets: Optional[str] = typer.Option(None, help="Facets separados por vírgula: country,org,port."),
    limit: int = typer.Option(100, help="Máximo de resultados a buscar."),
    fields: Optional[str] = typer.Option(None, help="Colunas da tabela (vírgula)."),
    count: bool = typer.Option(False, help="Só conta (não gasta 1 credit por página de resultados)."),
    save: bool = typer.Option(True, help="Salva JSON+CSV em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
    save_as: Optional[str] = typer.Option(None, help="Salva esta query com um nome reutilizável."),
    saved: Optional[str] = typer.Option(None, help="Usa uma query salva por nome."),
):
    """Search & facets: consulta o banco do Shodan com filtros e agregações (passivo)."""
    client = _client()

    if saved:
        stored = config.load_saved_queries().get(saved)
        if not stored:
            _die(f"query salva '{saved}' não encontrada.")
        query = stored
    if not query:
        _die("informe uma query (argumento) ou use --saved NOME.", code=2)
    if save_as:
        try:
            config.save_query(save_as, query)
        except ValueError as e:
            _die(str(e))
        console.print(f"[green]query salva como[/green] '{escape(save_as)}'")

    facet_list = _split(facets)

    if count:
        try:
            res = search_cmd.run_count(client, query, facet_list)
        except ShodanClientError as e:
            _die(str(e))
        console.print(f"[bold]{res.get('total', 0)}[/bold] resultados p/ [cyan]{escape(query)}[/cyan]")
        for name, items in (res.get("facets", {}) or {}).items():
            console.print(f"[bold]facet {escape(str(name))}:[/bold]")
            for it in items:
                console.print(f"  {escape(str(it.get('value')))}: {it.get('count')}")
        return

    try:
        result = search_cmd.run(client, query, facet_list, limit)
    except ShodanClientError as e:
        _die(str(e))

    field_list = _split(fields) or search_cmd.DEFAULT_FIELDS
    if as_json:
        console.print_json(result.model_dump_json())
    else:
        report.print_search(result, field_list)

    if save:
        outdir = output_dir(config.reports_dir(), f"search-{query}")
        report.write_json(result, outdir / "search.json")
        report.write_search_csv(result, outdir / "search.csv")
        console.print(f"[dim]salvo em {outdir}[/dim]")


# ------------------------------- pipeline ---------------------------------- #

@app.command()
def pipeline(
    target: Optional[str] = typer.Argument(None, help="IP ou domínio alvo."),
    from_host: Optional[str] = typer.Option(None, help="Coleta alvos de um host do Shodan (IP)."),
    from_search: Optional[str] = typer.Option(None, help="Coleta IPs de uma query Shodan."),
    from_subs: Optional[str] = typer.Option(None, help="Enumera subdomínios (subfinder→dnsx) do domínio e alimenta o funil."),
    from_file: Optional[Path] = typer.Option(None, help="Lê alvos (1 por linha; '#' = comentário) de um arquivo."),
    search_limit: int = typer.Option(50, help="Máx. de hosts de --from-search."),
    stages: str = typer.Option("httpx,nuclei,testssl", help="Estágios ativos a rodar."),
    severity: str = typer.Option("low,medium,high,critical", help="Severidades do nuclei."),
    scope_file: Optional[Path] = typer.Option(None, help="Arquivo de escopo específico a usar."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized",
        help="OVERRIDE explícito do scope-gating (registrado no relatório). Use com responsabilidade.",
    ),
    timeout: int = typer.Option(1800, help="Timeout por estágio (segundos)."),
    dry_run: bool = typer.Option(False, help="Mostra os comandos sem executar."),
):
    """Attack-surface pipeline: Shodan -> httpx-toolkit -> nuclei -> testssl (ATIVO, gated por scope)."""
    if not (target or from_host or from_search or from_subs or from_file):
        _die("informe um alvo: TARGET, --from-host, --from-search, --from-subs ou --from-file.")

    requested = _split(stages)
    invalid = [s for s in requested if s not in pipeline_cmd.VALID_STAGES]
    if invalid:
        _die(f"estágios inválidos: {invalid}. Válidos: {pipeline_cmd.VALID_STAGES}")

    # só --from-host/--from-search batem no Shodan; funil por subs/file/target dispensa API key.
    client = _client() if (from_host or from_search) else None
    try:
        hosts = pipeline_cmd.gather_targets(
            client, target, from_host, from_search, search_limit,
            from_subs=from_subs, from_file=from_file,
        )
    except (ShodanClientError, ValueError) as e:
        _die(str(e))
    if not hosts:
        _die("nenhum host coletado (ou todos malformados/filtrados).")
    console.print(f"[bold]{len(hosts)}[/bold] host(s) coletado(s).")

    try:
        decision = pipeline_cmd.decide_scope(hosts, config.scope_dir(), scope_file, i_am_authorized)
    except ValueError as e:
        _die(str(e), code=2)

    if decision.out_scope and not i_am_authorized:
        err.print(f"[yellow]{len(decision.out_scope)} host(s) FORA de escopo — não serão tocados:[/yellow]")
        for h in decision.out_scope[:20]:
            err.print(f"  [yellow]- {escape(h)}[/yellow]")
    if not decision.in_scope:
        _die(
            "nenhum alvo autorizado. Scan ativo exige autorização em "
            f"{config.scope_dir()} (Regra de ouro do README).\n"
            "Adicione um scope/*.txt, use --scope-file, ou --i-am-authorized se tiver "
            "autorização por escrito registrada.",
            code=3,
        )
    if i_am_authorized:
        err.print("[yellow]OVERRIDE ativo (--i-am-authorized): scope-gating ignorado.[/yellow]")

    src = ", ".join(sorted(decision.sources)) or "-"
    console.print(f"[green]{len(decision.in_scope)} alvo(s) autorizado(s)[/green] (fonte: {escape(src)})")

    label = target or from_subs or from_host or from_search or (
        from_file.name if from_file else "pipeline")
    if dry_run:
        outdir = config.reports_dir() / f"pipeline-{slugify(label)}"  # não cria diretório
    else:
        outdir = output_dir(config.reports_dir(), f"pipeline-{label}")

    stage_results = pipeline_cmd.run_stages(
        decision.in_scope, outdir, requested, severity, timeout, dry_run
    )

    st = report.Table(title="estágios", box=report.box.MINIMAL_DOUBLE_HEAD)
    for c in ("estágio", "rodou", "rc", "nota"):
        st.add_column(c)
    for s in stage_results:
        st.add_row(escape(s.name), "sim" if s.ran else "não",
                   str(s.returncode) if s.returncode is not None else "-", escape(s.note or ""))
    console.print(st)
    if dry_run:
        console.print("[bold]comandos (dry-run):[/bold]")
        for s in stage_results:
            console.print(f"  [dim]{escape(s.cmd_str)}[/dim]")
        return

    report.write_pipeline_md(
        label, hosts, decision.in_scope, decision.out_scope,
        src, stage_results, outdir / "pipeline.md",
    )
    console.print(f"[dim]relatório em {outdir}[/dim]")


# -------------------------------- crawl ------------------------------------ #

def _print_crawl_summary(target, run_dir, art, diff, prev_dir, stages, external_hosts=None):
    t = report.Table(title="crawl — resumo", box=report.box.MINIMAL_DOUBLE_HEAD)
    t.add_column("artefato")
    t.add_column("qtd", justify="right")
    rows = [
        ("registros JSONL", art.records), ("URLs", len(art.all_urls)),
        ("JS", len(art.js)), ("endpoints c/ params", len(art.param_urls)),
        ("param names únicos", len(art.param_names)),
        ("params (todos, p/ fuzz)", len(art.all_params)),
        ("subdomínios", len(art.subdomains)),
        ("API endpoints", len(art.api_endpoints)),
        ("JS endpoints (escondidos)", len(art.js_endpoints)),
        ("forms", len(art.forms)),
        ("possíveis segredos", len(art.secrets)),
    ]
    for name, n in rows:
        t.add_row(name, str(n))
    console.print(t)

    if diff:
        base = f"vs {prev_dir.name}" if prev_dir else "sem baseline (1º run)"
        dt = report.Table(title=f"novidades ({base})", box=report.box.SIMPLE)
        dt.add_column("categoria")
        dt.add_column("novos", justify="right")
        for name, items in diff.items():
            dt.add_row(name, f"[green]+{len(items)}[/green]" if items else "0")
        console.print(dt)

    if external_hosts:
        console.print(f"[yellow]hosts externos descobertos (NÃO testados): "
                      f"{len(external_hosts)}[/yellow] — ver external-hosts.txt")
    if art.secrets:
        err.print(f"[red]⚠ {len(art.secrets)} possível(is) segredo(s)[/red] — ver secrets.txt")
    if stages:
        for s in stages:
            tag = "[green]ok[/green]" if s.ran and s.returncode == 0 else f"[yellow]{escape(s.note or 'rc='+str(s.returncode))}[/yellow]"
            console.print(f"  chain {escape(s.name)}: {tag}")


@app.command()
def crawl(
    target: str = typer.Argument(..., help="IP/domínio/URL alvo do crawl."),
    depth: int = typer.Option(3, "-d", "--depth", help="Profundidade (>=3 p/ known-files)."),
    rate: int = typer.Option(20, "--rate", help="req/s global (katana -rl)."),
    host_rate: int = typer.Option(10, "--host-rate", help="req/s por host (-hrl)."),
    concurrency: int = typer.Option(5, "-c", "--concurrency", help="fetchers concorrentes (-c)."),
    parallelism: int = typer.Option(2, "--parallelism", help="inputs paralelos (-p)."),
    timeout_s: int = typer.Option(15, "--timeout", help="timeout por request (s)."),
    retry: int = typer.Option(2, "--retry", help="retries por request."),
    delay: int = typer.Option(1, "--delay", help="delay entre requests (s, -rd)."),
    duration: str = typer.Option("30m", "--duration", help="duração máx do crawl (-ct), ex 30m/1h."),
    field_scope: str = typer.Option("rdn", "--field-scope", help="escopo de campo do katana: rdn|fqdn|dn (-fs)."),
    js: bool = typer.Option(True, "--js/--no-js", help="parsing de endpoints em JS (-jc)."),
    known_files: bool = typer.Option(True, "--known-files/--no-known-files", help="known-files (-kf all)."),
    headless: bool = typer.Option(False, "--headless", help="crawl headless (-hl -nos -sc -xhr); lento."),
    header: Optional[list[str]] = typer.Option(None, "-H", "--header", help="header/cookie extra (repetível)."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="proxy HTTP/SOCKS5 (-proxy)."),
    extra: Optional[str] = typer.Option(None, "--extra", help="args katana crus (word-split)."),
    store_responses: bool = typer.Option(True, "--store-responses/--no-store-responses", help="salvar respostas brutas."),
    scope_file: Optional[Path] = typer.Option(None, help="Arquivo de escopo específico."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="OVERRIDE do scope-gating."),
    do_diff: bool = typer.Option(True, "--diff/--no-diff", help="diff vs run anterior (latest)."),
    scan_secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="varre bodies por segredos."),
    chain: bool = typer.Option(False, "--chain", help="encadeia httpx-toolkit -> nuclei nos achados."),
    do_httpx: bool = typer.Option(False, "--httpx", help="probe httpx-toolkit em all-urls (-> live.txt)."),
    severity: str = typer.Option("low,medium,high,critical", help="severidades do nuclei (no --chain)."),
    stage_timeout: int = typer.Option(1800, "--stage-timeout", help="timeout por estágio httpx/nuclei do chain (s)."),
    dry_run: bool = typer.Option(False, help="mostra o comando do katana sem executar."),
):
    """Crawl ATIVO com katana: URLs/JS/params/subs + forms/segredos/API, diff vs run anterior e encadeamento (gated por scope)."""
    if field_scope not in crawl_cmd.FIELD_SCOPES:
        _die(f"--field-scope inválido '{field_scope}' (use rdn|fqdn|dn).")
    if "," in target:
        # -u do katana é lista separada por vírgula: um target com ',' viraria
        # múltiplos seeds, dos quais só o 1º passa pelo scope-gate. Recusa.
        _die("target não pode conter vírgula (cada host deve ser um crawl separado).", code=2)

    host = crawl_cmd.extract_host(target) or target

    # scope-gating: crawl é ATIVO (toca o alvo)
    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())
    hit = scopemod.match(host, entries)
    if not hit and not i_am_authorized:
        _die(
            f"'{host}' não autorizado. Crawl é ativo e exige scope em {config.scope_dir()} "
            "(Regra de ouro). Use --scope-file ou --i-am-authorized se tiver autorização escrita.",
            code=3,
        )
    if i_am_authorized and not hit:
        err.print("[yellow]OVERRIDE ativo (--i-am-authorized): scope-gating ignorado.[/yellow]")

    katana = crawl_cmd.resolve_bin("katana")
    if not katana:
        _die("katana não encontrado (PATH nem ~/go/bin). Instale ou ajuste o PATH.", code=127)

    opt = crawl_cmd.CrawlOptions(
        depth=depth, rate=rate, host_rate=host_rate, concurrency=concurrency,
        parallelism=parallelism, timeout=timeout_s, retry=retry, delay=delay,
        duration=duration, field_scope=field_scope, js=js, known_files=known_files,
        headless=headless, headers=header or [], proxy=proxy or "",
        extra=crawl_cmd.split_extra(extra), store_responses=store_responses,
    )

    slug = slugify(f"crawl-{host}")
    parent = config.reports_dir() / slug
    prev_dir = crawl_cmd.previous_run(parent) if do_diff else None
    run_dir = parent / utc_stamp()

    seeds = crawl_cmd.build_seeds(target)
    args = crawl_cmd.build_katana_args(katana, seeds, run_dir, opt)
    scope_src = str(hit.source) if hit else "OVERRIDE (--i-am-authorized)"

    safe_target = crawl_cmd.strip_userinfo(target)   # nunca ecoar user:pass@ no console/relatório
    console.print(f"[bold]katana crawl[/bold] de [cyan]{escape(safe_target)}[/cyan] "
                  f"(scope: {escape(scope_src)})")
    console.print(f"[dim]{escape(' '.join(crawl_cmd.redact_args(args)))}[/dim]")

    if dry_run:
        console.print(f"[yellow]dry-run[/yellow] — nada executado (dir seria {run_dir}).")
        return

    run_dir.mkdir(parents=True, exist_ok=True)
    crawl_cmd.harden_dir(run_dir)                    # 0700: protege bodies/segredos
    crawl_cmd.write_meta(run_dir, target, seeds, katana, args, opt)
    rc = crawl_cmd.run_katana(args)
    if rc == 130:
        err.print("[yellow]interrompido — processando resultados parciais.[/yellow]")
    elif rc != 0:
        err.print(f"[yellow]katana saiu com código {rc}; processando o capturado.[/yellow]")

    art = crawl_cmd.process_jsonl(run_dir / "output.jsonl", scan_secrets)
    crawl_cmd.write_artifacts(art, run_dir)
    diff = crawl_cmd.compute_diff(run_dir, prev_dir) if do_diff else {}

    # BLINDAGEM: só URLs em escopo podem ser probadas; hosts externos descobertos
    # (JS de terceiros, redirects, etc.) vão p/ external-hosts.txt e NUNCA são tocados.
    inscope_urls, external_hosts = crawl_cmd.scope_partition(art, entries, host, i_am_authorized)
    crawl_cmd.write_scope_split(run_dir, inscope_urls, external_hosts)
    if external_hosts:
        err.print(f"[yellow]{len(external_hosts)} host(s) externos descobertos — "
                  "NÃO serão testados (ver external-hosts.txt).[/yellow]")

    stages = []
    if do_httpx or chain:
        stages = crawl_cmd.run_probe_and_chain(
            run_dir, run_dir / "all-urls-inscope.txt", chain, severity, stage_timeout, False
        )

    crawl_cmd.update_latest(parent, run_dir)
    _print_crawl_summary(safe_target, run_dir, art, diff, prev_dir, stages, external_hosts)
    crawl_cmd.write_report_md(run_dir, safe_target, art, diff, prev_dir, stages, scope_src, external_hosts)
    console.print(f"[dim]relatório em {run_dir}[/dim]")


# --------------------------------- subs ------------------------------------ #

@app.command()
def subs(
    domain: str = typer.Argument(..., help="Domínio raiz (ex: example.com)."),
    all_sources: bool = typer.Option(True, "--all/--fast", help="Todas as fontes do subfinder (mais lento) vs. rápido."),
    resolve: bool = typer.Option(True, "--resolve/--no-resolve", help="Resolve com dnsx e mantém só os vivos."),
    sub_timeout: int = typer.Option(300, help="Timeout do subfinder (s)."),
    dns_timeout: int = typer.Option(120, help="Timeout do dnsx (s)."),
    scope_file: Optional[Path] = typer.Option(None, help="Escopo específico p/ anotar in/out."),
    save: bool = typer.Option(True, help="Salva subs.txt/resolved.txt/subs.md em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Enum de subdomínios (subfinder → dnsx). Passivo/OSINT: anota in/out de escopo, não bloqueia."""
    if not subs_cmd.resolve_bin("subfinder"):
        _die("subfinder não encontrado (PATH nem ~/go/bin).", code=127)
    if resolve and not subs_cmd.resolve_bin("dnsx"):
        err.print("[yellow]dnsx ausente — seguindo sem resolução (--no-resolve).[/yellow]")
        resolve = False

    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())

    try:
        result = subs_cmd.run(domain, entries, all_sources=all_sources,
                              do_resolve=resolve, sub_timeout=sub_timeout,
                              dns_timeout=dns_timeout)
    except ValueError as e:
        _die(str(e), code=2)

    if result.subfinder_rc == 127:
        _die("subfinder falhou (rc 127).", code=127)

    if as_json:
        payload = {"domain": result.domain, "subdomains": result.subdomains,
                   "resolved": [{"host": h, "ips": ips} for h, ips in result.resolved],
                   "in_scope": result.in_scope, "out_scope": result.out_scope}
        console.print_json(report.json.dumps(payload))
    else:
        report.print_subs(result)

    if save and result.subdomains:
        outdir = output_dir(config.reports_dir(), f"subs-{result.domain}")
        report.write_subs_files(result, outdir)
        console.print(f"[dim]salvo em {outdir}[/dim]  "
                      f"[dim](alimente o pipeline: srecon pipeline --from-subs {escape(result.domain)})[/dim]")


# --------------------------------- cve ------------------------------------- #

@app.command()
def cve(
    cves: list[str] = typer.Argument(..., help="Uma ou mais CVEs (ex: CVE-2021-44228)."),
    with_msf: bool = typer.Option(False, "--msf", help="Também mapeia cada CVE para módulos do Metasploit."),
    timeout: float = typer.Option(15.0, help="Timeout por consulta à CVEDB (s)."),
    save: bool = typer.Option(True, help="Salva JSON+markdown em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """CVE intel via CVEDB do Shodan (grátis, sem key/credits): CVSS, EPSS, KEV, ação — e módulos MSF."""
    bad = [c for c in cves if not msfmod.normalize_cve(c)]
    if bad:
        _die(f"CVE(s) malformada(s): {bad} (formato CVE-AAAA-NNNN).", code=2)

    details, errors = cve_cmd.lookup(cves, timeout=timeout)
    if not details and errors:
        _die("; ".join(f"{c}: {m}" for c, m in errors))

    if as_json:
        console.print_json(report.json.dumps([d.model_dump() for d in details]))
    else:
        report.print_cve_details(details, errors)

    msf_result = None
    if with_msf:
        try:
            index = msfmod.load_index(None)
            hits = msf_cmd.match_cves(index, [d.cve_id for d in details])
            msf_result = msf_cmd.MsfMatchResult(target=",".join(d.cve_id for d in details), cve_hits=hits)
            report.print_msf(msf_result)
        except msfmod.MsfError as e:
            err.print(f"[yellow]MSF indisponível: {escape(str(e))}[/yellow]")

    if save and details:
        label = details[0].cve_id if len(details) == 1 else f"{len(details)}-cves"
        outdir = output_dir(config.reports_dir(), f"cve-{label}")
        report.write_json([d.model_dump() for d in details], outdir / "cve.json")
        console.print(f"[dim]salvo em {outdir}[/dim]")


# -------------------------------- vulns ------------------------------------ #

@app.command()
def vulns(
    reports: Optional[Path] = typer.Option(None, help="Diretório de relatórios (default: reports/ do workspace)."),
    min_cvss: float = typer.Option(0.0, help="Filtra CVEs abaixo deste CVSS."),
    enrich: bool = typer.Option(False, "--enrich", help="Enriquece cada CVE via CVEDB (KEV/EPSS)."),
    with_msf: bool = typer.Option(False, "--msf", help="Mapeia cada CVE para módulos do Metasploit."),
    save: bool = typer.Option(True, help="Salva markdown do rollup em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Rollup de vulnerabilidades cross-host: agrega CVEs de todos os host.json salvos (offline)."""
    reports_dir = reports or config.reports_dir()
    aggs = cve_cmd.aggregate_reports(reports_dir, min_cvss=min_cvss)
    if not aggs:
        console.print(f"[yellow]nenhuma CVE agregada em {escape(str(reports_dir))} "
                      "(rode 'srecon host' antes, ou ajuste --reports/--min-cvss).[/yellow]")
        return

    enriched: dict = {}
    if enrich:
        for e in aggs:
            try:
                enriched[e.cve] = cvedb.get_cve(e.cve)
            except cvedb.CvedbError:
                pass

    msf_map: dict = {}
    if with_msf:
        try:
            index = msfmod.load_index(None)
            for e in aggs:
                mods = index.by_cve(e.cve)
                if mods:
                    msf_map[e.cve] = [m.fullname for m in mods]
        except msfmod.MsfError as ex:
            err.print(f"[yellow]MSF indisponível: {escape(str(ex))}[/yellow]")

    if as_json:
        payload = [{"cve": e.cve, "cvss": e.max_cvss, "verified": e.verified,
                    "hosts": e.hosts, "kev": bool(enriched.get(e.cve) and enriched[e.cve].kev),
                    "msf_modules": msf_map.get(e.cve, [])} for e in aggs]
        console.print_json(report.json.dumps(payload))
    else:
        report.print_vuln_rollup(aggs, enriched=enriched, msf_map=msf_map)

    if save:
        outdir = output_dir(config.reports_dir(), "vulns-rollup")
        report.write_vulns_md(aggs, outdir / "vulns.md", enriched=enriched, msf_map=msf_map)
        console.print(f"[dim]salvo em {outdir}[/dim]")


# --------------------------------- msf ------------------------------------- #

@app.command()
def msf(
    target: Optional[str] = typer.Argument(None, help="IP/domínio: lookup passivo no Shodan e mapeia CVEs/produtos → módulos."),
    cve: Optional[str] = typer.Option(None, help="CVE(s) por vírgula p/ mapear direto (offline, sem API)."),
    report_file: Optional[Path] = typer.Option(None, "--report", help="Usa um host.json já salvo (offline, sem API)."),
    product: Optional[str] = typer.Option(None, help="Busca candidatos por palavra-chave de produto (ex: vsftpd)."),
    types: str = typer.Option("exploit,auxiliary", help="Tipos de módulo (vírgula): exploit,auxiliary,post,..."),
    min_rank: str = typer.Option("normal", help="Rank mínimo p/ candidatos por produto: manual|low|average|normal|good|great|excellent."),
    metadata: Optional[Path] = typer.Option(None, help="Caminho do modules_metadata.json (default ~/.msf4/...)."),
    rc: bool = typer.Option(False, "--rc", help="Gera resource script .rc de TRIAGEM (sem run) com RHOSTS."),
    rport: Optional[int] = typer.Option(None, help="RPORT a fixar no .rc."),
    save: bool = typer.Option(True, help="Salva JSON+markdown (+.rc) em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Metasploit: casa versões/CVEs achados (Shodan) com módulos do MSF — offline, via cache de metadata."""
    type_list = _split(types) or None
    rank_min = msfmod.RANK_FROM_LABEL.get(min_rank.strip().lower())
    if rank_min is None:
        _die(f"--min-rank inválido '{min_rank}'. Use: {', '.join(msfmod.RANK_LABELS.values())}.", code=2)

    try:
        index = msfmod.load_index(metadata)
    except msfmod.MsfError as e:
        _die(str(e), code=4)

    rhosts = None
    if cve:
        cves = _split(cve)
        invalid = [c for c in cves if not msfmod.normalize_cve(c)]
        if invalid:
            _die(f"CVE(s) malformada(s): {invalid} (formato CVE-AAAA-NNNN).", code=2)
        cve_hits = msf_cmd.match_cves(index, cves, types=type_list)
        result = msf_cmd.MsfMatchResult(target=target, rhosts=target, cve_hits=cve_hits)
        rhosts = target
    elif report_file:
        try:
            rep = HostReport.model_validate_json(report_file.read_text(errors="ignore"))
        except (OSError, ValueError) as e:
            _die(f"não consegui ler o host.json '{report_file}': {e}", code=2)
        result = msf_cmd.match_host(index, rep, types=type_list, min_rank=rank_min)
        rhosts = rep.ip
    elif product:
        phits = msf_cmd.match_products(index, [(product, None, [])], types=type_list, min_rank=rank_min)
        result = msf_cmd.MsfMatchResult(target=product, product_hits=phits)
    elif target:
        client = _client()
        try:
            rep = host_cmd.run(client, target)
        except (ShodanClientError, ValueError) as e:
            _die(str(e))
        result = msf_cmd.match_host(index, rep, types=type_list, min_rank=rank_min)
        rhosts = rep.ip or target
    else:
        _die("informe TARGET, --cve, --report ou --product.", code=2)

    if as_json:
        import json as _json
        payload = {
            "target": result.target, "rhosts": result.rhosts,
            "cve_hits": [
                {"cve": h.cve, "cvss": h.cvss,
                 "modules": [{"fullname": m.fullname, "type": m.mtype, "rank": m.rank_label} for m in h.modules]}
                for h in result.cve_hits
            ],
            "product_hits": [
                {"product": p.product, "version": p.version, "ports": p.ports,
                 "modules": [{"fullname": m.fullname, "type": m.mtype, "rank": m.rank_label} for m in p.modules]}
                for p in result.product_hits
            ],
        }
        console.print_json(_json.dumps(payload))
    else:
        report.print_msf(result)

    rc_text = None
    module_names = result.module_names()
    if rc:
        if not rhosts:
            err.print("[yellow]--rc ignorado: sem RHOSTS (use TARGET ou --report com IP).[/yellow]")
        elif not module_names:
            err.print("[yellow]--rc ignorado: nenhum módulo casado por CVE.[/yellow]")
        else:
            rc_text = msfmod.build_resource_script(rhosts, module_names, rport)

    if save and (result.cve_hits or result.product_hits):
        outdir = output_dir(config.reports_dir(), f"msf-{result.target or 'query'}")
        report.write_json(
            {"target": result.target, "rhosts": result.rhosts,
             "modules_by_cve": {h.cve: [m.fullname for m in h.modules] for h in result.cve_hits}},
            outdir / "msf.json",
        )
        report.write_msf_md(result, outdir / "msf.md")
        if rc_text:
            (outdir / "triage.rc").write_text(rc_text, encoding="utf-8")
            console.print(f"[green]resource script[/green] → {outdir / 'triage.rc'}  "
                          f"[dim](msfconsole -r {outdir / 'triage.rc'})[/dim]")
        console.print(f"[dim]salvo em {outdir}[/dim]")
    elif rc_text:
        console.print("[bold]resource script (triagem):[/bold]")
        console.print(escape(rc_text))


# ------------------------------ scope-check -------------------------------- #

@app.command("scope-check")
def scope_check(
    target: str = typer.Argument(..., help="IP/domínio/URL para testar contra scope/."),
    scope_file: Optional[Path] = typer.Option(None, help="Testa contra um arquivo específico."),
):
    """Testa se um alvo está autorizado pelos arquivos scope/ (offline, sem API)."""
    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())
    hit = scopemod.match(target, entries)
    if hit:
        console.print(f"[green]AUTORIZADO[/green] — {escape(target)} coberto por {escape(str(hit.source))}")
    else:
        srcs = ", ".join(str(e.source.name) for e in entries) or "(nenhum scope carregado)"
        err.print(f"[red]FORA DE ESCOPO[/red] — {escape(target)} não bate em: {escape(srcs)}")
        raise typer.Exit(code=3)


# ------------------------------- selftest ---------------------------------- #

@app.command()
def selftest():
    """Roda checagens offline (parsing de modelos + scope), sem tocar na API."""
    from .models import HostReport

    checks: list[tuple[str, bool, str]] = []

    sample = {
        "ip_str": "203.0.113.7", "org": "ACME", "asn": "AS64500",
        "hostnames": ["a.example.com"], "ports": [443, 22],
        "data": [
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.25",
             "vulns": {"CVE-2021-23017": {"cvss": 9.8, "verified": True, "summary": "x"}},
             "ssl": {"versions": ["TLSv1.2"]}, "_shodan": {"module": "https"}},
            {"port": 22, "transport": "tcp", "product": "OpenSSH"},
        ],
    }
    rep = HostReport.from_shodan(sample)
    checks.append(("parse ip", rep.ip == "203.0.113.7", rep.ip or ""))
    checks.append(("parse ports", rep.ports == [22, 443], str(rep.ports)))
    checks.append(("parse vuln", len(rep.vulns) == 1 and rep.vulns[0].cvss == 9.8,
                   str([v.cve for v in rep.vulns])))
    checks.append(("services sorted", rep.services[0].port == 22, str(rep.services[0].port)))

    entry = scopemod.parse_scope_text(
        "Autorizado *.cloudwiser.com.br e 198.51.100.0/24", Path("t.txt")
    )
    checks.append(("scope subdomain", scopemod.match("cortex.cloudwiser.com.br", [entry]) is not None, ""))
    checks.append(("scope url", scopemod.match("https://a.cloudwiser.com.br/x", [entry]) is not None, ""))
    checks.append(("scope cidr", scopemod.match("198.51.100.42", [entry]) is not None, ""))
    checks.append(("scope reject", scopemod.match("evil.com", [entry]) is None, ""))
    checks.append(("scope reject ip", scopemod.match("8.8.8.8", [entry]) is None, ""))
    checks.append(("scope reject newline",
                   scopemod.match("evil.com\ncortex.cloudwiser.com.br", [entry]) is None,
                   "gate anti-bypass"))
    checks.append(("scope reject comma",
                   scopemod.match("cortex.cloudwiser.com.br,evil.com", [entry]) is None,
                   "gate anti-bypass (vírgula)"))
    entry6 = scopemod.parse_scope_text("Autorizado 2001:db8::/32", Path("t6.txt"))
    checks.append(("scope ipv6 cidr",
                   scopemod.match("http://[2001:db8::5]/x", [entry6]) is not None, "ipv6"))

    # gate anti-bypass: linha de negação/exclusão NÃO autoriza
    neg = scopemod.parse_scope_text(
        "Autorizado prod.ok.com\nFora de escopo (NAO TOCAR): bad.evil.com", Path("n.txt"))
    checks.append(("scope allow line", scopemod.match("prod.ok.com", [neg]) is not None, ""))
    checks.append(("scope negation blocks",
                   scopemod.match("bad.evil.com", [neg]) is None, "gate anti-bypass (exclusão)"))

    # mineração de JS (APIs escondidas + params)
    from . import enrich
    eps = enrich.extract_js_endpoints('fetch("/api/v1/users?id=1");const x="https://a.b/c";')
    checks.append(("js endpoints", "/api/v1/users?id=1" in eps, str(len(eps))))
    checks.append(("js params", "id" in enrich.extract_js_params('go("/a?id=1&q=2")'), ""))

    # índice do Metasploit (CVE -> módulo)
    idx = msfmod.MsfIndex({"m": {"fullname": "exploit/x/y", "name": "n",
                                 "type": "exploit", "rank": 600,
                                 "references": ["CVE-2021-44228"]}})
    checks.append(("msf cve index",
                   bool(idx.by_cve("CVE-2021-44228")), "offline"))

    t = report.Table(title="selftest", box=report.box.MINIMAL_DOUBLE_HEAD)
    t.add_column("check")
    t.add_column("resultado")
    t.add_column("obs", style="dim")
    ok = True
    for name, passed, obs in checks:
        ok = ok and passed
        t.add_row(name, "[green]OK[/green]" if passed else "[red]FAIL[/red]", obs)
    console.print(t)
    if not ok:
        raise typer.Exit(code=1)
    console.print("[green]todos os checks passaram[/green]")


def main():
    try:
        app()
    except KeyboardInterrupt:
        err.print("[yellow]interrompido[/yellow]")
        raise SystemExit(130)
    except Exception as e:  # último recurso: erro limpo, sem traceback/locals
        err.print(f"[red]erro inesperado: {type(e).__name__}: {e}[/red]")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
