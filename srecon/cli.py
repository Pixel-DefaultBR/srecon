from __future__ import annotations

import getpass
import inspect
import sys
from pathlib import Path
from typing import Optional

import typer
from typer.models import ArgumentInfo, OptionInfo
from rich.console import Console
from rich.markup import escape

from . import __version__
from . import archive as archive_mod
from . import assets as assets_mod
from . import candidates as cand_mod
from . import config, report
from . import triage as triage_mod
from . import cvedb
from . import msf as msfmod
from . import scope as scopemod
from .commands import auto as auto_cmd
from .commands import crawl as crawl_cmd
from .commands import cve as cve_cmd
from .commands import fuzz as fuzz_cmd
from .commands import host as host_cmd
from .commands import msf as msf_cmd
from .commands import pipeline as pipeline_cmd
from .commands import search as search_cmd
from .commands import subs as subs_cmd
from .models import HostReport
from .shodan_client import ShodanClient, ShodanClientError
from .util import output_dir, slugify, utc_stamp

app = typer.Typer(
    help=(
        "srecon — recon com Shodan para a estação srv1876073.\n\n"
        "Consultas ao Shodan são [bold]passivas[/bold] (batem no banco, não no alvo). "
        "Os comandos [bold]ativos[/bold] — pipeline, crawl, fuzz — enviam tráfego ao "
        "alvo e por isso são bloqueados por escopo: o alvo precisa estar em algum "
        "scope/*.txt (Regra de ouro). Rode 'srecon scope-check ALVO' antes."
    ),
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


def _invoke(cmd_fn, **overrides):
    """Chama uma função de comando Typer reusando os defaults REAIS dela (extraídos
    dos OptionInfo/ArgumentInfo — chamar direto usaria o sentinela do Typer como valor)
    e sobrescrevendo só o que o `auto` precisa. Robusto a novos parâmetros; ignora
    override que o comando não tem (ex.: passar dry_run p/ um comando sem dry_run)."""
    kwargs: dict = {}
    for name, p in inspect.signature(cmd_fn).parameters.items():
        d = p.default
        kwargs[name] = d.default if isinstance(d, (OptionInfo, ArgumentInfo)) else d
    for k, v in overrides.items():
        if k in kwargs:
            kwargs[k] = v
    return cmd_fn(**kwargs)


# ------------------------ help: exemplos por comando ----------------------- #
# Exemplos completos por comando (mostrados no `srecon <cmd> --help`). rich markup:
# use [dim]/[bold]; NÃO use '[' literal em comandos (o rich tenta parsear como tag).

APP_EPILOG = (
    "[bold cyan]Começando[/bold cyan]\n"
    "  srecon init                  [dim]# salva a API key do Shodan (0600)[/dim]\n"
    "  srecon selftest              [dim]# checagens offline, sem tocar na API[/dim]\n"
    "  srecon host 1.2.3.4          [dim]# recon passivo (banco do Shodan)[/dim]\n"
    "  srecon scope-check alvo.com  [dim]# ativo só toca alvo em scope/*.txt[/dim]\n"
    "\n"
    "[dim]Passivo = consulta o banco do Shodan (não toca o alvo). Ativo (pipeline/"
    "crawl/fuzz) = envia tráfego ao alvo → bloqueado por escopo. Detalhes no README.[/dim]"
)

EXAMPLES = {
    "init": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "  srecon init                  [dim]# cola a key (não ecoa) e valida[/dim]\n"
        "  export SHODAN_API_KEY=...    [dim]# alternativa via ambiente[/dim]"
    ),
    "host": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "  srecon host 1.2.3.4\n"
        "  srecon host 1.2.3.4 --history          [dim]# inclui histórico (+credits)[/dim]\n"
        "  srecon host cortex.example.com --json  [dim]# JSON cru p/ jq/pipeline[/dim]"
    ),
    "search": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# busca com agregações (facets)[/dim]\n"
        "  srecon search 'org:\"ACME\" port:443' --facets country,product --limit 200\n"
        "[dim]# só conta — não gasta 1 credit por página[/dim]\n"
        "  srecon search 'ssl.cert.subject.cn:\"*.example.com\"' --count\n"
        "[dim]# salva a query e reusa depois[/dim]\n"
        "  srecon search 'org:\"ACME\"' --save-as acme\n"
        "  srecon search --saved acme"
    ),
    "pipeline": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# alvo único (precisa estar em scope/*.txt)[/dim]\n"
        "  srecon pipeline cortex.example.com\n"
        "[dim]# FUNIL: enumera subdomínios e joga os vivos no pipeline[/dim]\n"
        "  srecon pipeline --from-subs example.com\n"
        "[dim]# a partir de uma query Shodan (fora de escopo é descartado)[/dim]\n"
        "  srecon pipeline --from-search 'org:\"ACME\"' --search-limit 30 --dry-run\n"
        "[dim]# escolher estágios e severidade[/dim]\n"
        "  srecon pipeline 10.0.0.5 --stages httpx,nuclei --severity high,critical"
    ),
    "crawl": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# crawl ativo (gated); recupera sourcemaps e minera JS/segredos[/dim]\n"
        "  srecon crawl cortex.example.com\n"
        "[dim]# com cookie/header e profundidade maior[/dim]\n"
        "  srecon crawl https://app.example.com/ -d 4 -H 'Cookie: session=abc'\n"
        "[dim]# encadeia httpx-toolkit -> nuclei só nos in-scope[/dim]\n"
        "  srecon crawl cortex.example.com --chain --severity high,critical\n"
        "[dim]# prévia sem executar / desligar sourcemaps[/dim]\n"
        "  srecon crawl cortex.example.com --dry-run\n"
        "  srecon crawl cortex.example.com --no-sourcemaps"
    ),
    "subs": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# enum passivo (subfinder -> dnsx); anota in/out de escopo[/dim]\n"
        "  srecon subs example.com\n"
        "[dim]# rápido, sem resolver DNS[/dim]\n"
        "  srecon subs example.com --fast --no-resolve"
    ),
    "cve": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# CVSS/EPSS/KEV via CVEDB (grátis) + módulos do Metasploit[/dim]\n"
        "  srecon cve CVE-2021-44228 CVE-2011-2523 --msf"
    ),
    "vulns": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# agrega CVEs dos host.json salvos, enriquece (KEV/EPSS) e mapeia MSF[/dim]\n"
        "  srecon vulns --enrich --msf --min-cvss 7.0"
    ),
    "msf": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# lookup passivo no Shodan -> CVEs/produtos -> módulos[/dim]\n"
        "  srecon msf 1.2.3.4\n"
        "[dim]# CVE direto (offline, sem API)[/dim]\n"
        "  srecon msf --cve CVE-2021-44228\n"
        "[dim]# gera triage.rc (RHOSTS pronto, SEM 'run')[/dim]\n"
        "  srecon msf 10.0.0.5 --cve CVE-2021-44228 --rc\n"
        "[dim]# a partir de um host.json já salvo[/dim]\n"
        "  srecon msf --report reports/host-x/stamp/host.json --min-rank great"
    ),
    "fuzz": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# diretórios (ffuf) -> httpx confirma vivo + tech/título[/dim]\n"
        "  srecon fuzz cortex.example.com\n"
        "[dim]# lista curada de arquivos sensíveis (.git/.env/backup...)[/dim]\n"
        "  srecon fuzz cortex.example.com --files\n"
        "[dim]# extensões e wordlist custom[/dim]\n"
        "  srecon fuzz cortex.example.com -e .php,.bak,.zip -w /path/wordlist.txt"
    ),
    "scope-check": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# testa autorização offline (sem API)[/dim]\n"
        "  srecon scope-check cortex.example.com\n"
        "  srecon scope-check 10.0.0.5 --scope-file scope/cliente.txt"
    ),
    "urls": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# URLs históricas (Wayback + gau) + inventário de params — PASSIVO[/dim]\n"
        "  srecon urls example.com\n"
        "[dim]# só o host (sem subdomínios), limitando o volume da Wayback[/dim]\n"
        "  srecon urls app.example.com --no-subs --limit 5000\n"
        "[dim]# a wordlist de params (params.txt) alimenta fuzzing dirigido[/dim]\n"
        "  srecon urls example.com && ffuf -w reports/urls-*/params.txt ..."
    ),
    "assets": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# ativos interligados: CT (crt.sh) + ASN/netblock — GRÁTIS, passivo[/dim]\n"
        "  srecon assets example.com\n"
        "[dim]# + pivot por favicon no Shodan (gasta credit; alvo precisa estar em escopo)[/dim]\n"
        "  srecon assets example.com --shodan\n"
        "[dim]# pivot Shodan puro-passivo com hash já conhecido (não baixa favicon)[/dim]\n"
        "  srecon assets example.com --shodan --favicon-hash -1234567890"
    ),
    "candidates": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# classifica candidatos de bug a partir do último 'srecon urls' — PASSIVO[/dim]\n"
        "  srecon urls example.com && srecon candidates example.com\n"
        "[dim]# de um arquivo de URLs qualquer[/dim]\n"
        "  srecon candidates --from-file reports/urls-example.com/latest/urls-all.txt\n"
        "[dim]# PROVA ativa (payload benigno) só nos hosts em escopo[/dim]\n"
        "  srecon candidates example.com --active\n"
        "[dim]# subdomain takeover a partir de hosts (CNAME->fingerprint)[/dim]\n"
        "  srecon candidates example.com --takeover-hosts reports/subs-example.com/latest/in-scope.txt --active"
    ),
    "triage": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# consolida candidates + CVEs + urls + assets num ranking único[/dim]\n"
        "  srecon triage example.com\n"
        "[dim]# fluxo típico: descobre -> classifica -> tria[/dim]\n"
        "  srecon urls example.com && srecon candidates example.com && srecon triage example.com"
    ),
    "auto": (
        "[bold cyan]Exemplos[/bold cyan]\n"
        "[dim]# recon COMPLETO com um comando (passivo + ativo se em escopo)[/dim]\n"
        "  srecon example.com\n"
        "  srecon auto example.com          [dim]# forma explícita[/dim]\n"
        "[dim]# só passivo (não toca o alvo) / ver o plano sem executar[/dim]\n"
        "  srecon example.com --passive-only\n"
        "  srecon example.com --dry-run"
    ),
}


def _version_cb(value: bool):
    if value:
        console.print(f"srecon {__version__}")
        raise typer.Exit()


@app.callback(epilog=APP_EPILOG)
def _root(
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", is_eager=True, callback=_version_cb,
        help="Mostra a versão e sai.",
    ),
):
    # Callback raiz: só hospeda --version. O texto de ajuda do grupo vem do
    # help= do typer.Typer() acima (que tem precedência sobre esta docstring).
    return


# --------------------------------- init ------------------------------------ #

@app.command(epilog=EXAMPLES["init"])
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

@app.command(epilog=EXAMPLES["host"])
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

@app.command(epilog=EXAMPLES["search"])
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

@app.command(epilog=EXAMPLES["pipeline"])
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
        ("JS c/ sourcemap", len(art.js_with_sourcemap)),
        ("fontes recuperados (sourcemap)", art.sources_recovered),
        ("arquivos interessantes", len(art.interesting)),
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
    if art.interesting:
        err.print(f"[red]★ {len(art.interesting)} arquivo(s)/path(s) interessante(s)[/red] — ver interesting.txt")
        for u in art.interesting[:8]:
            err.print(f"  [red]{escape(u)}[/red]")
    if art.secrets:
        err.print(f"[red]⚠ {len(art.secrets)} possível(is) segredo(s)[/red] — ver secrets.txt")
    if stages:
        for s in stages:
            tag = "[green]ok[/green]" if s.ran and s.returncode == 0 else f"[yellow]{escape(s.note or 'rc='+str(s.returncode))}[/yellow]"
            console.print(f"  chain {escape(s.name)}: {tag}")


@app.command(epilog=EXAMPLES["crawl"])
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
    field_scope: str = typer.Option("auto", "--field-scope", help="escopo do katana: auto|rdn|fqdn|dn (-fs). 'auto' deriva regex do escopo autorizado (não vaza p/ irmãos fora de escopo)."),
    js: bool = typer.Option(True, "--js/--no-js", help="parsing de endpoints em JS (-jc)."),
    known_files: bool = typer.Option(True, "--known-files/--no-known-files", help="known-files (-kf all)."),
    headless: bool = typer.Option(False, "--headless", help="crawl headless (-hl -nos -sc -xhr); lento."),
    header: Optional[list[str]] = typer.Option(None, "-H", "--header", help="header/cookie extra (repetível)."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="proxy HTTP/SOCKS5 (-proxy)."),
    extra: Optional[str] = typer.Option(None, "--extra", help="args katana crus (word-split)."),
    store_responses: bool = typer.Option(True, "--store-responses/--no-store-responses", help="salvar respostas brutas."),
    follow_redirects: bool = typer.Option(False, "--follow-redirects/--no-follow-redirects", help="deixar o katana seguir redirects (default NÃO: -dr, evita GET real em host fora de escopo)."),
    scope_file: Optional[Path] = typer.Option(None, help="Arquivo de escopo específico."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="OVERRIDE do scope-gating."),
    do_diff: bool = typer.Option(True, "--diff/--no-diff", help="diff vs run anterior (latest)."),
    scan_secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="varre bodies por segredos."),
    sourcemaps: bool = typer.Option(True, "--sourcemaps/--no-sourcemaps", help="baixa .map de JS in-scope e recupera o fonte (ATIVO, gated)."),
    chain: bool = typer.Option(False, "--chain", help="encadeia httpx-toolkit -> nuclei nos achados."),
    do_httpx: bool = typer.Option(False, "--httpx", help="probe httpx-toolkit em all-urls (-> live.txt)."),
    severity: str = typer.Option("low,medium,high,critical", help="severidades do nuclei (no --chain)."),
    stage_timeout: int = typer.Option(1800, "--stage-timeout", help="timeout por estágio httpx/nuclei do chain (s)."),
    dry_run: bool = typer.Option(False, help="mostra o comando do katana sem executar."),
):
    """Crawl ATIVO com katana: URLs/JS/params/subs + forms/segredos/API, diff vs run anterior e encadeamento (gated por scope)."""
    if field_scope not in crawl_cmd.FIELD_SCOPES:
        _die(f"--field-scope inválido '{field_scope}' (use auto|rdn|fqdn|dn).")
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

    # 'auto' -> regex host-anchored derivado do escopo autorizado; senão keyword crua.
    resolved_fs = crawl_cmd.derive_field_scope(host, hit) if field_scope == "auto" else field_scope
    out_scope = crawl_cmd.derive_out_scope(entries)   # -cos a partir do deny (pode ser vazio)

    opt = crawl_cmd.CrawlOptions(
        depth=depth, rate=rate, host_rate=host_rate, concurrency=concurrency,
        parallelism=parallelism, timeout=timeout_s, retry=retry, delay=delay,
        duration=duration, field_scope=resolved_fs, crawl_out_scope=out_scope,
        disable_redirects=not follow_redirects, js=js, known_files=known_files,
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
    # sourcemaps: baixa .map de JS IN-SCOPE e recupera o fonte original (mais rico p/
    # minerar endpoints/segredos que o bundle minificado). ATIVO -> gated por scope.
    if sourcemaps:
        sm = crawl_cmd.harvest_sourcemaps(art, run_dir, entries, host, i_am_authorized, scan_secrets)
        if sm.get("fetched"):
            console.print(
                f"[dim]sourcemaps: {sm['fetched']}/{sm['candidates']} baixados, "
                f"{sm['recovered_sources']} fontes recuperados"
                + (" (limite atingido)" if sm.get("capped") else "") + "[/dim]"
            )
    crawl_cmd.write_artifacts(art, run_dir)
    diff = crawl_cmd.compute_diff(run_dir, prev_dir) if do_diff else {}

    # BLINDAGEM: só URLs em escopo podem ser probadas; hosts externos descobertos
    # (JS de terceiros, redirects, etc.) vão p/ external-hosts.txt e NUNCA são tocados.
    inscope_urls, external_hosts = crawl_cmd.scope_partition(art, entries, host, i_am_authorized)
    crawl_cmd.write_scope_split(run_dir, inscope_urls, external_hosts)
    crawl_cmd.write_js_inventory(run_dir, art, external_hosts)
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

@app.command(epilog=EXAMPLES["subs"])
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


# --------------------------------- urls ------------------------------------ #

@app.command(epilog=EXAMPLES["urls"])
def urls(
    domain: str = typer.Argument(..., help="Domínio/host raiz (ex: example.com)."),
    subs: bool = typer.Option(True, "--subs/--no-subs", help="Inclui subdomínios (matchType=domain) vs. só o host."),
    wayback: bool = typer.Option(True, "--wayback/--no-wayback", help="Fonte Wayback Machine (CDX)."),
    gau: bool = typer.Option(True, "--gau/--no-gau", help="Fonte gau, se instalado."),
    limit: Optional[int] = typer.Option(None, "--limit", help="Teto de URLs da Wayback (0/omitido = sem teto)."),
    status_ok: bool = typer.Option(False, "--status-ok", help="Só URLs com HTTP 200 no arquivo (Wayback)."),
    wayback_timeout: float = typer.Option(30.0, help="Timeout da Wayback (s)."),
    gau_timeout: int = typer.Option(180, help="Timeout do gau (s)."),
    scope_file: Optional[Path] = typer.Option(None, help="Escopo específico p/ anotar in/out."),
    save: bool = typer.Option(True, help="Salva urls-*.txt/params.txt/urls.md em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Recon histórico PASSIVO (Wayback + gau): URLs conhecidas + inventário de params. Anota in/out de escopo, não bloqueia."""
    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())

    if not wayback and not gau:
        _die("nada a fazer: --no-wayback e --no-gau desligam todas as fontes.", code=2)

    try:
        result = archive_mod.collect(
            domain, entries, use_wayback=wayback, use_gau=gau, include_subs=subs,
            limit=limit, status_ok_only=status_ok, wayback_timeout=wayback_timeout,
            gau_timeout=gau_timeout,
        )
    except ValueError as e:
        _die(str(e), code=2)

    if not result.urls and result.errors:
        _die("; ".join(f"{s}: {m}" for s, m in result.errors))

    if as_json:
        payload = {
            "domain": result.domain, "sources": result.sources,
            "counts": {"urls": len(result.urls), "in_scope": len(result.in_scope),
                       "out_scope": len(result.out_scope), "with_params": len(result.with_params),
                       "api": len(result.api), "interesting": len(result.interesting),
                       "params": len(result.params)},
            "params": {n: {"count": s.count, "example": s.example}
                       for n, s in result.params.items()},
            "in_scope": result.in_scope, "api": result.api, "interesting": result.interesting,
            "errors": [{"source": s, "msg": m} for s, m in result.errors],
        }
        console.print_json(report.json.dumps(payload))
    else:
        report.print_urls(result)

    if save and result.urls:
        outdir = output_dir(config.reports_dir(), f"urls-{result.domain}")
        report.write_urls_files(result, outdir)
        console.print(f"[dim]salvo em {outdir}[/dim]  "
                      f"[dim](in-scope.txt alimenta: srecon pipeline --from-file in-scope.txt)[/dim]")


# -------------------------------- assets ----------------------------------- #

@app.command(epilog=EXAMPLES["assets"])
def assets(
    domain: str = typer.Argument(..., help="Domínio/host raiz (ex: example.com)."),
    ct: bool = typer.Option(True, "--ct/--no-ct", help="Certificate Transparency (crt.sh)."),
    asn: bool = typer.Option(True, "--asn/--no-asn", help="ASN/netblock via bgpview (resolve o IP)."),
    shodan: bool = typer.Option(False, "--shodan", help="Pivot por favicon no Shodan (OPT-IN, gasta credit)."),
    favicon_url: Optional[str] = typer.Option(None, "--favicon-url", help="URL do favicon (default https://DOMÍNIO/favicon.ico)."),
    favicon_hash: Optional[int] = typer.Option(None, "--favicon-hash", help="Hash mmh3 já conhecido (pivot puro-passivo, não baixa o favicon)."),
    timeout: float = typer.Option(30.0, help="Timeout por fonte (s)."),
    scope_file: Optional[Path] = typer.Option(None, help="Escopo específico p/ anotar in/out."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="OVERRIDE p/ baixar favicon de host fora de escopo."),
    save: bool = typer.Option(True, help="Salva ct-hosts.txt/in-scope.txt/assets.md em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Ativos interligados ao alvo: CT (crt.sh) + ASN/netblock (grátis, passivo). --shodan pivota por favicon (opt-in). Anota in/out de escopo, não bloqueia."""
    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())

    host = crawl_cmd.extract_host(domain) or domain
    target_ip = None
    if asn:
        try:
            target_ip = host_cmd.resolve_target_ip(host)   # DNS passivo
        except ValueError as e:
            err.print(f"[yellow]sem ASN: {escape(str(e))}[/yellow]")

    try:
        result = assets_mod.collect(domain, entries, target_ip=target_ip,
                                    do_ct=ct, do_asn=asn, timeout=timeout)
    except ValueError as e:
        _die(str(e), code=2)

    # pivot favicon->Shodan (opt-in). Baixar o favicon é ATIVO -> gate por escopo.
    if shodan:
        fhash = favicon_hash
        if fhash is None:
            in_scope = scopemod.match(host, entries) is not None
            if not in_scope and not i_am_authorized:
                err.print(f"[yellow]favicon não baixado: '{escape(host)}' fora de escopo. "
                          "Use --favicon-hash N (passivo) ou --i-am-authorized.[/yellow]")
            else:
                furl = favicon_url or f"https://{host}/favicon.ico"
                data = assets_mod.fetch_favicon_bytes(furl, timeout=int(timeout))
                if not data:
                    err.print(f"[yellow]não consegui baixar o favicon em {escape(furl)}.[/yellow]")
                else:
                    fhash = assets_mod.favicon_hash(data)
        if fhash is not None:
            try:
                client = _client()
                result.favicon = assets_mod.shodan_favicon_pivot(client, fhash)
            except (ShodanClientError, ValueError) as e:
                result.errors.append(("shodan", str(e)))

    if not result.ct_hosts and not result.asn and not result.favicon and result.errors:
        _die("; ".join(f"{s}: {m}" for s, m in result.errors))

    if as_json:
        payload = {
            "domain": result.domain,
            "asn": result.asn.__dict__ if result.asn else None,
            "counts": {"ct_hosts": len(result.ct_hosts), "in_scope": len(result.in_scope),
                       "out_scope": len(result.out_scope)},
            "ct_hosts": result.ct_hosts, "in_scope": result.in_scope,
            "favicon": result.favicon or None,
            "errors": [{"source": s, "msg": m} for s, m in result.errors],
        }
        console.print_json(report.json.dumps(payload))
    else:
        report.print_assets(result)

    if save and (result.ct_hosts or result.asn or result.favicon):
        outdir = output_dir(config.reports_dir(), f"assets-{result.domain}")
        report.write_assets_files(result, outdir)
        console.print(f"[dim]salvo em {outdir}[/dim]  "
                      f"[dim](in-scope.txt alimenta: srecon subs / pipeline --from-file)[/dim]")


# ------------------------------ candidates --------------------------------- #

def _latest_report_dir(base: Path, target: str) -> Optional[Path]:
    """Diretório de run mais recente em reports/<slug>/ (usa 'latest' se houver)."""
    parent = base / slugify(target)
    latest = parent / "latest"
    if latest.is_dir():
        return latest
    if not parent.is_dir():
        return None
    subs = sorted(d for d in parent.iterdir() if d.is_dir() and d.name != "latest")
    return subs[-1] if subs else None


def _load_url_lines(path: Path) -> list[str]:
    try:
        return [ln.strip() for ln in path.read_text(errors="ignore").splitlines() if ln.strip()]
    except OSError:
        return []


@app.command(epilog=EXAMPLES["candidates"])
def candidates(
    domain: Optional[str] = typer.Argument(None, help="Domínio: usa o último 'srecon urls <domínio>'."),
    from_file: Optional[Path] = typer.Option(None, "--from-file", help="Arquivo de URLs (uma por linha) em vez do último run."),
    takeover_hosts: Optional[Path] = typer.Option(None, "--takeover-hosts", help="Arquivo de hosts p/ checar subdomain takeover (CNAME->fingerprint)."),
    min_confidence: int = typer.Option(40, "--min-confidence", help="Confiança mínima p/ listar um candidato (0-100)."),
    active: bool = typer.Option(False, "--active", help="PROVA ativa (payload benigno) — só hosts em escopo, gated."),
    timeout: int = typer.Option(12, help="Timeout por sonda ativa (s)."),
    scope_file: Optional[Path] = typer.Option(None, help="Escopo específico."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="OVERRIDE do scope-gate na prova ativa."),
    save: bool = typer.Option(True, help="Salva candidates.json/.md em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Hipótese de bug: classifica candidatos por param (SSRF/redirect/IDOR/XSS/LFI/SQLi) + subdomain takeover, rankeados. Passivo; --active prova em escopo."""
    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())

    # fonte de URLs
    urls: list[str] = []
    if from_file:
        urls = _load_url_lines(from_file)
        if not urls:
            _die(f"nenhuma URL em {from_file}.", code=2)
    elif domain:
        rd = _latest_report_dir(config.reports_dir(), f"urls-{domain}")
        if not rd:
            _die(f"nenhum run de 'srecon urls {domain}' encontrado. Rode-o antes ou use --from-file.", code=2)
        urls = _load_url_lines(rd / "urls-all.txt")

    cands = cand_mod.classify_urls(urls, min_confidence=min_confidence) if urls else []

    # subdomain takeover (CNAME -> fingerprint)
    if takeover_hosts:
        hosts = _load_url_lines(takeover_hosts)
        cmap = cand_mod.resolve_cnames(hosts)
        if not cmap and hosts:
            err.print("[yellow]dnsx ausente ou sem CNAMEs — takeover pulado.[/yellow]")
        for h, cname in cmap.items():
            c = cand_mod.assess_takeover(h, cname)
            if c:
                cands.append(c)

    # prova ATIVA (opt-in), só em escopo
    if active:
        _run_active_probes(cands, entries, i_am_authorized, timeout)

    cands.sort(key=lambda c: c.sort_key())

    if as_json:
        payload = [{"class": c.vuln_class, "severity": c.severity, "param": c.param,
                    "confidence": c.confidence, "example": c.example, "reason": c.reason,
                    "evidence": c.evidence} for c in cands]
        console.print_json(report.json.dumps(payload))
    else:
        report.print_candidates(cands, active=active)

    if save and cands:
        tgt = domain or (from_file.stem if from_file else "candidates")
        outdir = output_dir(config.reports_dir(), f"candidates-{tgt}")
        report.write_candidates_files(cands, outdir)
        console.print(f"[dim]salvo em {outdir}[/dim]")


def _run_active_probes(cands, entries, i_am_authorized: bool, timeout: int) -> None:
    """Roda a sonda benigna adequada a cada candidato cujo host está em escopo."""
    probed = 0
    skipped = 0
    for c in cands:
        host = crawl_cmd.extract_host(c.example) or c.example
        in_scope = scopemod.match(host, entries) is not None
        if not in_scope and not i_am_authorized:
            skipped += 1
            continue
        cls = c.vuln_class
        if cls == "open_redirect":
            c.evidence.update(cand_mod.probe_open_redirect(c.example, c.param, timeout))
        elif cls == "ssrf":
            # SSRF cego não confirma por corpo; reusa redirect como sinal de que o param
            # controla destino (Location aponta pro canário) — indício, não prova de SSRF.
            c.evidence.update(cand_mod.probe_open_redirect(c.example, c.param, timeout))
        elif cls == "xss":
            c.evidence.update(cand_mod.probe_reflection(c.example, c.param, timeout))
        elif cls == "subdomain_takeover":
            body = cand_mod.fetch_body(f"https://{c.example}/", timeout)
            fp = cand_mod.match_cname_service(c.evidence.get("cname", ""))
            if fp is not None:
                verified = cand_mod.body_indicates_takeover(fp, body or "")
                c.evidence["verified"] = verified
                c.confidence = 95 if verified else 25
        else:
            continue
        # endpoint-level: GraphQL introspection e CORS quando a URL tem cara de API
        low = c.example.lower()
        if "/graphql" in low:
            gq = cand_mod.probe_graphql(c.example, timeout)
            c.evidence["graphql"] = gq
            if gq.get("verified"):
                c.evidence["verified"] = True
        if any(m in low for m in ("/api/", "/api?", "/graphql", "/rest/", ".json")):
            cors = cand_mod.probe_cors(c.example, timeout)
            c.evidence["cors"] = cors
            if cors.get("exploitable"):
                c.evidence["verified"] = True
        if c.evidence.get("verified"):
            c.confidence = max(c.confidence, 90)
        probed += 1
    if skipped:
        err.print(f"[yellow]prova ativa: {skipped} candidato(s) fora de escopo pulado(s) "
                  "(use --i-am-authorized p/ forçar).[/yellow]")


# -------------------------------- triage ----------------------------------- #

def _read_json(path: Path):
    try:
        return report.json.loads(path.read_text(errors="ignore"))
    except (OSError, ValueError):
        return None


@app.command(epilog=EXAMPLES["triage"])
def triage(
    domain: str = typer.Argument(..., help="Domínio/alvo: consolida os relatórios já gerados p/ ele."),
    save: bool = typer.Option(True, help="Salva triage.json/.md em reports/."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Triagem: consolida candidates + CVEs (host) + urls + assets num ranking único por impacto."""
    base = config.reports_dir()
    leads: list = []
    used: list[str] = []

    # candidatos de bug / takeover
    cdir = _latest_report_dir(base, f"candidates-{domain}")
    if cdir:
        data = _read_json(cdir / "candidates.json")
        if data is not None:
            leads += triage_mod.leads_from_candidates(data)
            used.append("candidates")

    # CVEs do host intel (reports/<slug>/<stamp>/host.json)
    hdir = _latest_report_dir(base, domain)
    if hdir:
        hj = _read_json(hdir / "host.json")
        if hj is not None:
            leads += triage_mod.leads_from_host(hj)
            used.append("host")

    # superfície: arquivos/endpoints interessantes do urls
    udir = _latest_report_dir(base, f"urls-{domain}")
    if udir:
        interesting = _load_url_lines(udir / "interesting.txt")
        leads += triage_mod.leads_from_urls_interesting(interesting)
        if interesting:
            used.append("urls")

    # ativos fora de escopo (assets) — leads p/ pedir expansão de escopo
    adir = _latest_report_dir(base, f"assets-{domain}")
    if adir:
        outs = _load_url_lines(adir / "out-scope.txt")
        leads += triage_mod.leads_from_assets_outscope(outs)
        if outs:
            used.append("assets")

    if not leads:
        _die(f"nenhum artefato encontrado p/ '{domain}' em {base}. "
             "Rode urls/candidates/host/assets antes.", code=2)

    ranked = triage_mod.rank(leads)
    summary = triage_mod.summarize(ranked)
    summary["sources"] = used

    if as_json:
        payload = {"summary": summary,
                   "leads": [{"rank": i, "category": l.category, "title": l.title,
                              "severity": l.severity, "score": l.score,
                              "verified": l.verified, "source": l.source, "detail": l.detail}
                             for i, l in enumerate(ranked, 1)]}
        console.print_json(report.json.dumps(payload))
    else:
        console.print(f"[dim]fontes: {', '.join(used)}[/dim]")
        report.print_triage(ranked, summary)

    if save:
        outdir = output_dir(base, f"triage-{domain}")
        report.write_triage_files(ranked, summary, outdir)
        console.print(f"[dim]salvo em {outdir}[/dim]")


# --------------------------------- cve ------------------------------------- #

@app.command(epilog=EXAMPLES["cve"])
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

@app.command(epilog=EXAMPLES["vulns"])
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

@app.command(epilog=EXAMPLES["msf"])
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


# --------------------------------- fuzz ------------------------------------ #

@app.command(epilog=EXAMPLES["fuzz"])
def fuzz(
    target: str = typer.Argument(..., help="IP/domínio/URL alvo (ATIVO — gated por scope)."),
    files: bool = typer.Option(False, "--files", help="Modo 'arquivos interessantes' (lista curada) em vez de diretórios."),
    wordlist: Optional[Path] = typer.Option(None, "-w", "--wordlist", help="Wordlist custom (default: seclists/dirb ou $SRECON_WORDLIST)."),
    extensions: str = typer.Option("", "-e", "--extensions", help="Extensões a anexar, ex: .php,.bak,.zip,.old."),
    match_codes: str = typer.Option("200,204,301,302,307,401,403,405,500", "--mc", help="Status a considerar 'achado'."),
    threads: int = typer.Option(40, "-t", "--threads", help="Threads do ffuf."),
    rate: int = typer.Option(0, "--rate", help="req/s (0 = sem limite do ffuf)."),
    timeout_req: int = typer.Option(10, "--timeout", help="Timeout por request (s)."),
    max_time: int = typer.Option(900, "--max-time", help="Tempo máx total do ffuf/httpx (s)."),
    no_probe: bool = typer.Option(False, "--no-probe", help="Não re-probar achados com httpx (fica sem tech/título)."),
    scope_file: Optional[Path] = typer.Option(None, help="Arquivo de escopo específico."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="OVERRIDE do scope-gating."),
    save: bool = typer.Option(True, help="Salva found.txt/interesting.txt/tech.txt + fuzz.md."),
    as_json: bool = typer.Option(False, "--json", help="Imprime JSON cru."),
):
    """Descoberta de conteúdo: diretórios, arquivos interessantes e tecnologias (ffuf→httpx). ATIVO, gated por scope."""
    host = crawl_cmd.extract_host(target) or target
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
            f"'{host}' não autorizado. fuzz é ativo e exige scope em {config.scope_dir()} "
            "(Regra de ouro). Use --scope-file ou --i-am-authorized se tiver autorização escrita.",
            code=3,
        )
    if i_am_authorized and not hit:
        err.print("[yellow]OVERRIDE ativo (--i-am-authorized): scope-gating ignorado.[/yellow]")

    if not fuzz_cmd.resolve_bin("ffuf"):
        _die("ffuf não encontrado (PATH nem ~/go/bin).", code=127)

    outdir = output_dir(config.reports_dir(), f"fuzz-{host}")
    scope_src = str(hit.source) if hit else "OVERRIDE (--i-am-authorized)"
    console.print(f"[bold]fuzz[/bold] de [cyan]{escape(fuzz_cmd.base_url(target))}[/cyan] "
                  f"({'arquivos' if files else 'diretórios'}, scope: {escape(scope_src)})")

    res = fuzz_cmd.run(
        target, outdir, files_mode=files,
        wordlist=str(wordlist) if wordlist else None, extensions=extensions,
        match_codes=match_codes, threads=threads, rate=rate,
        timeout_req=timeout_req, ffuf_timeout=max_time, probe=not no_probe,
    )
    if res.ffuf_rc == fuzz_cmd.RC_NO_WORDLIST:
        _die("nenhuma wordlist encontrada. Instale seclists ou passe -w/--wordlist (ou $SRECON_WORDLIST).", code=2)
    if res.ffuf_rc == fuzz_cmd.RC_NO_FFUF:
        _die("ffuf indisponível.", code=127)

    if res.wildcard:
        w = res.wildcard
        err.print(f"[yellow]⚠ resposta uniforme (provável WAF/wildcard): {w['dropped']} hits "
                  f"status {w['status']} tam {w['length']} descartados "
                  f"({int(w['fraction'] * 100)}%). Ajuste --mc ou revise o alvo.[/yellow]")

    if as_json:
        import json as _json
        console.print_json(_json.dumps({
            "target": res.target, "base_url": res.base_url, "mode": res.mode,
            "wildcard": res.wildcard,
            "wordlist": res.wordlist, "hits": res.hits,
            "tech": [{"tech": t, "count": c} for t, c in res.tech],
            "interesting": [h.get("url") for h in res.interesting],
        }))
    else:
        report.print_fuzz(res)

    if save:
        fuzz_cmd.write_artifacts(res, outdir)
        report.write_fuzz_md(res, outdir / "fuzz.md")
        console.print(f"[dim]salvo em {outdir}[/dim]")


# ------------------------------ scope-check -------------------------------- #

@app.command("scope-check", epilog=EXAMPLES["scope-check"])
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
    elif scopemod.is_denied(target, entries):
        # negado explicitamente por regra de exclusão — pior que 'não listado':
        # em BB significa 'proibido', ainda que um allow wildcard/CIDR o cubra.
        err.print(f"[red]NEGADO[/red] — {escape(target)} bate em regra de EXCLUSÃO (fora de escopo por decisão explícita).")
        raise typer.Exit(code=3)
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

    # furo HIGH #1: deny prevalece sobre allow wildcard, e is_denied reporta certo
    denywc = scopemod.parse_scope_text(
        "*.example.com\n# Out of scope:\nadmin.example.com", Path("dw.txt"))
    checks.append(("scope deny over wildcard",
                   scopemod.match("admin.example.com", [denywc]) is None, "deny > allow wildcard"))
    checks.append(("scope wildcard still allows",
                   scopemod.match("api.example.com", [denywc]) is not None, ""))
    checks.append(("scope is_denied flags exclusion",
                   scopemod.is_denied("admin.example.com", [denywc]) is True, ""))

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


# --------------------------------- auto ------------------------------------ #

@app.command(epilog=EXAMPLES["auto"])
def auto(
    target: str = typer.Argument(..., help="IP/domínio/URL — roda o recon COMPLETO."),
    passive_only: bool = typer.Option(False, "--passive-only", help="Só passivo; não envia tráfego ao alvo."),
    scope_file: Optional[Path] = typer.Option(None, help="Arquivo de escopo específico."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="OVERRIDE do scope-gating no estágio ativo."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Mostra o plano e NÃO executa nada."),
    severity: str = typer.Option("low,medium,high,critical", help="Severidades do nuclei (estágio ativo)."),
    stage_timeout: int = typer.Option(1800, help="Timeout por estágio ativo (s)."),
):
    """Auto: só o alvo -> recon completo. Passivo sempre; ATIVO (crawl/fuzz/pipeline)
    só se o alvo estiver autorizado por scope (Regra de ouro). É o destino de
    'srecon <alvo>' sem subcomando."""
    thost = crawl_cmd.extract_host(target) or target
    is_ip = auto_cmd.looks_like_ip(thost)

    if scope_file:
        try:
            entries = [scopemod.load_scope_file(scope_file)]
        except ValueError as e:
            _die(str(e), code=2)
    else:
        entries = scopemod.load_scopes(config.scope_dir())
    hit = scopemod.match(thost, entries)
    in_scope = bool(hit) or i_am_authorized

    has_key = True
    try:
        config.resolve_api_key()
    except config.ConfigError:
        has_key = False
    have_subfinder = bool(subs_cmd.resolve_bin("subfinder"))
    have_ffuf = bool(fuzz_cmd.resolve_bin("ffuf"))

    console.print(f"[bold]auto[/bold] — recon completo de "
                  f"[cyan]{escape(crawl_cmd.strip_userinfo(target))}[/cyan] "
                  f"({'IP' if is_ip else 'domínio'})")
    if hit:
        console.print(f"escopo: [green]AUTORIZADO[/green] por {escape(str(hit.source))}")
    elif i_am_authorized:
        console.print("escopo: [yellow]OVERRIDE (--i-am-authorized)[/yellow]")
    else:
        console.print("escopo: [red]FORA DE ESCOPO[/red] — estágio ativo será pulado")

    # ------------------------------- plano --------------------------------- #
    plan: list = []
    if not is_ip:
        plan.append("subs (passivo)" + ("" if have_subfinder else "  [dim]subfinder ausente → pula[/dim]"))
    plan.append("host + CVEs (passivo, Shodan)" + ("" if has_key else "  [dim]sem API key → pula[/dim]"))
    plan.append("vulns/msf (offline)")
    if passive_only:
        plan.append("[dim](ativo desligado: --passive-only)[/dim]")
    elif not in_scope:
        plan.append("[dim](ativo pulado: fora de escopo)[/dim]")
    else:
        plan.append("crawl (ATIVO)")
        plan.append("fuzz (ATIVO)" + ("" if have_ffuf else "  [dim]ffuf ausente → pula[/dim]"))
        plan.append("pipeline (ATIVO)")
    console.print("\n[bold]plano:[/bold]")
    for i, p in enumerate(plan, 1):
        console.print(f"  {i}. {p}")

    if dry_run:
        console.print("\n[yellow]dry-run — nada executado.[/yellow]")
        return

    def step(title, fn, **kw):
        console.print(f"\n[bold cyan]▶ {title}[/bold cyan]")
        try:
            _invoke(fn, **kw)
        except typer.Exit as e:
            code = getattr(e, "exit_code", getattr(e, "code", "?"))
            err.print(f"[yellow]{escape(title)}: interrompido (exit {code}).[/yellow]")
        except KeyboardInterrupt:
            raise
        except Exception as e:  # um passo que falha não derruba o recon inteiro
            err.print(f"[yellow]{escape(title)}: falhou — {escape(str(e))}[/yellow]")

    # ------------------------------ passivo -------------------------------- #
    if not is_ip and have_subfinder:
        step("subs (passivo)", subs, domain=thost, scope_file=scope_file)
    if has_key:
        step("host + CVEs (passivo, Shodan)", host, target=target)
    else:
        err.print("[yellow]sem API key do Shodan — pulando host. Rode 'srecon init'.[/yellow]")
    step("vulns/msf (offline)", vulns, enrich=True, with_msf=True)

    # --------------------------- ativo (gated) ----------------------------- #
    if passive_only:
        console.print("\n[dim]--passive-only: estágio ativo desligado.[/dim]")
    elif not in_scope:
        err.print(f"\n[yellow]ATIVO pulado — '{escape(thost)}' fora de escopo. "
                  "Adicione em scope/*.txt ou use --i-am-authorized (autorização escrita).[/yellow]")
    else:
        step("crawl (ativo)", crawl, target=target, scope_file=scope_file,
             i_am_authorized=i_am_authorized)
        if have_ffuf:
            step("fuzz (ativo)", fuzz, target=target, scope_file=scope_file,
                 i_am_authorized=i_am_authorized)
        step("pipeline (ativo)", pipeline, target=target, scope_file=scope_file,
             i_am_authorized=i_am_authorized, severity=severity, timeout=stage_timeout)

    console.print("\n[green]✓ auto concluído.[/green]")


def main():
    # 'srecon <alvo>' (1º token não é subcomando conhecido) -> 'srecon auto <alvo>'.
    known = set(typer.main.get_command(app).commands)
    sys.argv[1:] = auto_cmd.route_argv(sys.argv[1:], known)
    try:
        app()
    except KeyboardInterrupt:
        err.print("[yellow]interrompido[/yellow]")
        raise SystemExit(130)
    except Exception as e:  # último recurso: erro limpo, sem traceback/locals
        # escape(): a mensagem pode conter '[...]' vindo do alvo e quebrar o markup do rich
        err.print(f"[red]erro inesperado: {escape(type(e).__name__)}: {escape(str(e))}[/red]")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
