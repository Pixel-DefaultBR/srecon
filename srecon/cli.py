from __future__ import annotations

import getpass
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

from . import config, report
from . import scope as scopemod
from .commands import host as host_cmd
from .commands import pipeline as pipeline_cmd
from .commands import search as search_cmd
from .shodan_client import ShodanClient, ShodanClientError
from .util import output_dir, slugify

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
    if not (target or from_host or from_search):
        _die("informe um alvo: TARGET, --from-host ou --from-search.")

    requested = _split(stages)
    invalid = [s for s in requested if s not in pipeline_cmd.VALID_STAGES]
    if invalid:
        _die(f"estágios inválidos: {invalid}. Válidos: {pipeline_cmd.VALID_STAGES}")

    client = _client()
    try:
        hosts = pipeline_cmd.gather_targets(client, target, from_host, from_search, search_limit)
    except ShodanClientError as e:
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

    label = target or from_host or (from_search or "pipeline")
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
