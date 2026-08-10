from __future__ import annotations

import csv
import json
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .models import HostReport, PlanInfo, SearchResult

console = Console()


def _s(x) -> str:
    """String segura p/ markup Rich — dados vindos do Shodan são NÃO confiáveis."""
    if x is None or x == "":
        return "-"
    return escape(str(x))


# ----------------------------- terminal ------------------------------------ #

def print_plan(info: PlanInfo) -> None:
    def n(x):
        return str(x) if x is not None else "-"

    t = Table(title="Shodan — plano & créditos", box=box.SIMPLE_HEAVY)
    t.add_column("campo", style="cyan")
    t.add_column("valor", style="white")
    t.add_row("plano", _s(info.plan))
    t.add_row("query credits", n(info.query_credits))
    t.add_row("scan credits", n(info.scan_credits))
    t.add_row("monitored IPs", n(info.monitored_ips))
    t.add_row("https / telnet", f"{n(info.https)} / {n(info.telnet)}")
    console.print(t)


def print_host(report: HostReport) -> None:
    head = Table(box=box.SIMPLE, show_header=False)
    head.add_column("k", style="cyan")
    head.add_column("v")
    head.add_row("IP", _s(report.ip))
    head.add_row("hostnames", _s(", ".join(report.hostnames)) if report.hostnames else "-")
    head.add_row("org / isp", f"{_s(report.org)} / {_s(report.isp)}")
    head.add_row("asn", _s(report.asn))
    head.add_row("local", f"{_s(report.city)}, {_s(report.country)}")
    head.add_row("os", _s(report.os))
    head.add_row("tags", _s(", ".join(report.tags)) if report.tags else "-")
    head.add_row("portas", " ".join(str(p) for p in report.ports) or "-")
    head.add_row("vulns", f"[red]{len(report.vulns)}[/red]" if report.vulns else "0")
    console.print(head)

    if report.services:
        st = Table(title="serviços", box=box.MINIMAL_DOUBLE_HEAD)
        for c in ("porta", "produto", "versão", "módulo", "vulns"):
            st.add_column(c)
        for s in report.services:
            st.add_row(
                f"{s.port}/{_s(s.transport)}", _s(s.product), _s(s.version),
                _s(s.module), f"[red]{len(s.vulns)}[/red]" if s.vulns else "0",
            )
        console.print(st)

    if report.vulns:
        vt = Table(title="vulnerabilidades", box=box.MINIMAL_DOUBLE_HEAD)
        vt.add_column("CVE", style="red")
        vt.add_column("CVSS")
        vt.add_column("verif")
        vt.add_column("resumo")
        for v in report.vulns[:60]:
            vt.add_row(
                _s(v.cve),
                f"{v.cvss:.1f}" if v.cvss is not None else "-",
                "✓" if v.verified else "",
                _s((v.summary or "")[:80]),
            )
        if len(report.vulns) > 60:
            vt.add_row("...", "", "", f"(+{len(report.vulns) - 60} outras)")
        console.print(vt)


def print_search(result: SearchResult, fields: list[str]) -> None:
    console.print(
        f"[bold]{result.total}[/bold] resultados p/ [cyan]{_s(result.query)}[/cyan] "
        f"(mostrando {len(result.matches)})"
    )
    if result.matches:
        t = Table(box=box.MINIMAL_DOUBLE_HEAD)
        for f in fields:
            t.add_column(f)
        for m in result.matches:
            d = m.model_dump()
            row = []
            for f in fields:
                val = d.get(f)
                if isinstance(val, list):
                    val = ",".join(str(x) for x in val)
                row.append(_s(val))
            t.add_row(*row)
        console.print(t)
    for name, items in result.facets.items():
        ft = Table(title=f"facet: {_s(name)}", box=box.SIMPLE)
        ft.add_column("valor")
        ft.add_column("count", justify="right")
        for it in items:
            ft.add_row(_s(it.value), str(it.count))
        console.print(ft)


def print_fuzz(res) -> None:
    console.print(
        f"[bold]fuzz[/bold] [cyan]{_s(res.base_url)}[/cyan] "
        f"({res.mode}) — [green]{len(res.hits)}[/green] achado(s), "
        f"[red]{len(res.interesting)}[/red] interessante(s)"
    )
    if res.hits:
        t = Table(box=box.MINIMAL_DOUBLE_HEAD)
        for c in ("status", "tam", "url", "tech / título"):
            t.add_column(c)
        for h in res.hits[:120]:
            extra = ", ".join(h.get("tech") or []) or _s(h.get("title"))
            url = h.get("url") or "-"
            mark = "[red]★[/red] " if h.get("interesting") else ""
            t.add_row(str(h.get("status") or "-"), str(h.get("length") or "-"),
                      mark + _s(url), _s(extra))
        console.print(t)
        if len(res.hits) > 120:
            console.print(f"[dim]… (+{len(res.hits) - 120}) — ver found.txt[/dim]")

    if res.interesting:
        console.print(f"[red]★ {len(res.interesting)} arquivo(s)/path(s) interessante(s):[/red]")
        for h in res.interesting[:40]:
            console.print(f"  [red]{h.get('status')}[/red] {_s(h.get('url'))}")

    if res.tech:
        tt = Table(title="tecnologias detectadas", box=box.SIMPLE)
        tt.add_column("tech")
        tt.add_column("hosts/paths", justify="right")
        for name, n in res.tech[:30]:
            tt.add_row(_s(name), str(n))
        console.print(tt)


def write_fuzz_md(res, path: Path) -> None:
    lines = [f"# Fuzz — {res.base_url}", "",
             f"- **modo:** {res.mode}",
             f"- **wordlist:** {res.wordlist or '-'}",
             f"- **achados:** {len(res.hits)}",
             f"- **interessantes:** {len(res.interesting)}", ""]
    if res.tech:
        lines += ["## Tecnologias", "", "| tech | contagem |", "|---|---|"]
        lines += [f"| {_md_cell(t)} | {c} |" for t, c in res.tech]
        lines.append("")
    if res.interesting:
        lines += ["## Interessantes", "", "| status | url |", "|---|---|"]
        lines += [f"| {h.get('status')} | {_md_cell(h.get('url'))} |" for h in res.interesting]
        lines.append("")
    lines += ["## Todos os achados", "", "| status | tam | url | tech |", "|---|---|---|---|"]
    for h in res.hits:
        lines.append(f"| {h.get('status')} | {h.get('length')} | {_md_cell(h.get('url'))} | "
                     f"{_md_cell(', '.join(h.get('tech') or []))} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_subs(result) -> None:
    console.print(
        f"[bold]{len(result.subdomains)}[/bold] subdomínio(s) — "
        f"[green]{len(result.resolved)}[/green] resolvem, "
        f"[cyan]{len(result.in_scope)}[/cyan] em escopo, "
        f"[yellow]{len(result.out_scope)}[/yellow] fora"
    )
    inset = set(result.in_scope)
    rows = result.resolved or [(h, []) for h in result.subdomains]
    if rows:
        t = Table(box=box.MINIMAL_DOUBLE_HEAD)
        t.add_column("host")
        t.add_column("IPs")
        t.add_column("escopo")
        for host, ips in rows[:80]:
            tag = "[cyan]in[/cyan]" if host in inset else "[yellow]out[/yellow]"
            t.add_row(_s(host), _s(", ".join(ips)) if ips else "-", tag)
        console.print(t)
        if len(rows) > 80:
            console.print(f"[dim]… (+{len(rows) - 80}) — ver subs.txt/resolved.txt[/dim]")


def write_subs_files(result, outdir: Path) -> None:
    def _w(name, items):
        (outdir / name).write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
    _w("subs.txt", result.subdomains)
    _w("resolved.txt", [f"{h}\t{','.join(ips)}" for h, ips in result.resolved])
    _w("in-scope.txt", result.in_scope)
    lines = [f"# Subdomínios — {result.domain}", "",
             f"- **total:** {len(result.subdomains)}",
             f"- **resolvem:** {len(result.resolved)}",
             f"- **em escopo:** {len(result.in_scope)}",
             f"- **fora de escopo:** {len(result.out_scope)}", "",
             "## Resolvidos", "", "| host | IPs | escopo |", "|---|---|---|"]
    inset = set(result.in_scope)
    for host, ips in result.resolved:
        lines.append(f"| {_md_cell(host)} | {_md_cell(','.join(ips))} | "
                     f"{'in' if host in inset else 'out'} |")
    (outdir / "subs.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------- urls ------------------------------------ #

def print_urls(result) -> None:
    srcs = ", ".join(f"{k}:{v}" for k, v in result.sources.items()) or "(nenhuma fonte)"
    console.print(
        f"[bold]{len(result.urls)}[/bold] URL(s) únicas — "
        f"[cyan]{len(result.in_scope)}[/cyan] em escopo, "
        f"[yellow]{len(result.out_scope)}[/yellow] fora  "
        f"[dim](fontes: {escape(srcs)})[/dim]"
    )
    console.print(
        f"[green]{len(result.params)}[/green] parâmetro(s) distintos, "
        f"[green]{len(result.with_params)}[/green] URL(s) com query, "
        f"[green]{len(result.api)}[/green] com cara de API, "
        f"[red]{len(result.interesting)}[/red] interessante(s)"
    )
    for src, msg in result.errors:
        console.print(f"[yellow]{_s(src)}: {_s(msg)}[/yellow]")
    top = sorted(result.params.values(), key=lambda p: (-p.count, p.name))[:25]
    if top:
        t = Table(box=box.MINIMAL_DOUBLE_HEAD, title="parâmetros mais vistos")
        t.add_column("param")
        t.add_column("#", justify="right")
        t.add_column("exemplo", overflow="fold")
        for p in top:
            t.add_row(_s(p.name), str(p.count), _s(p.example))
        console.print(t)
        if len(result.params) > 25:
            console.print(f"[dim]… (+{len(result.params) - 25}) — ver params.txt[/dim]")


def write_urls_files(result, outdir: Path) -> None:
    def _w(name, items):
        (outdir / name).write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
    _w("urls-all.txt", result.urls)
    _w("in-scope.txt", result.in_scope)
    _w("out-scope.txt", result.out_scope)
    _w("with-params.txt", result.with_params)
    _w("api.txt", result.api)
    _w("interesting.txt", result.interesting)
    # wordlist de params reais do alvo — alimenta Arjun/ffuf e a classificação (Fase C)
    _w("params.txt", result.param_names)

    lines = [f"# URLs históricas — {result.domain}", "",
             f"- **total únicas:** {len(result.urls)}",
             f"- **em escopo:** {len(result.in_scope)}",
             f"- **fora de escopo:** {len(result.out_scope)}",
             f"- **com parâmetros:** {len(result.with_params)}",
             f"- **API:** {len(result.api)}",
             f"- **interessantes:** {len(result.interesting)}",
             f"- **params distintos:** {len(result.params)}", "",
             "## Parâmetros mais vistos", "", "| param | # | exemplo |", "|---|---|---|"]
    for p in sorted(result.params.values(), key=lambda p: (-p.count, p.name))[:50]:
        lines.append(f"| {_md_cell(p.name)} | {p.count} | {_md_cell(p.example)} |")
    (outdir / "urls.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_cve_details(details, errors) -> None:
    for d in details:
        flags = []
        if d.kev:
            flags.append("[red]KEV[/red]")
        if d.ransomware_campaign and d.ransomware_campaign.lower() != "unknown":
            flags.append(f"[red]ransomware:{escape(d.ransomware_campaign)}[/red]")
        cvss = d.cvss_v3 if d.cvss_v3 is not None else d.cvss
        epss = f"{d.epss * 100:.1f}%" if d.epss is not None else "-"
        head = Table(box=box.SIMPLE, show_header=False)
        head.add_column("k", style="cyan")
        head.add_column("v")
        head.add_row("CVE", f"[bold]{_s(d.cve_id)}[/bold] {'  '.join(flags)}")
        head.add_row("CVSS", f"{cvss:.1f}" if cvss is not None else "-")
        head.add_row("EPSS", f"{epss} (rank {d.ranking_epss:.2f})" if d.ranking_epss is not None else epss)
        head.add_row("publicado", _s(d.published_time))
        head.add_row("resumo", _s((d.summary or "")[:400]))
        if d.propose_action:
            head.add_row("ação", _s(d.propose_action[:300]))
        console.print(head)
    for cid, msg in errors:
        console.print(f"[yellow]{_s(cid)}: {_s(msg)}[/yellow]")


def print_vuln_rollup(aggs, enriched=None, msf_map=None) -> None:
    enriched = enriched or {}
    msf_map = msf_map or {}
    console.print(f"[bold]{len(aggs)}[/bold] CVE(s) distintas nos relatórios salvos")
    if not aggs:
        return
    t = Table(box=box.MINIMAL_DOUBLE_HEAD)
    cols = ["CVE", "CVSS", "verif", "hosts"]
    if enriched:
        cols += ["KEV", "EPSS"]
    if msf_map:
        cols += ["MSF"]
    cols += ["alvos"]
    for c in cols:
        t.add_column(c)
    for e in aggs:
        row = [_s(e.cve),
               f"{e.max_cvss:.1f}" if e.max_cvss is not None else "-",
               "✓" if e.verified else "",
               str(e.count)]
        if enriched:
            d = enriched.get(e.cve)
            row.append("[red]sim[/red]" if (d and d.kev) else "")
            row.append(f"{d.epss * 100:.0f}%" if (d and d.epss is not None) else "-")
        if msf_map:
            mods = msf_map.get(e.cve) or []
            row.append(f"[red]{len(mods)}[/red]" if mods else "0")
        row.append(_s(", ".join(e.hosts[:6]) + (" …" if len(e.hosts) > 6 else "")))
        t.add_row(*row)
    console.print(t)


def write_vulns_md(aggs, path: Path, enriched=None, msf_map=None) -> None:
    enriched = enriched or {}
    msf_map = msf_map or {}
    lines = ["# Rollup de vulnerabilidades (cross-host)", "",
             f"- **CVEs distintas:** {len(aggs)}", "",
             "| CVE | CVSS | verif | #hosts | KEV | EPSS | MSF | alvos |",
             "|---|---|---|---|---|---|---|---|"]
    for e in aggs:
        d = enriched.get(e.cve)
        mods = msf_map.get(e.cve) or []
        lines.append(
            f"| {_md_cell(e.cve)} | {e.max_cvss if e.max_cvss is not None else '-'} | "
            f"{'sim' if e.verified else ''} | {e.count} | "
            f"{'sim' if (d and d.kev) else ''} | "
            f"{round(d.epss * 100) if (d and d.epss is not None) else '-'} | "
            f"{len(mods)} | {_md_cell(', '.join(e.hosts))} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_msf(result) -> None:
    console.print(
        f"[bold]metasploit[/bold] — alvo [cyan]{_s(result.target)}[/cyan] "
        f"({len(result.cve_hits)} CVE(s), {result.total_cve_modules} módulo(s) por CVE)"
    )
    hits = [h for h in result.cve_hits if h.modules]
    if hits:
        t = Table(title="CVE → módulos (alta precisão)", box=box.MINIMAL_DOUBLE_HEAD)
        for c in ("CVE", "CVSS", "#", "módulos (rank)"):
            t.add_column(c)
        for h in hits:
            top = ", ".join(f"{escape(m.fullname)} ({m.rank_label})" for m in h.modules[:4])
            if len(h.modules) > 4:
                top += f" (+{len(h.modules) - 4})"
            t.add_row(_s(h.cve), f"{h.cvss:.1f}" if h.cvss is not None else "-",
                      str(len(h.modules)), top or "-")
        console.print(t)
    else:
        console.print("[dim]nenhum módulo casado por CVE.[/dim]")

    prod = [p for p in result.product_hits if p.modules]
    if prod:
        pt = Table(title="produto → candidatos (por palavra-chave; ruído possível)",
                   box=box.SIMPLE)
        for c in ("produto", "versão", "portas", "#", "top módulos"):
            pt.add_column(c)
        for p in prod:
            top = ", ".join(escape(m.fullname) for m in p.modules[:3])
            if len(p.modules) > 3:
                top += f" (+{len(p.modules) - 3})"
            pt.add_row(_s(p.product), _s(p.version),
                       " ".join(str(x) for x in p.ports) or "-",
                       str(len(p.modules)), top or "-")
        console.print(pt)


# ------------------------------ writers ------------------------------------- #

def write_json(obj, path: Path) -> None:
    if hasattr(obj, "model_dump_json"):
        path.write_text(obj.model_dump_json(indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def _md_cell(s) -> str:
    return str(s if s is not None else "-").replace("|", "/").replace("\n", " ")


def write_search_csv(result: SearchResult, path: Path) -> None:
    cols = ["ip", "port", "transport", "org", "product", "version",
            "country", "asn", "hostnames", "timestamp"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for m in result.matches:
            d = m.model_dump()
            d["hostnames"] = ",".join(d.get("hostnames") or [])
            w.writerow([d.get(c, "") for c in cols])


def write_host_md(report: HostReport, path: Path) -> None:
    lines = [f"# Host {report.ip or '-'}", ""]
    lines += [
        f"- **hostnames:** {', '.join(report.hostnames) or '-'}",
        f"- **org/isp:** {report.org or '-'} / {report.isp or '-'}",
        f"- **asn:** {report.asn or '-'}",
        f"- **local:** {report.city or '-'}, {report.country or '-'}",
        f"- **os:** {report.os or '-'}",
        f"- **portas:** {' '.join(map(str, report.ports)) or '-'}",
        "",
    ]
    if report.vulns:
        lines += ["## Vulnerabilidades", "", "| CVE | CVSS | verif | resumo |", "|---|---|---|---|"]
        for v in report.vulns:
            lines.append(
                f"| {_md_cell(v.cve)} | {v.cvss if v.cvss is not None else '-'} | "
                f"{'sim' if v.verified else ''} | {_md_cell((v.summary or '')[:160])} |"
            )
        lines.append("")
    lines += ["## Serviços", "", "| porta | produto | versão | módulo | vulns |", "|---|---|---|---|---|"]
    for s in report.services:
        lines.append(
            f"| {s.port}/{s.transport} | {_md_cell(s.product)} | {_md_cell(s.version)} | "
            f"{_md_cell(s.module)} | {len(s.vulns)} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_msf_md(result, path: Path) -> None:
    lines = [f"# Metasploit — {result.target or '-'}", "",
             f"- **RHOSTS:** {result.rhosts or '-'}",
             f"- **CVEs com módulo:** {len([h for h in result.cve_hits if h.modules])}",
             f"- **módulos por CVE:** {result.total_cve_modules}", ""]
    hits = [h for h in result.cve_hits if h.modules]
    if hits:
        lines += ["## CVE → módulos", "", "| CVE | CVSS | módulo | tipo | rank |", "|---|---|---|---|---|"]
        for h in hits:
            for m in h.modules:
                lines.append(
                    f"| {_md_cell(h.cve)} | {h.cvss if h.cvss is not None else '-'} | "
                    f"{_md_cell(m.fullname)} | {_md_cell(m.mtype)} | {_md_cell(m.rank_label)} |"
                )
        lines.append("")
    prod = [p for p in result.product_hits if p.modules]
    if prod:
        lines += ["## Produto → candidatos (palavra-chave)", "",
                  "| produto | versão | portas | módulo | rank |", "|---|---|---|---|---|"]
        for p in prod:
            for m in p.modules[:20]:
                lines.append(
                    f"| {_md_cell(p.product)} | {_md_cell(p.version)} | "
                    f"{_md_cell(' '.join(map(str, p.ports)))} | {_md_cell(m.fullname)} | "
                    f"{_md_cell(m.rank_label)} |"
                )
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_pipeline_md(target_label: str, hosts, in_scope, out_scope,
                      scope_source, stages, path: Path) -> None:
    lines = [f"# Pipeline de superfície — {target_label}", ""]
    lines += [
        f"- **hosts coletados:** {len(hosts)}",
        f"- **autorizados (in-scope):** {len(in_scope)}",
        f"- **fora de escopo (pulados):** {len(out_scope)}",
        f"- **fonte(s) de autorização:** {scope_source or '-'}",
        "",
    ]
    if in_scope:
        lines += ["## Alvos processados", "", *[f"- `{h}`" for h in in_scope], ""]
    if out_scope:
        lines += ["## Fora de escopo (não tocados)", "", *[f"- `{h}`" for h in out_scope], ""]
    lines += ["## Estágios", "", "| estágio | rodou | rc | nota | comando |",
              "|---|---|---|---|---|"]
    for s in stages:
        lines.append(
            f"| {_md_cell(s.name)} | {'sim' if s.ran else 'não'} | "
            f"{s.returncode if s.returncode is not None else '-'} | {_md_cell(s.note)} | "
            f"`{_md_cell(s.cmd_str)}` |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
