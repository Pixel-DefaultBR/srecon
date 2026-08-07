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
