"""
Generates JSON and terminal (Rich) reports from scan results.
"""

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.rule import Rule

from detectors.base import Severity
from core.scanner import ScanSummary, SkillResult

console = Console()

SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

RISK_COLOR = {
    "CLEAN": "bold green",
    "LOW": "bold cyan",
    "MEDIUM": "bold yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold red on white",
}


def _severity_badge(s: Severity) -> Text:
    color = SEVERITY_COLOR.get(s, "white")
    return Text(f" {s.value} ", style=f"{color}")


def print_summary_table(summary: ScanSummary):
    console.print()
    console.print(Rule("[bold]ClawScan — Supply Chain Security Scanner[/bold]"))
    console.print()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white on dark_blue")
    table.add_column("Skill", style="bold")
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Top Severity", justify="center")

    for result in sorted(summary.results, key=lambda r: -r.risk_score):
        risk_color = RISK_COLOR.get(result.risk_label, "white")
        top_sev = result.highest_severity
        sev_text = _severity_badge(top_sev) if top_sev else Text("—", style="dim")

        table.add_row(
            result.skill.name,
            Text(result.risk_label, style=risk_color),
            str(result.risk_score),
            str(len(result.findings)),
            sev_text,
        )

    console.print(table)
    console.print()
    console.print(
        f"  [bold]Scanned:[/bold] {summary.total}  "
        f"[bold green]Clean:[/bold green] {summary.clean}  "
        f"[bold yellow]Flagged:[/bold yellow] {summary.flagged}  "
        f"[bold red]Critical:[/bold red] {summary.critical_count}"
    )
    console.print()


def print_skill_detail(result: SkillResult):
    if not result.findings:
        console.print(Panel(
            f"[bold green]No findings — skill appears clean.[/bold green]",
            title=f"[bold]{result.skill.name}[/bold]",
            border_style="green",
        ))
        return

    risk_color = RISK_COLOR.get(result.risk_label, "white")
    console.print(Panel(
        f"Risk Score: [{risk_color}]{result.risk_score}[/{risk_color}]  |  "
        f"Risk Level: [{risk_color}]{result.risk_label}[/{risk_color}]  |  "
        f"Findings: {len(result.findings)}",
        title=f"[bold]{result.skill.name}[/bold]",
        border_style="red" if result.risk_score > 10 else "yellow",
    ))

    for i, finding in enumerate(result.findings, 1):
        color = SEVERITY_COLOR.get(finding.severity, "white")
        console.print(
            f"\n  [{color}][{i}] {finding.severity.value}[/{color}]  "
            f"[bold]{finding.title}[/bold]"
        )
        console.print(f"      [dim]{finding.description}[/dim]")
        if finding.evidence:
            console.print(f"      [italic]Evidence:[/italic] [yellow]{finding.evidence[:100]}[/yellow]")
        if finding.owasp_asi:
            console.print(f"      [dim]OWASP ASI: {finding.owasp_asi}[/dim]")
        if finding.mitre_atlas:
            console.print(f"      [dim]MITRE ATLAS: {finding.mitre_atlas}[/dim]")

    console.print()


def export_json(summary: ScanSummary, output_path: Path):
    data = {
        "clawscan_version": "1.0.0",
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_skills": summary.total,
            "flagged": summary.flagged,
            "clean": summary.clean,
            "critical": summary.critical_count,
            "errors": summary.errors,
        },
        "results": [],
    }

    for result in summary.results:
        skill_data = {
            "name": result.skill.name,
            "author": result.skill.author,
            "version": result.skill.version,
            "risk_label": result.risk_label,
            "risk_score": result.risk_score,
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "owasp_asi": f.owasp_asi,
                    "mitre_atlas": f.mitre_atlas,
                    "line": f.line,
                }
                for f in result.findings
            ],
        }
        data["results"].append(skill_data)

    output_path.write_text(json.dumps(data, indent=2))
    console.print(f"[bold green]JSON report saved:[/bold green] {output_path}")
