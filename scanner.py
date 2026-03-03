#!/usr/bin/env python3
"""
ClawScan — OpenClaw Supply Chain Security Scanner
Detects malicious patterns in OpenClaw skill packages.

Usage:
  python scanner.py <skill-dir>              # scan a single skill
  python scanner.py <registry-dir> --all     # scan all skills in a registry
  python scanner.py <skill-dir> --json out.json
"""

import sys
from pathlib import Path

import click
from rich.console import Console

from core.scanner import scan_directory
from core.report import print_summary_table, print_skill_detail, export_json

console = Console()


@click.command()
@click.argument("target", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--all", "scan_all", is_flag=True, default=False,
    help="Treat TARGET as a registry directory and scan every subdirectory as a skill.",
)
@click.option(
    "--json", "json_out", type=click.Path(path_type=Path), default=None,
    help="Export full results to a JSON file.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Print per-finding detail for every skill.",
)
@click.option(
    "--only-flagged", is_flag=True, default=False,
    help="In verbose mode, skip clean skills.",
)
def main(target: Path, scan_all: bool, json_out: Path | None, verbose: bool, only_flagged: bool):
    """ClawScan: Detect malicious patterns in OpenClaw skill packages.

    TARGET is either a single skill directory or (with --all) a registry
    directory whose immediate subdirectories are treated as individual skills.
    """
    console.print(f"\n[bold cyan]ClawScan[/bold cyan] scanning [bold]{target}[/bold]...\n")

    summary = scan_directory(target, recursive=scan_all)

    if summary.errors:
        for path, msg in summary.errors:
            console.print(f"[yellow]WARN[/yellow] Could not parse [bold]{path}[/bold]: {msg}")
        console.print()

    if not summary.results:
        console.print("[red]No valid skills found to scan.[/red]")
        sys.exit(1)

    print_summary_table(summary)

    if verbose:
        for result in sorted(summary.results, key=lambda r: -r.risk_score):
            if only_flagged and not result.findings:
                continue
            print_skill_detail(result)

    if json_out:
        export_json(summary, json_out)

    if summary.critical_count > 0:
        sys.exit(2)
    elif summary.flagged > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
