import asyncio
import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner
from apifuzz.reporters.sarif import SARIFReporter
from apifuzz.reporters.json_reporter import JSONReporter
from apifuzz.reporters.html import HTMLReporter

app = typer.Typer(help="apifuzz — API Security Testing Framework (OWASP API Top 10)")
console = Console(stderr=True)

_SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


@app.command()
def scan(
    spec: str = typer.Argument(..., help="Path to OpenAPI spec (.yaml/.json), HAR file, or Postman collection"),
    target: str = typer.Option(..., "--target", "-t", help="Base URL of the API to test (e.g. https://api.example.com)"),
    auth_type: str = typer.Option("none", "--auth-type", help="Auth type: none | bearer | apikey | basic"),
    token: str = typer.Option("", "--token", help="Auth token / credentials"),
    second_token: str = typer.Option("", "--second-token", help="Second token for BOLA cross-user tests"),
    header_name: str = typer.Option("Authorization", "--header-name", help="Header name for apikey auth"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json | sarif | html"),
    out_file: Optional[str] = typer.Option(None, "--out-file", "-f", help="Output file path (default: stdout for json/sarif)"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Max concurrent HTTP requests"),
    rate_limit: float = typer.Option(10.0, "--rate-limit", help="Max requests per second"),
    timeout: float = typer.Option(15.0, "--timeout", help="HTTP request timeout in seconds"),
    checks: str = typer.Option("all", "--checks", help="Comma-separated check IDs or 'all'"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
) -> None:
    """Scan an API for OWASP API Top 10 security issues."""
    auth = AuthConfig(
        type=auth_type,
        token=token,
        header_name=header_name,
        second_token=second_token,
    )

    enabled_checks = None if checks == "all" else [c.strip() for c in checks.split(",")]

    scanner = Scanner(
        spec_path=spec,
        base_url=target,
        auth=auth,
        checks=enabled_checks,
        concurrency=concurrency,
        rate_limit_rps=rate_limit,
        timeout=timeout,
    )

    if not quiet:
        console.print(f"[bold cyan]apifuzz[/] scanning [green]{spec}[/] → [green]{target}[/]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        disable=quiet,
    ) as progress:
        task = progress.add_task("Running security checks…", total=None)
        findings = asyncio.run(scanner.run())
        progress.update(task, description=f"Done — {len(findings)} finding(s)")

    if not quiet:
        _print_summary(findings)

    # Output
    output_text = _format_output(findings, output, out_file)

    if out_file:
        if not quiet:
            console.print(f"[green]Report written:[/] {out_file}")
    else:
        if output_text:
            sys.stdout.write(output_text)

    # Exit code: non-zero if critical/high findings
    severity_values = {f.severity.value for f in findings}
    if "critical" in severity_values or "high" in severity_values:
        raise typer.Exit(code=1)


def _print_summary(findings) -> None:
    if not findings:
        console.print("[green]No findings.[/]")
        return

    table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", min_width=8)
    table.add_column("Title", min_width=30)
    table.add_column("Endpoint", style="cyan")
    table.add_column("Rule ID", style="dim")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 99))

    for f in sorted_findings:
        color = _SEVERITY_COLOR.get(f.severity.value, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/]",
            f.title,
            f"{f.endpoint_method} {f.endpoint_path}",
            f.rule_id,
        )

    console.print(table)

    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [f"[{_SEVERITY_COLOR[k]}]{v} {k}[/]" for k, v in sorted(counts.items(), key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x[0],9))]
    console.print("Summary: " + "  ".join(parts))


def _format_output(findings, output: str, out_file: Optional[str]) -> Optional[str]:
    if output == "sarif":
        reporter = SARIFReporter()
        sarif = reporter.generate(findings)
        text = json.dumps(sarif, indent=2)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(text)
            return None
        return text + "\n"

    if output == "html":
        reporter = HTMLReporter()
        if out_file:
            reporter.write(findings, out_file)
            return None
        return reporter.generate(findings)

    # Default: json
    reporter = JSONReporter()
    data = reporter.generate(findings)
    text = json.dumps(data, indent=2)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write(text)
        return None
    return text + "\n"


if __name__ == "__main__":
    app()
