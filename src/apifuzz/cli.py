import asyncio
import json
import sys
from collections import Counter
from typing import List, Optional

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
    rate_limit: float = typer.Option(10.0, "--rate-limit", help="Max requests per second (rate_limit check bursts are exempt)"),
    timeout: float = typer.Option(15.0, "--timeout", help="HTTP request timeout in seconds"),
    checks: str = typer.Option("all", "--checks", help="Comma-separated check IDs or 'all'"),
    min_confidence: str = typer.Option(
        "tentative", "--min-confidence",
        help="Report only findings at or above this confidence: tentative (all) | firm"),
    time_based: bool = typer.Option(
        False, "--time-based", help="Add time-based SQLi probes (each waits ~5 s on a vulnerable target)"),
    allow_destructive: bool = typer.Option(
        False, "--allow-destructive", help="Also test PUT/PATCH/DELETE endpoints (they modify or delete data)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the test plan (requests per check/endpoint), send nothing"),
    include: Optional[List[str]] = typer.Option(
        None, "--include", help="Only test paths matching this glob (repeatable), e.g. '/api/v1/*'"),
    exclude: Optional[List[str]] = typer.Option(None, "--exclude", help="Skip paths matching this glob (repeatable)"),
    max_requests: Optional[int] = typer.Option(None, "--max-requests", help="Stop sending after this many requests"),
    retries: int = typer.Option(2, "--retries", help="Retries on 429/503 (honours Retry-After, else backoff)"),
    insecure: bool = typer.Option(False, "--insecure", help="Skip TLS certificate verification"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Send traffic through a proxy, e.g. http://127.0.0.1:8080"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
) -> None:
    """Scan an API for OWASP API Top 10 security issues."""
    if min_confidence not in ("tentative", "firm"):
        raise typer.BadParameter("must be 'tentative' or 'firm'", param_hint="--min-confidence")
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
        time_based=time_based,
        allow_destructive=allow_destructive,
        include=include,
        exclude=exclude,
        max_requests=max_requests,
        verify=not insecure,
        proxy=proxy,
        retries=retries,
    )

    if dry_run:
        _print_plan(scanner)
        return

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
        if min_confidence == "firm":
            findings = [f for f in findings if f.confidence == "firm"]
        progress.update(task, description=f"Done — {len(findings)} finding(s)")

    if not quiet:
        _print_summary(findings)
        if scanner.skipped:
            console.print(f"[dim]Skipped {len(scanner.skipped)} endpoint(s): " + "; ".join(scanner.skipped) + "[/]")
        if scanner.budget.limit is not None and scanner.budget.used >= scanner.budget.limit:
            console.print(f"[yellow]--max-requests {scanner.budget.limit} reached: the scan is incomplete.[/]")

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


def _print_plan(scanner: Scanner) -> None:
    """--dry-run: what a scan would send (first pass; confirmations depend on responses)."""
    cases = scanner.plan()
    table = Table(title="Test plan (nothing sent)", box=box.ROUNDED)
    table.add_column("Endpoint", style="cyan")
    table.add_column("Check")
    table.add_column("Requests", justify="right")
    counts = Counter((tc.extra.get("endpoint_key", ""), tc.check_id) for tc in cases)
    for (endpoint, check_id), n in sorted(counts.items()):
        table.add_row(endpoint, check_id, str(n))
    console.print(table)
    console.print(f"Total: {len(cases)} request(s) to {scanner.base_url}"
                  + (f" (capped at --max-requests {scanner.budget.limit})" if scanner.budget.limit else ""))
    for s in scanner.skipped:
        console.print(f"[dim]Skipped: {s}[/]")


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
            f.title + (" [dim](tentative)[/]" if f.confidence == "tentative" else ""),
            f"{f.endpoint_method} {f.endpoint_path}",
            f.rule_id,
        )

    console.print(table)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [f"[{_SEVERITY_COLOR[k]}]{v} {k}[/]" for k, v in sorted(counts.items(), key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x[0],9))]
    console.print("Summary: " + "  ".join(parts))


def _format_output(findings, output: str, out_file: Optional[str]) -> Optional[str]:
    reporter: SARIFReporter | HTMLReporter | JSONReporter
    if output == "sarif":
        reporter = SARIFReporter()
    elif output == "html":
        reporter = HTMLReporter()
    else:
        reporter = JSONReporter()
    if out_file:
        reporter.write(findings, out_file)
        return None
    result = reporter.generate(findings)
    return result if isinstance(result, str) else json.dumps(result, indent=2) + "\n"


if __name__ == "__main__":
    app()
