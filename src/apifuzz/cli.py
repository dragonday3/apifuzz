import asyncio
import json
import os
import sys
from collections import Counter
from typing import List, Optional

import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.markup import escape

from apifuzz import ignore as ignore_file
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
    auth_type: Optional[str] = typer.Option(
        None, "--auth-type", help="Auth type: none | bearer | apikey | basic [default: bearer with --token, else none]"),
    token: str = typer.Option("", "--token", help="Auth token / credentials"),
    second_token: str = typer.Option("", "--second-token", help="Second token for BOLA cross-user tests"),
    low_priv_token: str = typer.Option(
        "", "--low-priv-token", help="Low-privilege user's token for BFLA tests (--token should be privileged)"),
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
    max_requests: Optional[int] = typer.Option(None, "--max-requests", min=1,
                                               help="Stop sending after this many requests"),
    retries: int = typer.Option(2, "--retries", min=0, help="Retries on 429/503 (honours Retry-After, else backoff)"),
    insecure: bool = typer.Option(False, "--insecure", help="Skip TLS certificate verification"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Send traffic through a proxy, e.g. http://127.0.0.1:8080"),
    oob_url: str = typer.Option(
        "", "--oob-url", help="Collector URL you control (interactsh, webhook) for blind SSRF payloads"),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Exit 1 if any finding is at least this severe: critical | high | medium | low | "
                                  "info | never"),
    ignore_path: Optional[str] = typer.Option(
        None, "--ignore-file", help=f"Accepted findings to suppress (default: {ignore_file.DEFAULT_FILE} if present)"),
    write_ignore: Optional[str] = typer.Option(
        None, "--write-ignore", help="Write an ignore file accepting every finding of this scan, then exit 0"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
) -> None:
    """Scan an API for OWASP API Top 10 security issues."""
    try:
        target_url = httpx.URL(target)
    except httpx.InvalidURL as e:
        raise typer.BadParameter(str(e), param_hint="--target")
    if target_url.scheme not in ("http", "https") or not target_url.host:
        raise typer.BadParameter("must be an http(s) URL such as https://api.example.com", param_hint="--target")
    if fail_on not in _FAIL_ON:
        raise typer.BadParameter(f"must be one of: {', '.join(_FAIL_ON)}", param_hint="--fail-on")
    ignore_rules: list[ignore_file.IgnoreRule] = []
    ignore_src = ignore_path or (ignore_file.DEFAULT_FILE if os.path.exists(ignore_file.DEFAULT_FILE) else None)
    if ignore_src:
        try:
            ignore_rules = ignore_file.load(ignore_src)
        except (OSError, ValueError) as e:
            raise typer.BadParameter(str(e), param_hint="--ignore-file")
    if min_confidence not in ("tentative", "firm"):
        raise typer.BadParameter("must be 'tentative' or 'firm'", param_hint="--min-confidence")
    # --token alone used to mean no auth at all (the default was "none"), silently scanning unauthenticated.
    if auth_type is None:
        auth_type = "bearer" if token else "none"
    elif auth_type == "none" and (token or second_token or low_priv_token):
        raise typer.BadParameter("--auth-type none ignores the tokens given; drop it or pick bearer | apikey | basic",
                                 param_hint="--auth-type")
    auth = AuthConfig(
        type=auth_type,
        token=token,
        header_name=header_name,
        second_token=second_token,
        low_priv_token=low_priv_token,
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
        oob_url=oob_url,
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
        all_findings = findings  # before suppression: --write-ignore must see everything
        findings, suppressed, expired = ignore_file.apply(findings, ignore_rules)
        progress.update(task, description=f"Done — {len(findings)} finding(s)")

    if not quiet:
        _print_summary(findings)
        if scanner.skipped:
            console.print(f"[dim]Skipped {len(scanner.skipped)} endpoint(s): " + escape("; ".join(scanner.skipped)) + "[/]")
        if scanner.budget.denied:
            console.print(f"[yellow]--max-requests {scanner.budget.limit} reached: {scanner.budget.denied} "
                          f"request(s) not sent, the scan is incomplete.[/]")
    _warn_failures(scanner)
    if suppressed and not quiet:
        console.print(f"[dim]{len(suppressed)} finding(s) suppressed by {ignore_src}[/]")
    for rule in expired:
        console.print(f"[yellow]Ignore entry expired on {rule.expires}: {rule.rule_id} {rule.endpoint}. "
                      f"It no longer suppresses anything.[/]")
    if scanner.oob_probes:  # printed even with --quiet: the user needs this to confirm callbacks
        console.print(f"[cyan]Sent {len(scanner.oob_probes)} blind-SSRF probe(s) to {oob_url}. A request to "
                      f"<collector>/apifuzz-<id> means that parameter fetches attacker URLs:[/]")
        for oob_id, where in sorted(scanner.oob_probes.items()):
            console.print(f"  apifuzz-{oob_id}  {escape(where)}")  # "[param]" isn't Rich markup

    # Output
    output_text = _format_output(findings, output, out_file)

    if out_file:
        if not quiet:
            console.print(f"[green]Report written:[/] {out_file}")
    else:
        if output_text:
            sys.stdout.write(output_text)

    if write_ignore:
        # Keep what was already accepted there (reasons, expiry dates); add only what's new.
        existing = ignore_rules if ignore_src and os.path.abspath(ignore_src) == os.path.abspath(write_ignore) else (
            ignore_file.load(write_ignore) if os.path.exists(write_ignore) else [])
        n = ignore_file.write(all_findings, write_ignore, existing)
        console.print(f"[green]Added {n} accepted finding(s) to {write_ignore}[/] ({len(existing)} kept; "
                      f"fill in each new reason)")
        return

    # Exit code 1 if any reported (not ignored) finding reaches --fail-on.
    threshold = _FAIL_ON.index(fail_on)
    if fail_on != "never" and any(_FAIL_ON.index(f.severity.value) <= threshold for f in findings):
        raise typer.Exit(code=1)


_FAIL_ON = ["critical", "high", "medium", "low", "info", "never"]


def _warn_failures(scanner: Scanner) -> None:
    """Failed requests must never pass for a clean result (TLS, scope, connection, budget)."""
    failed = sum(scanner.errors.values())
    if not failed:
        return
    kinds = ", ".join(f"{k} x{n}" for k, n in scanner.errors.most_common())
    console.print(f"[yellow]{failed} of {scanner.sent} request(s) failed: {kinds}[/]")
    if scanner.sent and failed == scanner.sent:
        console.print("[bold red]Every request failed: the scan is inconclusive, not clean. "
                      "Check --target, TLS (--insecure), the proxy, and connectivity.[/]")
        raise typer.Exit(code=2)


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
        console.print(f"[dim]Skipped: {escape(s)}[/]")


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
