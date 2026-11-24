# Output formats and exit codes

Choose the format with `--output json|sarif|html` (default `json`) and a file with `--out-file`; without
`--out-file` the report goes to stdout. Progress, the findings table and warnings go to stderr, so stdout stays
a clean report.

## Finding fields

Every format carries the same findings:

| Field | Meaning |
|---|---|
| `rule_id` | Stable rule identifier, e.g. `APIFUZZ-BOLA-001` (listed on each [check page](../checks/index.md)) |
| `title`, `description` | What was found |
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `confidence` | `firm` (confirmed by a comparison) or `tentative` (verify by hand) |
| `owasp_category` | e.g. `API1:2023 - Broken Object Level Authorization`; injection is `A03:2021 Injection (OWASP Top 10)` |
| `endpoint_method`, `endpoint_path` | The probe's method and concrete URL |
| `endpoint` | The spec operation the probe belongs to, e.g. `GET /users/{id}` |
| `parameter` | The probed parameter, for injection, SSRF and ReDoS findings |
| `evidence` | What decided the finding (the error string, the canary, the comparison) |
| `request_sample` | The request as sent (method, URL, headers, body), credentials masked |
| `response_sample` | An excerpt of the response (the first 500 characters); says so when the body was cut at `--max-body` |
| `remediation` | How to fix it |

Response bodies longer than `--max-body` (8192 characters by default) are truncated before detection, so
detection only sees the first 8192 characters.

## JSON

A list of findings:

```json
[
  {"title": "...", "severity": "critical", "confidence": "firm", "rule_id": "APIFUZZ-AUTH-NO_AUTH", "...": "..."}
]
```

With `--oob-url` (and at least one blind-SSRF probe sent), the output is an object instead, so a callback that
reaches your collector after the scan can be mapped back from the report alone:

```json
{
  "findings": [ ... ],
  "oob_probes": {"apifuzz-<id>": "METHOD /path [param]"}
}
```

Without `--oob-url` it stays a plain list.

## SARIF 2.1.0

For GitHub code scanning and any SARIF 2.1-compatible tool ([CI integration](../ci.md)).

- **Rules**: one per `rule_id`, with the OWASP category as a tag and a numeric `security-severity` (critical
  9.8, high 8.1, medium 5.3, low 3.1, info 0.0) that GitHub uses to rank alerts and to decide whether a check
  fails.
- **Tentative findings** go under a separate rule `<rule_id>/tentative` with `security-severity` 5.0 (medium),
  and their results have level `note`, so GitHub's default check threshold (high) doesn't fail on them. Firm
  findings have level `error` (critical, high), `warning` (medium) or `note` (low, info).
- **Locations**: the spec operation's path (probe URLs change every run), relative to `%APIROOT%`, plus a
  logical location `METHOD URL`.
- **Fingerprints**: `partialFingerprints.apifuzzFinding/v1` is a SHA-256 of rule id, method, spec operation and
  parameter. It is stable across runs (probe URLs carry random ids and payloads), so GitHub recognises a
  recurring alert instead of opening a new one.
- **Properties**: each result carries `owasp_category`, `severity`, `confidence`, `remediation`, and
  `evidence`/`request_sample`/`response_sample` when present. The run's properties carry `totalFindings`, `criticalCount`, `highCount` and `mediumCount`.
- With `--oob-url`, `runs[0].properties.oobProbes` maps each blind-SSRF probe id to `METHOD /path [param]`.

## HTML

A single self-contained file (no external scripts, styles or fonts): a dark-theme report with collapsible
findings, severity badges, a dashed "tentative" badge, evidence, the request and response samples, and
remediation. With `--oob-url`, a "Blind SSRF probes" section lists which probe id is which parameter.

## Filtering

- `--min-confidence firm` drops tentative findings from every output (default `tentative`: report all).
- `--ignore-file PATH` suppresses accepted findings; by default `.apifuzz-ignore.yaml` is used when it exists in
  the working directory ([CI integration](../ci.md#accepting-known-findings)). The console says how many
  findings were suppressed and warns about expired entries.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan completed with no finding at or above `--fail-on` (outside the ignore file), or `--dry-run`, or `--write-ignore` wrote its file |
| `1` | At least one reported finding is at or above `--fail-on` (default `high`) |
| `2` | Every request failed (TLS, scope, connection, budget): the scan is inconclusive, not clean |

`--fail-on` takes `critical`, `high`, `medium`, `low`, `info` or `never`. Findings removed by `--min-confidence`
or the ignore file don't count. Invalid options (an unknown `--fail-on`, a `--target` that isn't an http(s) URL,
an invalid ignore file) exit with Typer's usage error code `2` before anything is sent.
