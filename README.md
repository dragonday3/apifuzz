# apifuzz

**API Security Testing Framework** — Give it an OpenAPI spec, get back OWASP API Top 10 findings, SARIF output, and CI/CD integration in minutes.

[![CI](https://github.com/dragonday3/apifuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/dragonday3/apifuzz/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010-red.svg)](https://owasp.org/API-Security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

apifuzz takes any API spec (OpenAPI, HAR, Postman) → generates semantic security test cases → executes them asynchronously → maps results to OWASP API Top 10 → outputs SARIF (shows findings inline on GitHub PRs), JSON, or HTML.

No wordlists. No spray-and-pray. Test cases are generated from your actual schema — field names, types, and endpoint semantics drive the payloads.

### Why it needs a spec (not just a URL)

apifuzz is a **test-case generator**, not a traffic interceptor. Before it can inject payloads, it needs to know what endpoints exist, what parameters they accept, and what types those parameters are. A bare URL tells it nothing — `GET /weather?q=STRING` is what lets it try `q='; DROP TABLE--`.

**No spec? Use a HAR file.** Record your browser traffic against the API, export it, and pass that instead — apifuzz reverse-engineers the schema from real requests. See [Quick Start](#quick-start) below.

### `--target` is the base URL only

The spec (or HAR) provides the paths. Pass just the origin:

```
--target https://api.example.com        ✓
--target https://api.example.com/v1/weather  ✗  (path goes in the spec)
```

**Checks implemented** (mapped to the [OWASP API Security Top 10 — 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)):

| ID | OWASP category (2023) | What it tests |
|----|-----------------------|---------------|
| `bola` | API1 — Broken Object Level Authorization | Cross-user access with `--second-token`, confirmed when user B gets user A's object back; ID enumeration (tentative: another object with the same fields) |
| `auth` | API2 — Broken Authentication | No auth, invalid/empty tokens, malformed scheme, JWT `alg:none`, on endpoints the spec marks as secured or doesn't document (HAR/Postman); reported only when the response looks like the authenticated one (same status, content type, JSON fields and similar size) |
| `mass_assignment` | API3 — Broken Object Property Level Authorization | Privileged field injection (`role`, `admin`, `isAdmin`, …) into request bodies; confirmed by a follow-up `GET` showing the values were stored |
| `rate_limit` | API4 — Unrestricted Resource Consumption | 50-request burst per endpoint; any `429`, `Retry-After` or `X-RateLimit-*` header counts as protected |
| `ssrf` | API7 — Server Side Request Forgery | Cloud-metadata and internal URL probes in URL-type parameters |
| `cors` | API8 — Security Misconfiguration | Origin reflection + credentials misconfiguration |
| `data_exposure` | API3 — Broken Object Property Level Authorization | Sensitive fields (passwords, secrets, keys, tokens, card numbers) with real values in GET responses; response fields the spec doesn't document (tentative) |
| `user_enum` | API2 — Broken Authentication | Login answers differently for an existing username than for unknown lookalike usernames (wrong password in all). Sends one wrong password for the spec's example user per scan |
| `bfla` | API5 — Broken Function Level Authorization | With `--low-priv-token`: operations the spec marks as privileged (an `/admin/`-style path segment, role tag or operationId word, "only admins" in the summary, or `x-admin`/`x-internal`) called as the low-privilege user |
| `inventory` | API9 — Improper Inventory Management | Specs describing operations missing from the scanned spec, Spring actuator, `.env`, expvar/metrics/server-status, and neighbouring API versions (once per scan). The API's own published spec and docs UI aren't reported |
| `injection` | *(no 2023 API category; OWASP Top 10 A03:2021 Injection)* | SQLi (DB error strings, boolean true/false conditions, time-based with `--time-based`), SSTI and command injection (computed canaries), NoSQLi (Mongo errors and `$ne`/`$eq` response differences), XSS reflected unescaped in HTML |

Coverage: API1, API2, API3, API4, API5, API7, API8 and API9. API6 (business flows) and API10 (unsafe consumption) are not tested.

### Benchmark: the VAmPI vulnerable API (erev0s/VAmPI)

Scored against [VAmPI](https://github.com/erev0s/VAmPI)'s own list of 9 documented vulnerabilities. The scan runs against the vulnerable build and against the same API with its flaws switched off. Method and reproduction: [`benchmarks/`](benchmarks/README.md). Latest run: [`benchmarks/results/vampi.md`](benchmarks/results/vampi.md).

| | v0.1.0 | current |
|---|---|---|
| Documented vulnerabilities detected | 0 / 9 | 6 / 9: SQLi, BOLA, debug-endpoint data exposure, user enumeration, rate limiting (firm); unauthorized password change (tentative) |
| ...among the 7 apifuzz has a check for | 0 | 6 / 7 |
| False positives, vulnerable build | 25 with tokens, 12 without | 0 |
| False positives, secure build | 25 with tokens, 12 without | 0 |

Two rules were changed after benchmark runs, both disclosed in [`benchmarks/`](benchmarks/README.md). Missed: mass assignment on registration (stored, but nothing in the response to confirm it with). Not covered: RegexDoS, weak JWT signing key.

**Confidence.** Each finding is `firm` (confirmed by a comparison: an authenticated baseline request, the first user's object, a follow-up `GET`, or a true/false pair) or `tentative` (a plausible signal to verify by hand). In SARIF, tentative findings are `note`s under a separate `<rule>/tentative` rule with medium security-severity, so GitHub's default check threshold (High) doesn't fail on them. `--min-confidence firm` hides them.

---

## Install

> **Not on PyPI.** The `apifuzz` package on PyPI is a different, unrelated project — do not `pip install apifuzz`. Install from this repository instead.

### From source

```bash
git clone https://github.com/dragonday3/apifuzz
cd apifuzz
pip install -e .            # add ".[dev]" for tests
```

### Straight from GitHub

```bash
pip install "git+https://github.com/dragonday3/apifuzz.git"
```

### Docker (build locally)

```bash
git clone https://github.com/dragonday3/apifuzz && cd apifuzz
docker build -t apifuzz .
docker run --rm apifuzz --help
```

---

## Quick Start

```bash
# Scan with an OpenAPI spec
apifuzz openapi.yaml --target https://api.example.com

# With bearer token auth
apifuzz openapi.yaml --target https://api.example.com \
  --auth-type bearer --token eyJhbGc...

# BOLA cross-user test (two accounts)
apifuzz openapi.yaml --target https://api.example.com \
  --auth-type bearer --token USER_A_TOKEN \
  --second-token USER_B_TOKEN

# Output as SARIF (GitHub Code Scanning)
apifuzz openapi.yaml --target https://api.example.com \
  --output sarif --out-file results.sarif

# Output as interactive HTML report
apifuzz openapi.yaml --target https://api.example.com \
  --output html --out-file report.html

# Run specific checks only
apifuzz openapi.yaml --target https://api.example.com \
  --checks bola,auth,cors

# Scan a HAR file (from browser DevTools export)
apifuzz recording.har --target https://api.example.com

# Scan a Postman collection
apifuzz collection.json --target https://api.example.com

# See what would be sent, without sending anything
apifuzz openapi.yaml --target https://api.example.com --dry-run

# Route traffic through Burp/ZAP to verify findings by hand
# (TLS is verified: trust the proxy's CA, or add --insecure)
apifuzz openapi.yaml --target https://api.example.com --proxy http://127.0.0.1:8080 --insecure
```

### Safety defaults

- **Read-mostly by default.** `PUT`, `PATCH` and `DELETE` endpoints are skipped unless you pass `--allow-destructive`, because probes such as cross-user BOLA really modify or delete the target's data. `POST` endpoints are still tested: each gets a 50-request rate-limit burst plus injection and mass-assignment probes, so expect dozens of new records per `POST` endpoint (leave `rate_limit` out of `--checks` to avoid the burst).
- **Scope lock.** Every request goes to the `--target` origin: hosts recorded in HAR/Postman files or spec `servers` are ignored, and redirects to another host are refused. Narrow the scan further with `--include` / `--exclude` path globs.
- **Politeness.** `--rate-limit` paces requests, `--max-requests` caps the total, and `429`/`503` responses are retried (`--retries`, honouring `Retry-After`).
- **TLS** certificates are verified unless you pass `--insecure`.
- **Failures are reported.** The scan prints how many requests failed and why (TLS, scope, connection, budget). If every request failed, it exits with code `2` (inconclusive) instead of reporting a clean result.
- **Redaction.** Reports show each finding's request as it was sent, with `Authorization`, cookies, API-key headers and your configured tokens masked (`Bear****`).

### No spec? Zero-spec workflow via HAR

If you don't have an OpenAPI spec, record your browser traffic instead:

1. Open **Chrome/Firefox DevTools** → **Network** tab
2. Make some requests to the API (browse, search, login, etc.)
3. Right-click any request → **Save all as HAR with content**
4. Pass the exported file:

```bash
apifuzz recording.har --target https://api.example.com
```

apifuzz parses the recorded requests to discover endpoints and parameters automatically — no spec writing required.

---

## All CLI Options

```
Arguments:
  SPEC    Path to OpenAPI spec (.yaml/.json), HAR file, or Postman collection

Options:
  --target, -t TEXT          Base URL of the API to test [required]
  --auth-type TEXT           Auth type: none | bearer | apikey | basic [default: none]
  --token TEXT               Auth token / credentials
  --second-token TEXT        Second token for BOLA cross-user tests
  --low-priv-token TEXT      Low-privilege user's token for BFLA tests (--token
                             should then be a privileged user)
  --oob-url TEXT             Collector you control (interactsh, webhook) for blind
                             SSRF; the scan prints which probe id is which parameter
  --header-name TEXT         Header name for apikey auth [default: Authorization]
  --output, -o TEXT          Output format: json | sarif | html [default: json]
  --out-file, -f TEXT        Output file path (stdout if omitted for json/sarif)
  --concurrency, -c INT      Max concurrent HTTP requests [default: 10]
  --rate-limit FLOAT         Max requests per second; the rate_limit check's 50-request
                             bursts are exempt (leave it out of --checks to avoid them)
                             [default: 10.0]
  --timeout FLOAT            HTTP request timeout in seconds [default: 15.0]
  --checks TEXT              Comma-separated check IDs or 'all' [default: all]
  --min-confidence TEXT      Report only: tentative (all) | firm [default: tentative]
  --time-based               Add time-based SQLi probes (each waits ~5 s on a
                             vulnerable target)
  --allow-destructive        Also test PUT/PATCH/DELETE endpoints (modifies data)
  --dry-run                  Print the test plan, send nothing
  --include TEXT             Only test paths matching this glob (repeatable)
  --exclude TEXT             Skip paths matching this glob (repeatable)
  --max-requests INT         Stop sending after this many requests
  --retries INT              Retries on 429/503 [default: 2]
  --insecure                 Skip TLS certificate verification
  --proxy TEXT               Proxy URL, e.g. http://127.0.0.1:8080
  --quiet, -q                Suppress progress output
  --help                     Show this message and exit.
```

**Exit codes:**
- `0` — scan completed, no critical/high findings
- `1` — critical or high severity findings detected (use with `continue-on-error: true` in CI)
- `2` — every request failed (TLS, scope, connection): the scan is inconclusive

---

## CI/CD Integration

### GitHub Actions — SARIF upload

Findings appear inline in the **Security → Code Scanning** tab and as PR annotations.

```yaml
name: API Security Scan

on: [pull_request]

jobs:
  apifuzz:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Install apifuzz
        run: pip install "git+https://github.com/dragonday3/apifuzz.git"

      - name: Run API security scan
        run: |
          apifuzz openapi.yaml \
            --target ${{ secrets.API_BASE_URL }} \
            --auth-type bearer \
            --token ${{ secrets.API_TEST_TOKEN }} \
            --output sarif \
            --out-file apifuzz.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: apifuzz.sarif
```

### GitLab CI

```yaml
api-security:
  image: python:3.12-slim
  script:
    - pip install "git+https://github.com/dragonday3/apifuzz.git"
    - apifuzz openapi.yaml --target $API_BASE_URL --output sarif --out-file gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
  allow_failure: true
```

> **Shared staging?** The default scan still sends a 50-request burst to every endpoint (and creates records through `POST`). Use `--checks` without `rate_limit` and/or `--max-requests` against shared environments. Add `--insecure` if staging uses a self-signed certificate (otherwise every request fails and the job exits `2`).

---

## Python SDK

```python
import asyncio
from apifuzz.scanner import Scanner
from apifuzz.models.endpoint import AuthConfig
from apifuzz.reporters.sarif import SARIFReporter
from apifuzz.reporters.html import HTMLReporter

auth = AuthConfig(type="bearer", token="your-token")

scanner = Scanner(
    spec_path="openapi.yaml",
    base_url="https://api.example.com",
    auth=auth,
    checks=["bola", "auth", "injection"],  # None = all checks
    concurrency=10,
    rate_limit_rps=5.0,
    timeout=15.0,
)

findings = asyncio.run(scanner.run())

for f in findings:
    print(f"{f.severity.value.upper():10} {f.title}")
    print(f"  {f.endpoint_method} {f.endpoint_path}")
    print(f"  {f.owasp_category.value}")

# Export SARIF
SARIFReporter().write(findings, "results.sarif")

# Export HTML
HTMLReporter().write(findings, "report.html")
```

---

## Output Formats

### SARIF 2.1

Upload to GitHub Code Scanning (workflow above) and findings appear in the Security tab and inline on pull requests, with severity, description and remediation guidance. Tentative findings are reported at level `note` under `<rule>/tentative` rules. Any SARIF 2.1-compatible tool can read the file.

### JSON

Machine-readable array of findings. Each finding includes:
- `rule_id`, `title`, `severity`, `confidence` (`firm` | `tentative`), `owasp_category`
- `endpoint_method`, `endpoint_path`
- `evidence` — what matched (e.g. the error string or canary found)
- `request_sample` — the request as sent (method, URL, headers, body), credentials masked
- `response_sample` — an excerpt of the response (bodies over 8 KB are truncated, and the excerpt says so)
- `remediation` — actionable fix guidance

### HTML

Dark-theme interactive report with collapsible findings, severity badges, evidence blocks, and remediation guidance. Self-contained single file, no external dependencies.

---

## Trying It Against a Deliberately Vulnerable API

Run a practice target such as [OWASP crAPI](https://github.com/OWASP/crAPI) or [VAmPI](https://github.com/erev0s/VAmPI) locally using their own setup instructions, then point apifuzz at it with that project's OpenAPI spec:

```bash
apifuzz ./target-openapi.yaml --target http://localhost:<port> \
  --allow-destructive --output html --out-file report.html
```

`--allow-destructive` is fine here because these targets are disposable. VAmPI, for example, resets its data with `GET /createdb`.

---

## Architecture

```
Input Parsers          → Endpoint models
  OpenAPI 3.x / Swagger 2.x
  HAR file
  Postman Collection v2

Check Engine           → TestCase list
  11 checks:
    bola           (API1 - BOLA/IDOR)
    auth           (API2 - Broken Auth)
    mass_assignment(API3 - BOPLA / mass assignment)
    ssrf           (API7 - SSRF)
    injection      (A03:2021 - Injection)
    rate_limit     (API4 - Rate Limiting)
    cors           (API8 - CORS)
    data_exposure  (API3 - excessive data exposure)
    user_enum      (API2 - login user enumeration)
    bfla           (API5 - function level authorization)
    inventory      (API9 - inventory, once per scan)

Async Executor         → TestResult list
  httpx AsyncClient
  Semaphore concurrency control
  Scope lock to the --target origin (redirects too)
  Minimum-interval rate limiting (bursts exempt),
    request budget, 429/503 retry with backoff
  Auth injection (bearer / apikey / basic),
    never replacing the headers an auth/BOLA probe sets

Response Analyzer      → Finding list
  Per-check detection, compared against a baseline
    request per endpoint; canary payloads; true/false
    pairs; follow-up GETs; firm / tentative confidence
  Rate limit verdict per endpoint
  Severity-based deduplication

Reporters
  SARIF 2.1 (GitHub Code Scanning)
  JSON       (machine-readable)
  HTML       (interactive dark-theme report)
```

---

## Development

```bash
git clone https://github.com/dragonday3/apifuzz
cd apifuzz
pip install -e ".[dev]"

# Run tests (unit + end-to-end against a mocked API in tests/e2e)
pytest tests/

# Lint and type-check
ruff check .
mypy src

# Run with coverage
pytest --cov=apifuzz --cov-report=term-missing tests/

# Run a specific check
pytest tests/checks/test_injection.py -v
```

**Test matrix:** Python 3.10, 3.11, 3.12 (CI runs all three on every push).

---

## Authorized Use Only

apifuzz sends attack payloads (injection, SSRF, auth bypass, request bursts). Only scan APIs you own or have explicit written permission to test.

---

## License

MIT
