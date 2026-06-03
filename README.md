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

**Checks implemented:**

| ID | OWASP Category | What It Tests |
|----|---------------|---------------|
| `bola` | API1 - BOLA/IDOR | ID enumeration, cross-user access |
| `auth` | API2 - Broken Auth | No auth, invalid tokens, JWT alg:none |
| `mass_assignment` | API6 - Mass Assignment | Privileged field injection into request body |
| `ssrf` | API7 - SSRF | Internal URL probes in URL-type parameters |
| `injection` | API8 - Injection | SQLi, SSTI, NoSQLi, command injection, XSS |
| `rate_limit` | API4 - Rate Limiting | 50-request burst detection |
| `cors` | API8 - CORS | Origin reflection + credentials misconfiguration |

---

## Install

### pip

```bash
pip install apifuzz
```

### Docker

```bash
docker pull dragonday3/apifuzz
docker run --rm dragonday3/apifuzz --help
```

### From source

```bash
git clone https://github.com/dragonday3/apifuzz
cd apifuzz
pip install -e ".[dev]"
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
```

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
  --header-name TEXT         Header name for apikey auth [default: Authorization]
  --output, -o TEXT          Output format: json | sarif | html [default: json]
  --out-file, -f TEXT        Output file path (stdout if omitted for json/sarif)
  --concurrency, -c INT      Max concurrent HTTP requests [default: 10]
  --rate-limit FLOAT         Max requests per second [default: 10.0]
  --timeout FLOAT            HTTP request timeout in seconds [default: 15.0]
  --checks TEXT              Comma-separated check IDs or 'all' [default: all]
  --quiet, -q                Suppress progress output
  --help                     Show this message and exit.
```

**Exit codes:**
- `0` — scan completed, no critical/high findings
- `1` — critical or high severity findings detected (use with `continue-on-error: true` in CI)

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
        run: pip install apifuzz

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
  image: dragonday3/apifuzz:latest
  script:
    - apifuzz openapi.yaml --target $API_BASE_URL --output sarif --out-file gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
  allow_failure: true
```

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

Native integration with GitHub Code Scanning, GitLab SAST, and Azure DevOps. Findings appear inline on pull requests with severity, description, and remediation guidance. Rule IDs map directly to OWASP API Top 10 categories.

### JSON

Machine-readable array of findings. Each finding includes:
- `rule_id`, `title`, `severity`, `owasp_category`
- `endpoint_method`, `endpoint_path`
- `evidence` — actual request/response excerpt that triggered the finding
- `remediation` — actionable fix guidance

### HTML

Dark-theme interactive report with collapsible findings, severity badges, evidence blocks, and remediation guidance. Self-contained single file, no external dependencies.

---

## Verifying Against Real Vulnerable APIs

```bash
# OWASP crAPI (deliberately vulnerable API)
docker run -d --name crapi -p 8888:8888 crapi/crapi:latest
apifuzz ./crapi-openapi.yaml --target http://localhost:8888 \
  --output html --out-file crapi-report.html

# vAPI (vulnerable API)
docker run -d --name vapi -p 9090:80 roottusk/vapi
apifuzz ./vapi-openapi.yaml --target http://localhost:9090 \
  --output sarif --out-file vapi.sarif
```

---

## Architecture

```
Input Parsers          → Endpoint models
  OpenAPI 3.x / Swagger 2.x
  HAR file
  Postman Collection v2

Check Engine           → TestCase list
  7 OWASP checks:
    bola           (API1 - BOLA/IDOR)
    auth           (API2 - Broken Auth)
    mass_assignment(API6 - Mass Assignment)
    ssrf           (API7 - SSRF)
    injection      (API8 - Injection)
    rate_limit     (API4 - Rate Limiting)
    cors           (API8 - CORS)

Async Executor         → TestResult list
  httpx AsyncClient
  Semaphore concurrency control
  Token-bucket rate limiting
  Auth injection (bearer / apikey / basic)

Response Analyzer      → Finding list
  Per-check detection heuristics
  Rate limit burst aggregation
  Severity-based deduplication

Reporters
  SARIF 2.1 (GitHub / GitLab / Azure DevOps)
  JSON       (machine-readable)
  HTML       (interactive dark-theme report)
```

---

## Development

```bash
git clone https://github.com/dragonday3/apifuzz
cd apifuzz
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with coverage
pytest --cov=apifuzz --cov-report=term-missing tests/

# Run a specific check
pytest tests/checks/test_injection.py -v
```

**Test matrix:** Python 3.10, 3.11, 3.12 (CI runs all three on every push).

---

## License

MIT
