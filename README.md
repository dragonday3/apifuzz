# apifuzz

**API Security Testing Framework** — Give it an OpenAPI spec, get back OWASP API Top 10 findings, SARIF output, and CI/CD integration in minutes.

[![CI](https://github.com/dragonday3/apifuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/dragonday3/apifuzz/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010-red.svg)](https://owasp.org/API-Security/)

---

## What It Does

apifuzz takes any API spec (OpenAPI, HAR, Postman) → generates semantic security test cases → executes them asynchronously → maps results to OWASP API Top 10 → outputs SARIF (shows findings inline on GitHub PRs), JSON, or HTML.

**Checks implemented:**

| ID | OWASP Category | What It Tests |
|----|---------------|---------------|
| `bola` | API1 - BOLA/IDOR | ID enumeration, cross-user access |
| `auth` | API2 - Broken Auth | No auth, invalid tokens, JWT alg:none |
| `mass_assignment` | API6 - Mass Assignment | Privileged field injection |
| `ssrf` | API7 - SSRF | Internal URL probes in URL-type params |
| `injection` | API8 - Injection | SQLi, SSTI, NoSQLi, command injection, XSS |
| `rate_limit` | API4 - Rate Limiting | 50-request burst detection |
| `cors` | API8 - CORS | Origin reflection + credentials |

---

## Install

```bash
pip install apifuzz
```

Or with Docker:

```bash
docker pull dragonday3/apifuzz
docker run --rm dragonday3/apifuzz --help
```

---

## Quick Start

```bash
# Scan with an OpenAPI spec
apifuzz openapi.yaml --target https://api.example.com

# With bearer auth
apifuzz openapi.yaml --target https://api.example.com --auth-type bearer --token eyJhbGc...

# BOLA cross-user test (requires two accounts)
apifuzz openapi.yaml --target https://api.example.com \
  --auth-type bearer --token USER_A_TOKEN \
  --second-token USER_B_TOKEN

# Output formats
apifuzz openapi.yaml --target https://api.example.com --output sarif --out-file results.sarif
apifuzz openapi.yaml --target https://api.example.com --output html  --out-file report.html
apifuzz openapi.yaml --target https://api.example.com --output json  --out-file findings.json

# Run specific checks only
apifuzz openapi.yaml --target https://api.example.com --checks bola,auth,cors

# Scan a HAR file (from browser DevTools)
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
  --out-file, -f TEXT        Output file path (default: stdout for json/sarif)
  --concurrency, -c INT      Max concurrent HTTP requests [default: 10]
  --rate-limit FLOAT         Max requests per second [default: 10.0]
  --timeout FLOAT            HTTP request timeout in seconds [default: 15.0]
  --checks TEXT              Comma-separated check IDs or 'all' [default: all]
  --quiet, -q                Suppress progress output
  --help                     Show this message and exit.
```

---

## CI/CD Integration

### GitHub Actions — SARIF upload (findings show inline on PRs)

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

Findings appear in the **Security → Code Scanning** tab of your repo, with annotations directly on the API spec file.

---

## Python SDK

```python
import asyncio
from apifuzz.scanner import Scanner
from apifuzz.models.endpoint import AuthConfig
from apifuzz.reporters.sarif import SARIFReporter

auth = AuthConfig(type="bearer", token="your-token")
scanner = Scanner(
    spec_path="openapi.yaml",
    base_url="https://api.example.com",
    auth=auth,
    checks=["bola", "auth", "injection"],
)

findings = asyncio.run(scanner.run())

for f in findings:
    print(f"{f.severity.value.upper()}: {f.title} [{f.owasp_category.value}]")

# Export SARIF
SARIFReporter().write(findings, "results.sarif")
```

---

## Output Formats

### SARIF 2.1 (for GitHub/GitLab/Azure DevOps)

Native integration with GitHub Code Scanning. Findings appear inline on pull requests with severity, description, and remediation guidance.

### JSON

Array of findings with full evidence, remediation, and OWASP category mapping.

### HTML

Dark-theme interactive report with collapsible findings, severity badges, evidence blocks, and remediation guidance.

---

## Verifying Against Real Vulnerable APIs

```bash
# Test against OWASP crAPI (deliberately vulnerable)
docker run -d --name crapi -p 8888:8888 crapi/crapi:latest
apifuzz ./crapi-openapi.yaml --target http://localhost:8888 \
  --output html --out-file crapi-report.html

# Test against vAPI
docker run -d --name vapi -p 9090:80 roottusk/vapi
apifuzz ./vapi-openapi.yaml --target http://localhost:9090 --output sarif
```

---

## Architecture

```
Input Parsers          → Endpoint models
  OpenAPI 3.x/Swagger 2.x
  HAR file
  Postman Collection v2

Check Engine           → TestCase list
  7 OWASP checks (bola, auth, mass_assignment, ssrf,
                  injection, rate_limit, cors)

Async Executor         → TestResult list
  httpx AsyncClient
  Semaphore concurrency control
  Token-bucket rate limiting
  Auth injection (bearer/apikey/basic)

Response Analyzer      → Finding list
  Per-check detection heuristics
  Rate limit burst aggregation
  Severity-based dedup

Reporters
  SARIF 2.1 (GitHub/GitLab/Azure DevOps)
  JSON (machine-readable)
  HTML (interactive dark-theme report)
```

---

## Development

```bash
git clone https://github.com/dragonday3/apifuzz
cd apifuzz
pip install -e ".[dev]"
pytest --cov=apifuzz tests/
```

---

## License

MIT
