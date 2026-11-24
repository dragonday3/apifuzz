# fuzzowl

**API Security Testing Framework** — Give it an OpenAPI spec, get back OWASP API Top 10 findings, SARIF output, and CI/CD integration in minutes.

[![CI](https://github.com/dragonday3/fuzzowl/actions/workflows/ci.yml/badge.svg)](https://github.com/dragonday3/fuzzowl/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010-red.svg)](https://owasp.org/API-Security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)


**Documentation: [dragonday3.github.io/fuzzowl](https://dragonday3.github.io/fuzzowl/)**

> **Formerly `apifuzz`.** Renamed in 0.2.0, before its first package release, because an unrelated OWASP API
> scanner already publishes `apifuzz` on PyPI with the same command and module name. The old
> `github.com/dragonday3/apifuzz` links redirect here. Results measured before the rename (v0.1.0 and both
> crAPI runs) keep the old name and `APIFUZZ-` rule ids; the rename changed no detection code.

---

## What It Does

fuzzowl takes any API spec (OpenAPI, HAR, Postman) → generates semantic security test cases → executes them asynchronously → maps results to OWASP API Top 10 → outputs SARIF (shows findings inline on GitHub PRs), JSON, or HTML.

No wordlists. No spray-and-pray. Test cases are generated from your actual schema — field names, types, and endpoint semantics drive the payloads. Checks only generate requests; every finding is decided by comparing the probe's response with a normal authenticated request, a control, or a follow-up read ([how it works](https://dragonday3.github.io/fuzzowl/how-it-works/)).

![fuzzowl HTML report from a scan of the VAmPI vulnerable API](assets/fuzzowl-report.png)
<sub>HTML report from an authenticated scan of [VAmPI](https://github.com/erev0s/VAmPI) (rate-limit findings trimmed to one for space). Credentials in the request are masked.</sub>

**Checks implemented** (mapped to the [OWASP API Security Top 10 — 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/); each links to what it sends, how it decides and its limits):

| ID | OWASP category (2023) | What it tests |
|----|-----------------------|---------------|
| [`bola`](https://dragonday3.github.io/fuzzowl/checks/bola/) | API1 — Broken Object Level Authorization | User B reading or changing user A's objects (`--second-token`), including objects A creates during the scan; ID enumeration (tentative) |
| [`auth`](https://dragonday3.github.io/fuzzowl/checks/auth/) | API2 — Broken Authentication | No/invalid/empty credentials, malformed scheme; JWT `alg:none`, unverified signature, `kid` traversal, weak HS256 key cracked offline |
| [`user_enum`](https://dragonday3.github.io/fuzzowl/checks/user-enum/) | API2 — Broken Authentication | Login answers differently for an existing username than for unknown lookalikes |
| [`mass_assignment`](https://dragonday3.github.io/fuzzowl/checks/mass-assignment/) | API3 — Broken Object Property Level Authorization | Privileged fields (`role`, `isAdmin`, …) injected into bodies, confirmed stored by a follow-up `GET` |
| [`data_exposure`](https://dragonday3.github.io/fuzzowl/checks/data-exposure/) | API3 — Broken Object Property Level Authorization | Secrets (passwords, keys, tokens, card numbers) in responses; fields the spec doesn't document (tentative) |
| [`rate_limit`](https://dragonday3.github.io/fuzzowl/checks/rate-limit/) | API4 — Unrestricted Resource Consumption | 50-request bursts; unthrottled guessing on login/OTP/reset operations (tentative) |
| [`redos`](https://dragonday3.github.io/fuzzowl/checks/redos/) | API4 — Unrestricted Resource Consumption | Regex backtracking on email/URL/pattern fields (`--time-based` only) |
| [`bfla`](https://dragonday3.github.io/fuzzowl/checks/bfla/) | API5 — Broken Function Level Authorization | Operations the spec marks as privileged, called with `--low-priv-token` |
| [`ssrf`](https://dragonday3.github.io/fuzzowl/checks/ssrf/) | API7 — Server Side Request Forgery | Cloud-metadata and internal URLs in URL-type parameters; blind probes with `--oob-url` |
| [`cors`](https://dragonday3.github.io/fuzzowl/checks/cors/) | API8 — Security Misconfiguration | Origin reflection with credentials allowed |
| [`inventory`](https://dragonday3.github.io/fuzzowl/checks/inventory/) | API9 — Improper Inventory Management | `.env`, Spring actuator, expvar/metrics/server-status, shadow specs, neighbouring API versions (once per scan) |
| [`injection`](https://dragonday3.github.io/fuzzowl/checks/injection/) | *(no 2023 API category; OWASP Top 10 A03:2021 Injection)* | SQLi (error, boolean, time-based), NoSQLi, SSTI and command injection (computed canaries), reflected XSS |

Coverage: API1, API2, API3, API4, API5, API7, API8 and API9. API6 (business flows) and API10 (unsafe consumption) are not tested. Known gaps: [comparison and limitations](https://dragonday3.github.io/fuzzowl/comparison/).

### Benchmark: the VAmPI vulnerable API (erev0s/VAmPI)

Scored against [VAmPI](https://github.com/erev0s/VAmPI)'s own list of 9 documented vulnerabilities. The scan runs against the vulnerable build and against the same API with its flaws switched off. Method and reproduction: [`benchmarks/`](benchmarks/README.md). Latest run: [`benchmarks/results/vampi.md`](benchmarks/results/vampi.md).

| | v0.1.0 | current, default scan | current, `--time-based` |
|---|---|---|---|
| Documented vulnerabilities detected | 0 / 9 | 7 / 9: SQLi, BOLA, debug-endpoint data exposure, user enumeration, rate limiting, weak JWT signing key (firm); unauthorized password change (tentative) | 8 / 9: the same plus RegexDoS (firm) |
| False positives, vulnerable build | 25 with tokens, 12 without | 0 | 0 |
| False positives, secure build | 25 with tokens, 12 without | 0 | 0 |

The weak-key and RegexDoS checks were written after VAmPI listed both as uncovered, and two earlier rules were changed after benchmark runs; all disclosed in [`benchmarks/`](benchmarks/README.md) (the weak key is found because VAmPI's key is in the bundled public wordlist, at rank 2,836 of 10,000). Missed: mass assignment on registration (stored, but nothing the API returns shows it).

### Benchmark: OWASP crAPI (held-out)

[crAPI](https://github.com/OWASP/crAPI) was added after the VAmPI work and measured once **before any rule was tuned for it** (held-out), so it shows how fuzzowl does on an API it wasn't developed against. The fixes that run prompted are generic but benchmark-motivated, so the after-tuning number is shown separately. Scored against crAPI's 18 documented challenges. crAPI has no fixed build, so every finding outside that list was re-checked by hand. Details: [`benchmarks/`](benchmarks/README.md#crapi-held-out-target), [`benchmarks/results/crapi.md`](benchmarks/results/crapi.md).

| crAPI (18 documented challenges) | held-out (`b21ea70`; reproduced at `5a117ab`) | after tuning (`d8653f0`) |
|---|---|---|
| Documented challenges detected | 5 / 18: vehicle-location BOLA, unauthenticated order access, JWT `alg:none` accepted (firm); video internal property exposed, admin video delete by a normal user (tentative, via the BOLA probe) | 7 / 18 (4 firm): also mechanic-report BOLA (firm, an id in a query param) and OTP brute force (tentative, weak evidence: the same signal fires on crAPI's protected v3 endpoint) |
| ...among the 14 fuzzowl has a check for | 5 / 14 | 7 / 14 |
| Findings outside the documented list | 39: 29 real (no rate limiting, `/.env` with DB credentials, login user enumeration, other users' orders), **10 false positives** | 38: 32 real, **6 false positives** (all tentative) |

Held-out misses included BOLA through a query parameter (detected after tuning), SQLi/NoSQLi on the coupon endpoints, mass assignment through `PUT`, and SSRF without an out-of-band collector. They are listed in [`benchmarks/`](benchmarks/README.md#crapi-held-out-target).

**Confidence.** Each finding is `firm` (confirmed by a comparison: an authenticated baseline request, the first user's object, a follow-up `GET`, or a true/false pair) or `tentative` (a plausible signal to verify by hand). In SARIF, tentative findings are `note`s under a separate `<rule>/tentative` rule with medium security-severity, so GitHub's default check threshold (High) doesn't fail on them. `--min-confidence firm` hides them.

---

## Install

> **Not on PyPI.** The `fuzzowl` package on PyPI is a different, unrelated project — do not `pip install fuzzowl`. Install from this repository instead.

```bash
pip install "git+https://github.com/dragonday3/fuzzowl.git"

# or from a clone
git clone https://github.com/dragonday3/fuzzowl
cd fuzzowl
pip install -e .            # add ".[dev]" for tests

# or Docker, built locally
docker build -t fuzzowl .
docker run --rm fuzzowl --help
```

---

## Quick Start

The spec (or HAR/Postman file) provides the paths; `--target` is the base URL only (`https://api.example.com`, not `https://api.example.com/v1/weather`).

```bash
# See what would be sent, without sending anything
fuzzowl openapi.yaml --target https://api.example.com --dry-run

# Scan with a bearer token; JSON to stdout
fuzzowl openapi.yaml --target https://api.example.com --token eyJhbGc...

# Cross-user BOLA tests (two accounts), HTML report
fuzzowl openapi.yaml --target https://api.example.com \
  --token USER_A_TOKEN --second-token USER_B_TOKEN \
  --output html --out-file report.html

# SARIF for GitHub code scanning; fail on high or worse (the default)
fuzzowl openapi.yaml --target https://api.example.com \
  --output sarif --out-file results.sarif --fail-on high

# No spec? A HAR recording or a Postman collection works too
fuzzowl recording.har --target https://api.example.com
```

**Safety defaults:** `PUT`/`PATCH`/`DELETE` are skipped unless `--allow-destructive`; `POST` endpoints are tested and create records (including a 50-request rate-limit burst per endpoint; leave `rate_limit` out of `--checks` to avoid it). Every request stays on the `--target` origin, redirects included; TLS is verified; credentials are masked in reports. Exit codes: `0` clean, `1` a finding at or above `--fail-on`, `2` every request failed (inconclusive). Details: [safety and scope](https://dragonday3.github.io/fuzzowl/safety/).

## Documentation

- [Quickstart](https://dragonday3.github.io/fuzzowl/quickstart/): install, first scan, reading the report, HAR workflow
- [How it works](https://dragonday3.github.io/fuzzowl/how-it-works/): pipeline, baselines, firm vs tentative, scan passes, resource linking, redaction, Python API
- [Checks](https://dragonday3.github.io/fuzzowl/checks/): one page per check
- [CLI reference](https://dragonday3.github.io/fuzzowl/reference/cli/) (generated from the CLI) and [output formats and exit codes](https://dragonday3.github.io/fuzzowl/reference/output/)
- [CI integration](https://dragonday3.github.io/fuzzowl/ci/): GitHub Actions + SARIF upload, GitLab, `--fail-on`, `.fuzzowl-ignore.yaml`
- [Benchmarks](https://dragonday3.github.io/fuzzowl/benchmarks/) and [comparison and limitations](https://dragonday3.github.io/fuzzowl/comparison/)
- [Contributing and architecture](https://dragonday3.github.io/fuzzowl/contributing/) ([CONTRIBUTING.md](CONTRIBUTING.md))

---

## Authorized Use Only

fuzzowl sends attack payloads (injection, SSRF, auth bypass, request bursts). Only scan APIs you own or have explicit written permission to test.

---

## License

MIT
