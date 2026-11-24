# Changelog

All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

Hardening release: v0.1.0's findings could not be trusted (on the VAmPI benchmark it detected 0 of 9 documented
vulnerabilities and reported 25 false positives per build with auth tokens). This release fixes correctness, removes
false positives, makes scans safe to point at real systems, adds coverage, and measures the result.

### Benchmark
- `benchmarks/`: reproducible scoring against VAmPI's own list of documented vulnerabilities, on its vulnerable
  and secure builds. Current: **6/9 detected** (5 firm, 1 tentative), 6/7 of those apifuzz has a check for,
  **0 false positives on both builds**. Two rules changed after seeing benchmark output; both are disclosed in
  `benchmarks/README.md`.
- Second benchmark target: OWASP crAPI, measured before any tuning (held-out): 5/18 documented challenges
  detected (3 firm), 10 false positives among 39 findings outside the documented list.

### Fixed (correctness)
- `--token` without `--auth-type` now authenticates as bearer. Before, the default `none` silently ignored the token and scanned unauthenticated; `--auth-type none` together with a token is now an error.
- The configured token no longer overwrites the auth and cross-user BOLA probes' headers (v0.1.0 reported false
  CRITICAL bypasses on secure APIs). The second user's credential is sent in the same scheme.
- Request bodies are built from schema examples instead of sending the JSON schema itself; path parameters are
  always filled and percent-encoded.
- OWASP labels match the 2023 list (mass assignment is API3; injection maps to A03:2021).
- SSTI/command-injection detection uses computed canaries instead of matching any `49` or `$ `; NoSQLi and XSS
  are actually detected; a lone-quote payload catches SQL errors that `' OR '1'='1` hides.
- Rate limiter is concurrency-safe; rate-limit bursts aren't throttled, run last, one endpoint at a time.
- The HTML report template ships in the package (wheel installs could not render HTML); the Docker image builds.
- The "empty bearer" auth probe is actually sent (its trailing space made it an illegal header).
- `Endpoint.response_schema` holds plain dicts and lists instead of jsonref proxies, so it serialises with
  `json.dumps`; a recursive `$ref` is kept as `{"$ref": ...}` where it loops back.

### Changed (fewer false positives)
- Findings carry `confidence: firm | tentative`; tentative findings are SARIF notes under a separate
  medium-severity rule, and `--min-confidence firm` hides them.
- The auth check reads the spec's `security` requirements and skips public endpoints; a bypass must look like
  the authenticated response.
- BOLA: cross-user findings need user B to get user A's object; ID enumeration alone is not a finding.
- Mass assignment needs the injected value, confirmed by a follow-up GET; blind SQLi (boolean, and time-based
  with `--time-based`); rate limiting honours `429`, `Retry-After` and `X-RateLimit-*`.

### Added (safety and scope)
- Safe by default: `PUT`/`PATCH`/`DELETE` are skipped unless `--allow-destructive`; `--dry-run` prints the plan.
- Scope lock: every request (redirects included) stays on the `--target` origin; `--include`/`--exclude` globs.
- `--max-requests`, `429`/`503` retries honouring `Retry-After`; TLS verified by default (`--insecure`), `--proxy`.
- `--max-body` (default 8192 characters) sets how much of each response body is kept for detection; it used to be
  a fixed 8 KB.
- Credentials are redacted in every report; findings show the request as sent.
- A scan in which every request failed exits `2` (inconclusive) instead of reporting a clean result.

### Added (coverage)
- `data_exposure` (API3), `user_enum` (API2), `bfla` with `--low-priv-token` (API5), `inventory` (API9, once per
  scan), and blind SSRF via `--oob-url`. Coverage: API1, 2, 3, 4, 5, 7, 8 and 9.
- JWT attacks (API2), when the configured bearer token is a JWT: unverified signature (garbage signature),
  `kid` path traversal signed with a null key, and — for HS256 tokens — a weak signing key cracked **offline**
  (no requests) against a bundled public wordlist (wallarm/jwt-secrets, MIT, top 10000 verbatim entries; see
  `src/apifuzz/jwt_secrets.README.md`). A cracked key is proved by re-signing the token (same identity) and by
  an expired copy; the guessed key is masked in the evidence like any other credential. This joins the existing
  `alg:none` probe; all keep the `APIFUZZ-AUTH-JWT*` rule-id family. RS256→HS256 confusion and `jku` injection
  are **not** implemented (they need the server's published key or an attacker-hosted JWKS, which the current
  request model does not provide cleanly).
- The blind-SSRF probe map (`apifuzz-<id>` → `METHOD /path [param]`) is in every report, not only the console:
  SARIF `runs[0].properties.oobProbes`, an HTML section, and in JSON an object
  `{"findings": [...], "oob_probes": {...}}` (only with `--oob-url`; otherwise JSON stays a plain array).

### Added (CI/CD)
- SARIF `partialFingerprints` (stable across runs), `--fail-on <severity>`, `.apifuzz-ignore.yaml` accepted
  findings with expiry (`--write-ignore` bootstraps one).
- CI runs ruff and mypy plus the end-to-end suite; a weekly benchmark workflow fails on regressions.
- Release workflow: PyPI as `apifuzz-scanner` (trusted publishing) and `ghcr.io/dragonday3/apifuzz`.

## [0.1.0] - 2026-06-03

Initial version: OpenAPI/Swagger, HAR and Postman parsers; 7 checks (bola, auth, mass_assignment, ssrf,
injection, rate_limit, cors); JSON, SARIF and HTML reports; Typer CLI.
