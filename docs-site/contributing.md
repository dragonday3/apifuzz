# Contributing and architecture

The short version is in [CONTRIBUTING.md](https://github.com/dragonday3/apifuzz/blob/main/CONTRIBUTING.md); this
page adds the architecture and the rules a change has to follow. Security issues in apifuzz itself go through
[private vulnerability reporting](https://github.com/dragonday3/apifuzz/security/advisories/new), not public
issues ([SECURITY.md](https://github.com/dragonday3/apifuzz/blob/main/SECURITY.md)).

## Development setup

```bash
git clone https://github.com/dragonday3/apifuzz.git
cd apifuzz
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

pytest tests/ -q                   # unit tests + end-to-end scans against a mocked API (tests/e2e)
ruff check .                       # lint
mypy src                           # type-check
pytest --cov=apifuzz --cov-report=term-missing tests/
pytest tests/checks/test_injection.py -v
```

CI runs ruff, mypy and the tests on Python 3.10, 3.11 and 3.12 on every push and pull request.

### Documentation

The site is built with MkDocs Material from `docs-site/` (`mkdocs.yml` at the repository root):

```bash
pip install -e ".[docs]"
mkdocs serve                       # http://127.0.0.1:8000
mkdocs build --strict              # what CI runs: any warning fails
```

The [CLI reference](reference/cli.md) is generated from the Typer app. After changing an option or its help text,
regenerate it and commit the result; the docs workflow regenerates it and fails if the committed file differs:

```bash
python -m typer apifuzz.cli utils docs --name apifuzz --output docs-site/reference/cli.md
```

The [changelog](changelog.md) page includes `CHANGELOG.md` directly, so edit only that file.

## Architecture

```text
src/apifuzz/
  cli.py            Typer CLI: options, --fail-on, ignore file, exit codes, console output
  scanner.py        Scanner.run: parse, scope, generate, the five executor passes, analyze, scrub credentials
  parsers/          OpenAPI 3 / Swagger 2, HAR, Postman v2  ->  list[Endpoint]
  payloads/         example request bodies from JSON schemas
  checks/           one module per check: generate(endpoint, auth) -> list[TestCase]
  executor.py       TestCase / TestResult, httpx client, scope lock, rate limiter, budget, retries
  analyzer.py       every detection rule, baselines, follow-ups, resource linking, dedup
  jwt_forge.py      stdlib-only JWT forging and offline HS256 cracking (+ jwt_secrets.txt)
  redact.py         masking of credentials in reports
  ignore.py         .apifuzz-ignore.yaml
  reporters/        json, sarif, html (template in templates/)
  models/           Endpoint, Parameter, AuthConfig, Finding
```

The pipeline is described in [How it works](how-it-works.md). The rules that keep it correct:

- **Checks only generate requests; they never decide findings.** Detection lives entirely in `analyzer.py`,
  dispatched on `TestCase.check_id`. A check passes context to the analyzer in `TestCase.extra` (`strategy`,
  `payload`, `injection_type`, `pair_id`/`polarity`, ...); the two sides are coupled by those keys.
- **Checks send `endpoint.body_example`, never `body_schema`.** Build URLs with `self._build_url()`: it fills
  every path parameter (override, then example, then `"1"`) and percent-encodes values, so a payload containing
  `/` stays in one segment.
- **Auth modes.** `TestCase.auth_mode` is `default` (the executor adds the configured credentials), `none`
  (strips them, including a custom API-key header) or `override` (sends `tc.headers` untouched). Probes that set
  their own credentials (auth, BOLA, BFLA) must use `none` or `override`; v0.1.0's false positives came from the
  configured token overwriting them. Use `executor.auth_headers()` to build a second user's header in the same
  scheme.
- **Compare with the baseline.** `Analyzer._baseline(result)` / `_baseline_body(result)` return the endpoint's
  normal response; content the endpoint always returns is never a finding.
- **Decide the confidence.** Every new detector emits `firm` (confirmed by a comparison) or `tentative`.
- **Use the redaction helpers.** Findings use `_request_text(result)` and `_response_text(result)`, never the raw
  label or body, so credentials are masked and truncation is stated.
- **Extra executors share the scan's options.** Create them with `Executor(auth, n, **self._executor_opts)` so
  the scope lock, request budget, TLS, proxy and retries apply.

## Adding a check

A new check touches these places:

1. `src/apifuzz/checks/<your_check>.py`: subclass `BaseCheck`, set `check_id` and `name`, implement
   `generate(endpoint, auth) -> list[TestCase]` (or `generate_global(endpoints, auth)` for probes sent once per
   scan, like `inventory`).
2. Register it in `_ALL_CHECKS` in `src/apifuzz/scanner.py`. If its detector compares with the baseline, add the
   check id to `_BASELINE_CHECKS`.
3. Add a `_check_<id>` handler to `Analyzer._dispatch` (or an aggregate pass for pairs and groups), with an OWASP
   API Top 10 (2023) category and a stable `rule_id`. `rule_id` is what SARIF and the ignore file key on.
4. Add the rule prefix to `RULE_CHECK` in `benchmarks/run.py`, so benchmark scoring knows which check it belongs
   to.
5. Tests: generation in `tests/checks/test_<your_check>.py`, detection in `tests/test_analyzer.py`, and an
   end-to-end case in `tests/e2e/` against the mock API (one secure response with no finding, one vulnerable
   response with the finding). The `mock_api` fixture in `tests/e2e/conftest.py` serves a configurable
   petstore-shaped API.
6. Documentation: a page in `docs-site/checks/` (what it sends, how it decides, false-positive guards,
   remediation, limitations), a row in the [checks overview](checks/index.md) and the README checks table.

Every bug fix needs a regression test that fails before the fix and passes after it.

## Benchmark honesty

Numbers in the README and on this site come only from `benchmarks/run.py` output committed under
`benchmarks/results/`. Any rule change motivated by benchmark output must be disclosed in `benchmarks/README.md`
under "Rules changed after seeing benchmark output"; never tune to a benchmark target silently. The held-out crAPI
number stays published next to any after-tuning number ([Benchmarks](benchmarks.md)).

## Releases

The version lives only in `src/apifuzz/__init__.py`. Pushing a tag `vX.Y.Z` runs the release workflow, which is
set up to publish to PyPI as `apifuzz-scanner`, push an image to GHCR and create a GitHub release from the
changelog section. Nothing has been published to PyPI or GHCR yet (v0.1.0 is a git tag only). Details:
[DEPLOY.md](https://github.com/dragonday3/apifuzz/blob/main/DEPLOY.md).
