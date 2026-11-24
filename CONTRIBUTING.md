# Contributing to fuzzowl

Thanks for your interest in contributing. This document covers how to set up the project, submit changes, and the standards we hold contributions to.

## Development Setup

```bash
git clone https://github.com/dragonday3/fuzzowl.git
cd fuzzowl
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest tests/ -q

# Lint and type-check (both must pass)
ruff check .
mypy src

# With coverage
pytest --cov=fuzzowl --cov-report=term-missing tests/

# Specific module
pytest tests/checks/test_injection.py -v
```

All PRs must keep the test suite green across Python 3.10, 3.11, and 3.12.

## Adding a New Check

Checks only generate requests; detection lives in the analyzer. A new check touches these places:

1. `src/fuzzowl/checks/your_check.py`: subclass `BaseCheck`, set `check_id` and `name`, and implement
   `generate(endpoint, auth) -> list[TestCase]` (or `generate_global(endpoints, auth)` for probes sent once per
   scan, like `inventory`). Build URLs with `self._build_url()` and bodies from
   `endpoint.body_example`. Pass context for the analyzer in `TestCase.extra`. If your probe sets its own
   auth headers, set `auth_mode="override"` (or `"none"`) so the configured token doesn't replace them.
2. Register it in `_ALL_CHECKS` in `src/fuzzowl/scanner.py`.
3. Add a `_check_<id>` handler to `Analyzer._dispatch` in `src/fuzzowl/analyzer.py`, with an OWASP API
   Top 10 (2023) category and a stable `rule_id`. Compare against `self._baseline_body(result)` so
   content the endpoint always returns isn't reported.
4. Tests: generation in `tests/checks/test_your_check.py`, detection in `tests/test_analyzer.py`, and an
   end-to-end case in `tests/e2e/` against the mock API (one secure response with no finding, one
   vulnerable response with the finding). Add the rule prefix to `RULE_CHECK` in `benchmarks/run.py`.
5. Docs: a page in `docs-site/checks/`, a row in `docs-site/checks/index.md` and the README checks table.

## Documentation

The website (https://dragonday3.github.io/fuzzowl/) is built with MkDocs Material from `docs-site/`:

```bash
pip install -e ".[docs]"
mkdocs build --strict      # CI fails on any warning
# after changing a CLI option or its help text, regenerate the CLI reference and commit it:
python -m typer fuzzowl.cli utils docs --name fuzzowl --output docs-site/reference/cli.md
```

## Submitting Changes

1. Fork the repo and create a feature branch: `git checkout -b feat/your-feature`
2. Write tests first (TDD preferred)
3. Keep commits atomic — one logical change per commit
4. Run the full test suite before opening a PR
5. Open a PR against `main` with a clear description of what and why

## PR Requirements

- [ ] Tests pass (`pytest tests/ -q`)
- [ ] New code has test coverage
- [ ] No new security vulnerabilities introduced
- [ ] README updated if behavior changes
- [ ] Commit messages are clear and descriptive

## Reporting Bugs

Open a GitHub issue with:
- Python version and OS
- Minimal reproduction steps
- Expected vs actual behavior
- Full error traceback if applicable

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).
