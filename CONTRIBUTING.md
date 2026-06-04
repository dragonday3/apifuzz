# Contributing to apifuzz

Thanks for your interest in contributing. This document covers how to set up the project, submit changes, and the standards we hold contributions to.

## Development Setup

```bash
git clone https://github.com/dragonday3/apifuzz.git
cd apifuzz
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest tests/ -q

# With coverage
pytest --cov=apifuzz --cov-report=term-missing tests/

# Specific module
pytest tests/checks/test_injection.py -v
```

All PRs must keep the test suite green across Python 3.10, 3.11, and 3.12.

## Adding a New Check

1. Create `src/apifuzz/checks/your_check.py` implementing the `BaseCheck` interface
2. Add corresponding tests in `tests/checks/test_your_check.py` (aim for ≥10 tests)
3. Register the check in `src/apifuzz/engine/runner.py`
4. Document the check in `README.md` under the checks table
5. Map it to an OWASP API Top 10 category

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
