# CI integration

apifuzz is a command that exits non-zero when it finds something at or above `--fail-on`, so any CI system can
run it. It is not on PyPI yet: install it from the GitHub repository (pin a commit or tag for reproducible
builds, e.g. `git+https://github.com/dragonday3/apifuzz.git@<commit>`).

!!! warning "Scan a disposable or staging environment"
    A default scan sends a 50-request burst to every endpoint and creates records through `POST`
    ([Safety and scope](safety.md)). Against shared environments, use `--checks` without `rate_limit` and/or
    `--max-requests`. Add `--insecure` if staging uses a self-signed certificate; otherwise every request fails
    and the job exits `2`.

## GitHub Actions with code scanning

Findings appear in **Security → Code scanning** and as annotations on pull requests.

```yaml
name: API security scan

on: [pull_request]

jobs:
  apifuzz:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload SARIF
      actions: read            # needed by upload-sarif in private repositories
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install apifuzz (from GitHub; not on PyPI yet)
        run: pip install "git+https://github.com/dragonday3/apifuzz.git"

      - name: Run API security scan
        run: |
          apifuzz openapi.yaml \
            --target "${{ secrets.API_BASE_URL }}" \
            --token "${{ secrets.API_TEST_TOKEN }}" \
            --second-token "${{ secrets.API_TEST_TOKEN_B }}" \
            --output sarif --out-file apifuzz.sarif \
            --fail-on high

      - name: Upload SARIF to code scanning
        # Upload even when the scan step failed on findings; skip if no report was written (exit 2).
        if: always() && hashFiles('apifuzz.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: apifuzz.sarif
```

Notes:

- Keep credentials in repository secrets. `--second-token` is optional (it enables cross-user BOLA tests).
- The job fails when a finding at or above `--fail-on` is reported (`--fail-on never` to only upload). Code
  scanning applies its own threshold to the uploaded alerts by `security-severity`; tentative findings are
  uploaded as `note`s with medium severity, so they don't fail that check
  ([SARIF details](reference/output.md#sarif-210)).
- SARIF results carry stable `partialFingerprints`, so a recurring finding updates the same alert instead of
  opening a new one.

## GitLab CI

```yaml
api-security:
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends git
    - pip install "git+https://github.com/dragonday3/apifuzz.git"
  script:
    - apifuzz openapi.yaml --target "$API_BASE_URL" --token "$API_TEST_TOKEN"
        --output html --out-file apifuzz-report.html --fail-on high
  artifacts:
    when: always
    paths:
      - apifuzz-report.html
```

Store `API_BASE_URL` and `API_TEST_TOKEN` as masked CI/CD variables. The `slim` image has no `git`, which
`pip install git+...` needs. apifuzz writes SARIF, JSON and HTML; it does not produce GitLab's own security
report format, so keep the report as a job artifact (or add a second run with `--output sarif` for tools that
read SARIF).

## Failing the build: `--fail-on`

`--fail-on` sets the lowest severity that makes the run exit `1`: `critical`, `high` (default), `medium`, `low`,
`info`, or `never`. Findings hidden by `--min-confidence firm` or suppressed by the ignore file don't count. An
exit code `2` means every request failed: treat it as a broken job, not a clean result
([exit codes](reference/output.md#exit-codes)).

## Accepting known findings

A finding you've reviewed and accepted shouldn't fail every later build. Record it in `.apifuzz-ignore.yaml`:

```yaml
ignore:
  - rule_id: APIFUZZ-RATE-001
    endpoint: "GET /health"            # spec operation; globs allowed; omit for every endpoint
    reason: rate limited at the gateway, not the app
    expires: 2027-01-31                # optional: the entry stops applying after this date
```

- `rule_id` and `endpoint` are glob patterns (`APIFUZZ-RATE-*`, `GET /books/*`). They match the finding's rule
  id and its spec operation, so the entry keeps working although probe URLs change between runs.
- After `expires`, an entry no longer suppresses anything, and every run warns about it, so accepted risks get
  reviewed again.
- The file in the working directory is used automatically when it exists; `--ignore-file PATH` points to
  another one. An invalid file (no `rule_id`, a bad date) stops the run before anything is sent.

**Bootstrap it** from a scan: `--write-ignore .apifuzz-ignore.yaml` writes one entry per rule and operation
found, with `reason: "TODO: why this is accepted"`, and exits `0`. Entries already in the file are kept as they
are (reasons, expiry dates); only new ones are added. Review the file, fill in each reason (and an `expires`
date where it fits), and commit it.
