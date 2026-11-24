# Quickstart

## Install

!!! note "fuzzowl, not apifuzz"
    fuzzowl was called apifuzz before 0.2.0. The `apifuzz` package on PyPI is a different, unrelated scanner:
    install `fuzzowl`.

fuzzowl needs Python 3.10 or newer (CI tests 3.10, 3.11 and 3.12).

=== "PyPI"

    ```bash
    pip install fuzzowl
    ```

=== "Docker"

    ```bash
    docker run --rm ghcr.io/dragonday3/fuzzowl:latest --help
    # mount the directory holding your spec and the report
    docker run --rm -v "$(pwd):/data" ghcr.io/dragonday3/fuzzowl:latest /data/openapi.yaml \
      --target https://api.example.com --output sarif --out-file /data/results.sarif
    ```

=== "Straight from GitHub"

    ```bash
    pip install "git+https://github.com/dragonday3/fuzzowl.git"
    ```

=== "From a clone"

    ```bash
    git clone https://github.com/dragonday3/fuzzowl
    cd fuzzowl
    pip install -e .            # add ".[dev]" for the test tools
    ```

=== "Docker (build locally)"

    ```bash
    git clone https://github.com/dragonday3/fuzzowl && cd fuzzowl
    docker build -t fuzzowl .
    docker run --rm fuzzowl --help
    # mount the directory holding your spec and the report
    docker run --rm -v "$(pwd):/data" fuzzowl /data/openapi.yaml --target https://api.example.com \
      --output sarif --out-file /data/results.sarif
    ```

The package, the command and the Python module are all `fuzzowl`.

## What fuzzowl needs

1. **A description of the API**: an OpenAPI 3.x or Swagger 2.0 file (`.yaml`/`.json`), a HAR recording
   (`.har`) or a Postman collection v2 (`.json`/`.yaml` with `info` and `item`). fuzzowl is a test-case
   generator, not a traffic interceptor: it has to know which endpoints exist and what their parameters are
   before it can inject anything. A bare URL tells it nothing; `GET /weather?q=STRING` is what lets it try
   `q='; DROP TABLE--`.
2. **`--target`, the base URL only.** The spec provides the paths:

    ```text
    --target https://api.example.com             ✓
    --target https://api.example.com/v1/weather  ✗  (the path goes in the spec)
    ```

    `--target` is authoritative: hosts in the spec's `servers`, a HAR or a Postman file are ignored, and every
    request stays on that origin ([Safety and scope](safety.md)).

3. **Credentials**, if the API needs them: `--token` (bearer by default), or `--auth-type apikey
   --header-name X-API-Key --token ...`, or `--auth-type basic --token user:password`. Some checks need more
   than one account ([`--second-token`](checks/bola.md), [`--low-priv-token`](checks/bfla.md)).

## A first scan

Start with `--dry-run`: it prints what a scan would send and sends nothing. Using the Petstore spec from the
repository's test fixtures:

```console
$ fuzzowl tests/fixtures/petstore.yaml --target https://api.example.com --dry-run
                            Test plan (nothing sent)
+------------------------------------------------------------------------------+
| Endpoint                                        | Check           | Requests |
|-------------------------------------------------+-----------------+----------|
| GET /.env (not in spec)                         | inventory       |        1 |
| ...                                             |                 |          |
| GET /pets                                       | auth            |        4 |
| GET /pets                                       | baseline        |        1 |
| GET /pets                                       | cors            |        4 |
| GET /pets                                       | data_exposure   |        1 |
| GET /pets                                       | rate_limit      |       50 |
| GET /pets/{petId}                               | auth            |        4 |
| GET /pets/{petId}                               | baseline        |        1 |
| GET /pets/{petId}                               | bola            |        5 |
| GET /pets/{petId}                               | cors            |        4 |
| GET /pets/{petId}                               | data_exposure   |        1 |
| GET /pets/{petId}                               | injection       |       11 |
| GET /pets/{petId}                               | rate_limit      |       50 |
| ...                                             |                 |          |
| POST /pets                                      | auth            |        4 |
| POST /pets                                      | baseline        |        1 |
| POST /pets                                      | cors            |        4 |
| POST /pets                                      | injection       |       26 |
| POST /pets                                      | mass_assignment |        1 |
| POST /pets                                      | rate_limit      |       50 |
+------------------------------------------------------------------------------+
Total: 237 request(s) to https://api.example.com
Skipped: DELETE /pets/{petId} (destructive; use --allow-destructive)
```

The plan covers the first pass only: confirmation requests depend on responses (see
[scan passes](how-it-works.md#scan-passes)). Then run it for real against an API you may test:

```bash
# JSON to stdout (the default)
fuzzowl openapi.yaml --target https://staging.example.com --token "$API_TOKEN"

# an HTML report
fuzzowl openapi.yaml --target https://staging.example.com --token "$API_TOKEN" \
  --output html --out-file report.html

# cross-user BOLA tests with a second account
fuzzowl openapi.yaml --target https://staging.example.com \
  --token "$USER_A_TOKEN" --second-token "$USER_B_TOKEN"

# only some checks; no 50-request bursts
fuzzowl openapi.yaml --target https://staging.example.com --checks bola,auth,cors

# route traffic through Burp or ZAP to verify findings by hand
# (TLS is verified: trust the proxy's CA, or add --insecure)
fuzzowl openapi.yaml --target https://staging.example.com --proxy http://127.0.0.1:8080 --insecure
```

### No spec? Record a HAR

1. Open the browser's DevTools, **Network** tab.
2. Use the application so it calls the API (browse, search, log in...).
3. Right-click a request, **Save all as HAR with content**.
4. Scan the recording:

```bash
fuzzowl recording.har --target https://api.example.com
```

fuzzowl reads the recorded requests (method, path, query parameters, JSON bodies) as endpoints. Recorded URLs
are concrete (`/users/42`), so no path parameters are inferred from them; checks that probe path parameters
(BOLA ID probes, path injection) get more out of a spec. A Postman collection works the same way:
`fuzzowl collection.json --target https://api.example.com`.

## Reading the report

The console prints a findings table (tentative ones are marked) and a summary per severity. The JSON report
is a list of findings. This one is real output from a scan of the Petstore spec against a mocked API that
ignores credentials:

```json
{
  "title": "Broken Auth: No Auth accepted",
  "description": "Endpoint returned 2xx with no Authorization header.",
  "severity": "critical",
  "owasp_category": "API2:2023 - Broken Authentication",
  "endpoint_method": "GET",
  "endpoint_path": "https://api.example.com/pets",
  "request_sample": "# Auth: GET /pets [no auth header]\nGET https://api.example.com/pets",
  "response_sample": "{\"id\":1,\"name\":\"rex\",\"tag\":\"dog\"}",
  "evidence": "HTTP 200 returned with strategy: no_auth; matches the authenticated baseline (HTTP 200, 33 bytes)",
  "remediation": "Require valid authentication on all protected endpoints.",
  "rule_id": "FUZZOWL-AUTH-NO_AUTH",
  "confidence": "firm",
  "endpoint": "GET /pets",
  "parameter": ""
}
```

- `endpoint_path` is the probe's concrete URL; `endpoint` is the spec operation it belongs to.
- `evidence` says what decided the finding, here the comparison with the authenticated baseline.
- `request_sample` is the request as sent, with credentials masked.
- `confidence: tentative` means verify by hand before acting on it.

Every field is described in [Output formats](reference/output.md). The process exits `1` when a finding at or
above `--fail-on` (default `high`) is reported, `2` when every request failed, else `0`.

## Practice targets

Deliberately vulnerable APIs such as [VAmPI](https://github.com/erev0s/VAmPI) and
[OWASP crAPI](https://github.com/OWASP/crAPI) are good first targets. Run them locally with their own setup
instructions, then scan them with their OpenAPI spec:

```bash
fuzzowl ./target-openapi.yaml --target http://localhost:<port> \
  --allow-destructive --output html --out-file report.html
```

`--allow-destructive` is fine here because these targets are disposable (VAmPI, for example, resets its data
with `GET /createdb`; exclude that path with `--exclude /createdb` so a probe doesn't reset it mid-scan). The
[benchmark harness](benchmarks.md) automates this for both.

!!! warning "Git Bash on Windows rewrites `/paths`"
    Git Bash turns an argument that starts with `/` into a Windows path, so `--exclude /createdb` reaches fuzzowl
    as `C:/Program Files/Git/createdb` and excludes nothing. fuzzowl warns when a glob matches no path in the
    spec; when you see that warning, run with `MSYS_NO_PATHCONV=1 fuzzowl ...` or write the glob as `'*/createdb'`.
    PowerShell, cmd, macOS and Linux shells pass `/createdb` unchanged.
