# `apifuzz`

Scan an API for OWASP API Top 10 security issues.

**Usage**:

```console
$ apifuzz [OPTIONS] {spec}
```

**Arguments**:

* `spec <str>`: Path to OpenAPI spec (.yaml/.json), HAR file, or Postman collection  [required]

**Options**:

* `-t, --target <str>`: Base URL of the API to test (e.g. https://api.example.com)  [required]
* `--auth-type <str>`: Auth type: none | bearer | apikey | basic (default: bearer with --token, else none)
* `--token <str>`: Auth token / credentials
* `--second-token <str>`: Second token for BOLA cross-user tests
* `--low-priv-token <str>`: Low-privilege user&#x27;s token for BFLA tests (--token should be privileged)
* `--header-name <str>`: Header name for apikey auth  [default: Authorization]
* `-o, --output <str>`: Output format: json | sarif | html  [default: json]
* `-f, --out-file <str>`: Output file path (default: stdout for json/sarif)
* `-c, --concurrency <int>`: Max concurrent HTTP requests  [default: 10]
* `--rate-limit <float>`: Max requests per second (rate_limit check bursts are exempt)  [default: 10.0]
* `--timeout <float>`: HTTP request timeout in seconds  [default: 15.0]
* `--checks <str>`: Comma-separated check IDs or &#x27;all&#x27;  [default: all]
* `--min-confidence <str>`: Report only findings at or above this confidence: tentative (all) | firm  [default: tentative]
* `--time-based`: Add time-based SQLi and ReDoS probes, sent one at a time (each waits ~5 s on a vulnerable target)
* `--allow-destructive`: Also test PUT/PATCH/DELETE endpoints (they modify or delete data)
* `--dry-run`: Print the test plan (requests per check/endpoint), send nothing
* `--include <list[str]>`: Only test paths matching this glob (repeatable), e.g. &#x27;/api/v1/*&#x27;. Matches the path only, no method
* `--exclude <list[str]>`: Skip paths matching this glob (repeatable), e.g. &#x27;/admin/*&#x27;. Matches the path only
* `--max-requests <int range>`: Stop sending after this many requests  [x&gt;=1]
* `--retries <int range>`: Retries on 429/503 (honours Retry-After, else backoff)  [default: 2; x&gt;=0]
* `--max-body <int range>`: Keep this many characters of each response body; detection sees only these  [default: 8192; x&gt;=1]
* `--insecure`: Skip TLS certificate verification
* `--proxy <str>`: Send traffic through a proxy, e.g. http://127.0.0.1:8080
* `--oob-url <str>`: Collector URL you control (interactsh, webhook) for blind SSRF payloads
* `--fail-on <str>`: Exit 1 if any finding is at least this severe: critical | high | medium | low | info | never  [default: high]
* `--ignore-file <str>`: Accepted findings to suppress (default: .apifuzz-ignore.yaml if present)
* `--write-ignore <str>`: Write an ignore file accepting every finding of this scan, then exit 0
* `-q, --quiet`: Suppress progress output
* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.
