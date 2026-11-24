# `apifuzz`

Scan an API for OWASP API Top 10 security issues.

**Usage**:

```console
$ apifuzz [OPTIONS] SPEC
```

**Arguments**:

* `SPEC`: [required]

**Options**:

* `-t, --target TEXT`: Base URL of the API to test (e.g. https://api.example.com)  [required]
* `--auth-type TEXT`: Auth type: none | bearer | apikey | basic
* `--token TEXT`: Auth token / credentials
* `--second-token TEXT`: Second token for BOLA cross-user tests
* `--low-priv-token TEXT`: Low-privilege user&#x27;s token for BFLA tests (--token should be privileged)
* `--header-name TEXT`: Header name for apikey auth  [default: Authorization]
* `-o, --output TEXT`: Output format: json | sarif | html  [default: json]
* `-f, --out-file TEXT`: Output file path (default: stdout for json/sarif)
* `-c, --concurrency INTEGER`: Max concurrent HTTP requests  [default: 10]
* `--rate-limit FLOAT`: Max requests per second (rate_limit check bursts are exempt)  [default: 10.0]
* `--timeout FLOAT`: HTTP request timeout in seconds  [default: 15.0]
* `--checks TEXT`: Comma-separated check IDs or &#x27;all&#x27;  [default: all]
* `--min-confidence TEXT`: Report only findings at or above this confidence: tentative (all) | firm  [default: tentative]
* `--time-based`: Add time-based SQLi and ReDoS probes, sent one at a time (each waits ~5 s on a vulnerable target)
* `--allow-destructive`: Also test PUT/PATCH/DELETE endpoints (they modify or delete data)
* `--dry-run`: Print the test plan (requests per check/endpoint), send nothing
* `--include TEXT`: Only test paths matching this glob (repeatable), e.g. &#x27;/api/v1/*&#x27;. Matches the path only, no method
* `--exclude TEXT`: Skip paths matching this glob (repeatable), e.g. &#x27;/admin/*&#x27;. Matches the path only
* `--max-requests INTEGER RANGE`: Stop sending after this many requests  [x&gt;=1]
* `--retries INTEGER RANGE`: Retries on 429/503 (honours Retry-After, else backoff)  [default: 2; x&gt;=0]
* `--max-body INTEGER RANGE`: Keep this many characters of each response body; detection sees only these  [default: 8192; x&gt;=1]
* `--insecure`: Skip TLS certificate verification
* `--proxy TEXT`: Send traffic through a proxy, e.g. http://127.0.0.1:8080
* `--oob-url TEXT`: Collector URL you control (interactsh, webhook) for blind SSRF payloads
* `--fail-on TEXT`: Exit 1 if any finding is at least this severe: critical | high | medium | low | info | never  [default: high]
* `--ignore-file TEXT`: Accepted findings to suppress (default: .apifuzz-ignore.yaml if present)
* `--write-ignore TEXT`: Write an ignore file accepting every finding of this scan, then exit 0
* `-q, --quiet`: Suppress progress output
* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.
