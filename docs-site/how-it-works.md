# How it works

## Pipeline

```text
spec file ──► parser ──► endpoints ──► checks generate test cases ──► executor sends them (5 passes)
                                                                              │
             reporters (JSON / SARIF / HTML) ◄── findings ◄── analyzer decides ◄┘
```

1. **Parse.** The format is detected from the file: `.har` is a HAR recording; a `.json`/`.yaml` file with
   `info` and `item` is a Postman collection; anything else is OpenAPI 3.x or Swagger 2.0. Each operation
   becomes an `Endpoint`: method, path, parameters (with type, example, `format`, `pattern`), a concrete
   request body (`body_example`, built from the schema's examples or taken from the recording), the documented
   2xx response schema, and whether the spec's `security` marks it as secured, public or undocumented.
   Path parameters always get a typed example (an untyped string becomes `"1"`).
2. **Scope.** Every endpoint's base URL is forced to `--target`. `PUT`, `PATCH` and `DELETE` operations are
   dropped unless `--allow-destructive`, and `--include`/`--exclude` path globs apply. Dropped operations are
   listed at the end of the scan ([Safety and scope](safety.md)).
3. **Generate.** Each enabled check turns each endpoint into test cases. **Checks only generate requests;
   they never decide findings.** They pass context (strategy, payload, probed parameter, pair ids) to the
   analyzer with the test case. `inventory` generates its probes once per scan instead of per endpoint. A
   required query parameter is added to every request of its endpoint, not only to the probes that test it.
4. **Send.** The executor sends the test cases with `httpx` in five passes (below), with a concurrency limit,
   a requests-per-second limit, retries, a request budget and a scope lock.
5. **Decide.** The analyzer turns responses into findings. Each check has a handler that compares the probe's
   response with something: the endpoint's baseline, a control request, the other half of a pair, or a
   follow-up read. Findings are deduplicated: the highest-severity one is kept per
   (rule id, method, probe URL).
6. **Report.** Configured credentials are scrubbed from every finding field, `--min-confidence` and the ignore
   file are applied, and the reporters write JSON, SARIF or HTML ([Output formats](reference/output.md)).

## Baselines

Most detectors need to know what the endpoint *normally* answers. Before any probe, the scanner sends one
**baseline** request per endpoint: the spec's example request with the configured credentials. It is sent only
when a check on that endpoint compares against it (`auth`, `bfla`, `bola`, `injection`, `mass_assignment`,
`ssrf`), and never for `DELETE` (it would delete the object). With `bola` and `--second-token`, every secured
`POST` gets one even when no other check needs it, so the object it creates can be read back.

Two comparisons are used throughout:

- **Resembles** (`_resembles`): same status, same content type, the same top-level JSON keys, and a body within
  10% (at least 20 bytes) of the other's length, or byte-identical. An `{"error": ...}` body never resembles a
  user object of similar length. An auth bypass, for example, is a probe without credentials that *resembles*
  the authenticated baseline.
- **Same object** (`_same_object`): two bodies describe the same object when their identifying fields agree
  (`id`, `uuid`, `username`, `email`, `*_id`, `*Id`, plus the probed parameter's name; per-request fields like
  `request_id` or `trace_id` are ignored), or, without identifying fields, when they are identical. Empty bodies
  (a `204`) never count as the same object. Cross-user BOLA is user B getting the *same object* user A's
  baseline returned.

## Firm and tentative

Every finding has a `confidence`:

- **firm**: confirmed by a comparison. The probe resembled the authenticated baseline; user B got user A's
  object; a follow-up `GET` returned the injected values; a boolean pair answered differently while its two
  controls agreed; every slow probe was slower than every control.
- **tentative**: a plausible signal with nothing to compare against, or one known to have innocent explanations.
  Examples: a cross-user `PUT` answered `204` (nothing shows whose object changed), injected fields echoed in
  the response but not confirmed by a read, response fields missing from the spec (the spec may just be out of
  date), an object user B can also see in a listing (it may be public by design).

Each detector decides which one it emits; the [check pages](checks/index.md) list them. Tentative findings are
SARIF `note`s under a separate `<rule>/tentative` rule with security-severity 5.0 (medium), so GitHub's default
code-scanning threshold (high) doesn't fail on them. `--min-confidence firm` drops them from every output.

## Scan passes

Requests go out in this order:

1. **Baselines** and the `data_exposure` reads (plain authenticated `GET`s), before any probe can change the
   objects they read.
2. **Probes**: everything else except the passes below, concurrently, paced by `--rate-limit`.
3. **Serial probes**, one at a time: boolean SQLi (control, true, false, control again, so nothing lands between
   them), and with `--time-based` the time-based SQLi and ReDoS probes (a slow request must not delay innocent
   ones queued behind it).
4. **Confirmations**, built from the responses so far: the `GET` that checks whether a mass-assignment probe's
   values were stored, and with `--second-token` user A's and user B's reads of objects A's `POST` baselines
   created (see resource linking below).
5. **Rate-limit bursts** last, one endpoint at a time, exempt from `--rate-limit` and never retried, so they
   can't exhaust a real limit and turn other probes into `429`s.

`--dry-run` prints passes 1 to 3 (and the bursts) as a table; the confirmations depend on responses, so they
aren't in the plan.

## Resource linking

A `POST` that creates an object doesn't always say where the object lives. For the confirmation reads, the
analyzer finds the created object's URL in this order: the `Location` header (same origin only, since the
follow-up carries credentials), the same URL for `PUT`/`PATCH`, `<url>/<id>` when the `POST` response has an
`id`, and otherwise a **sibling `GET`**: an item path `<parent>/{param}` whose parent is a prefix of the creating
path, with `{param}` filled from a response field, then a request-body field, of the same name. A
`<x>_id`/`<x>Id` parameter also takes the response's `id`. For example, `POST /users/v1/register` with a
`username` links to `GET /users/v1/{username}`. When several siblings match, the longest parent wins, then the
shorter path, then alphabetical order.

Linking is used twice:

- **Mass assignment**: the sibling `GET` must return the injected values, and its normal read (baseline) must
  not already have them, for a firm finding.
- **BOLA on created objects** (`--second-token`): user A reads the object A's `POST` baseline created, then user
  B reads it. Firm only if B gets what A's own read returned. Public endpoints are skipped, and only reads are
  sent.

A wrong link costs one request, never a finding: confirmation still needs the injected values, or A's object,
in what comes back.

## Redaction

Reports show each finding's request as it was sent, so they would otherwise contain credentials:

- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token` and the configured
  `--header-name` are masked in request samples (first 4 characters + `****`).
- Request-body values under password/secret/token/api-key-like keys are masked (recorded HAR/Postman login
  bodies).
- After the scan, every configured credential (`--token`, `--second-token`, `--low-priv-token`, and any
  user:password in `--target`), raw and base64-encoded, is replaced wherever it was echoed in a finding's `title`, `description`, `endpoint_path`, `evidence`,
  `request_sample` or `response_sample`.
- `data_exposure` findings mask the sensitive values they report, so the report doesn't repeat the leak.
- A cracked JWT signing key is shown masked in the evidence.

## Python API

The scanner can be used from Python. The ignore file, `--min-confidence` and `--fail-on` are CLI features; the
API returns every finding.

```python
import asyncio
from fuzzowl.scanner import Scanner
from fuzzowl.models.endpoint import AuthConfig
from fuzzowl.reporters.sarif import SARIFReporter
from fuzzowl.reporters.html import HTMLReporter

auth = AuthConfig(type="bearer", token="your-token")

scanner = Scanner(
    spec_path="openapi.yaml",
    base_url="https://api.example.com",
    auth=auth,
    checks=["bola", "auth", "injection"],  # None = all checks
    concurrency=10,
    rate_limit_rps=5.0,
    timeout=15.0,
)

findings = asyncio.run(scanner.run())

for f in findings:
    print(f"{f.severity.value.upper():10} {f.title}")
    print(f"  {f.endpoint_method} {f.endpoint_path}")
    print(f"  {f.owasp_category.value}")

SARIFReporter().write(findings, "results.sarif")
HTMLReporter().write(findings, "report.html")
```

The keyword-only options mirror the CLI: `allow_destructive`, `include`, `exclude`, `max_requests`, `verify`,
`proxy`, `retries`, `max_body`, `oob_url`, plus `time_based`.
