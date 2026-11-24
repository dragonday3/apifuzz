# Safety and scope

apifuzz sends real attack payloads to a real API. The defaults aim to make a scan safe to point at a staging
system, but read this page before you scan anything shared.

!!! warning "Authorized use only"
    Only scan APIs you own or have explicit written permission to test.

## Read-mostly by default

`PUT`, `PATCH` and `DELETE` operations are **skipped** unless you pass `--allow-destructive`. Probes such as
cross-user BOLA really modify or delete the target's data: on the VAmPI benchmark, a cross-user `PUT` changed
another user's password. The console lists every skipped operation and why.

`POST` operations **are** tested, and they create records:

- every `POST` gets a baseline request (one record), injection probes (13 per top-level string body field or
  string query parameter, 11 per string path parameter, plus 9 time-based ones per target with `--time-based`)
  and one mass-assignment probe;
- `rate_limit` sends a **50-request burst** to every endpoint, `POST` included;
- `user_enum` sends three login attempts with a wrong password per login-like operation, one of them for the
  spec's example user (on an API with lockout, that counts towards it).

Expect dozens of new records per `POST` endpoint. Leave `rate_limit` out of `--checks` to avoid the bursts.

With `bola` and `--second-token`, every secured `POST` gets a baseline `POST` even when no other check needs one (one more record only with a narrowed `--checks` list; by default it already has one) and, when
a sibling `GET` can read the created object, two `GET`s that read it back as user A and as user B. Every `GET`
without path parameters (or id-like query parameters) is read once as user B.

## Preview with `--dry-run`

`--dry-run` prints the test plan (requests per endpoint and check, and the total) and sends nothing. Follow-up
confirmations depend on responses, so they are not in the plan.

## Scope lock

- Every request goes to the `--target` origin (scheme, host, port; IDN hosts compared in punycode, default
  ports filled in). Hosts in a spec's `servers`, a HAR recording or a Postman collection are ignored.
- Redirects are followed only inside that origin: each hop passes the same check, and a request to any other
  origin fails with `OutOfScope` instead of being sent.
- A mass-assignment confirmation never follows a `Location` header to another origin.
- `--include` / `--exclude` narrow the scan by path glob (repeatable; they match the path only, without the
  method, e.g. `--exclude '/admin/*'`). They apply to the inventory probes too. A glob that matches no path in
  the spec is warned about, even with `--quiet`.

## Politeness and limits

| Option | Default | What it does |
|---|---|---|
| `--rate-limit` | 10 | Requests per second (a minimum interval between requests). The rate-limit bursts are exempt. `0` disables pacing. |
| `--concurrency` | 10 | Requests in flight at once. |
| `--max-requests` | none | Stop sending after this many requests (retries count). The scan says how many were not sent and that it is incomplete. |
| `--retries` | 2 | Retries on `429` and `503`, honouring `Retry-After` (capped at 30 s), else exponential backoff with jitter. A `POST`/`PATCH` is retried only on `429`, since a `503`'d one may have been processed. Bursts are never retried. |
| `--timeout` | 15 s | Per-request timeout. |
| `--max-body` | 8192 | Characters of each response body kept; detection sees only these. |

## TLS and proxies

TLS certificates are verified by default. `--insecure` skips verification (a staging API with a self-signed or
private-CA certificate needs it, or every request fails). `--proxy http://127.0.0.1:8080` sends traffic through
an intercepting proxy such as Burp or ZAP so you can verify findings by hand; trust the proxy's CA or add
`--insecure`.

## Failures are reported

The scan prints how many requests failed and why (TLS, out of scope, connection, budget). If **every** request
failed, the scan exits with code `2` (inconclusive) instead of reporting a clean result.

## Credentials in reports

Reports show each finding's request as it was sent, with `Authorization`, cookies, API-key headers and every
configured token masked (`Bear****`). See [Redaction](how-it-works.md#redaction) for the details.

## Opt-in probes

`--time-based` adds time-based SQLi and ReDoS probes. They are sent one at a time, and on a vulnerable target
each waits about 5 seconds and makes the server burn CPU (ReDoS), so they are off by default.
