# injection: SQL, NoSQL, template, command injection and XSS

| | |
|---|---|
| OWASP | A03:2021 Injection (OWASP Top 10). The API Security Top 10 (2023) has no injection category. |
| Rule ids | `APIFUZZ-INJECT-SQLI`, `-SQLI-BOOL`, `-SQLI-TIME`, `-NOSQLI`, `-NOSQLI-BOOL`, `-SSTI`, `-CMD`, `-XSS` |
| Needs | string query/path parameters or top-level string fields in a JSON body; `--time-based` for time-based SQLi |

## What it sends

Targets: every string query or path parameter, and every top-level string field of the example JSON body (one
field at a time; the rest of the body stays valid). Per target:

**7 single probes**, the value replaced by:

| Payload | Type |
|---|---|
| `'` | SQLi: breaks quoting, so a database error shows even where a tautology is valid SQL |
| `' OR '1'='1` | SQLi |
| `{{1337*7331}}` | SSTI (Jinja2, Twig, Nunjucks) |
| `${1337*7331}` | SSTI (FreeMarker, JSP EL, Thymeleaf) |
| `; id` | command injection |
| `; echo apifuzz$((1337*7331))` | command injection |
| `<script>apifuzz(1337)</script>` | XSS |

**4 boolean SQLi probes** (not for `DELETE`, since the control carries the real value), sent one at a time in
this order: the original value (control), value + `' AND '1'='1` (true), value + `' AND '1'='2` (false), the
original value again.

**2 NoSQLi probes** (query parameters and body fields, not path parameters): `param[$ne]=apifuzz-nonexistent`
and `param[$eq]=apifuzz-nonexistent` in the query (Express-style bracket syntax); `{"$ne": null}` and
`{"$eq": "apifuzz-nonexistent"}` in a JSON body.

**With `--time-based`, 9 more** (3 payloads × 3 repeats, one at a time): value + `' AND SLEEP(5)-- -`,
`'||pg_sleep(5)--` and `'; WAITFOR DELAY '0:0:5'--`.

That is 13 requests per string query parameter or body field and 11 per string path parameter, plus 9 with
`--time-based`.

## How it decides

Every rule compares with the endpoint's baseline, so content the endpoint always returns is never a finding.

| Rule | Severity | Finding when |
|---|---|---|
| `INJECT-SQLI` | critical | a SQLi probe's response contains a database error (`SQL syntax`, `ORA-nnnnn`, `SQLSTATE[`, `sqlite3.OperationalError`, `Unclosed quotation mark`, ...) that the baseline doesn't |
| `INJECT-SQLI-BOOL` | critical | the true probe resembles the control, the false probe resembles neither control, and the two controls resemble each other |
| `INJECT-SQLI-TIME` | critical | every repeat of a sleep payload took at least 4.5 s longer than the control, or timed out |
| `INJECT-SSTI` | critical | the response contains the computed product `9801547`, does not contain the literal `1337*7331`, and the baseline doesn't contain `9801547` |
| `INJECT-CMD` | critical | the response contains `uid=N(name) gid=N` or the computed canary `apifuzz9801547`, and the baseline contains neither |
| `INJECT-XSS` | medium | the script payload is reflected verbatim in a `text/html` response |
| `INJECT-NOSQLI` | high | the response contains a MongoDB error (`MongoError`, `MongoServerError`, `unknown operator`, `$where`) that the baseline doesn't |
| `INJECT-NOSQLI-BOOL` | high | the `$ne` probe got a 2xx and the `$eq` probe a different status or a body differing in length by more than 10% (at least 20 bytes) |

All injection findings are firm.

## False-positive guards

- **Canaries, never reflection**: SSTI and command injection look for a value the server had to compute
  (`1337*7331 = 9801547`), which never appears in the payload. v0.1.0 flagged any `49` or `$ ` in a body.
- Duplicate-key (`E11000`) and type-validation (`CastError`) errors are not NoSQLi signals: both are normal on
  a secure Mongo API.
- Boolean SQLi needs both controls to agree. A response that grows with every request (each probe adds a
  comment to the post it returns) fails that test instead of passing as SQL; the four requests run in a serial
  pass with nothing in between.
- Pairs split by a `429` or a `5xx` are ignored: a limiter or crash, not the query, made the difference.
- Time-based probes are compared with the control's own latency and need every repeat to be slow.

## Remediation

Use parameterised queries; never concatenate input into SQL or pass it to a shell or template engine; reject
objects and operators where scalars are expected (NoSQL); HTML-encode output and return JSON with
`application/json`.

## Limitations

- Error-based detection depends on the error text reaching the response; blind injection without a boolean
  difference needs `--time-based`.
- Nested body fields, headers and cookies are not injected.
- XSS: reflected only (no stored or DOM XSS), and only in `text/html` responses.
- crAPI's coupon NoSQLi and SQLi (challenges 12 and 13) were not detected.
- Only the first `--max-body` characters of each response are searched.
