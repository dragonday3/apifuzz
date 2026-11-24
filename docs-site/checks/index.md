# Checks

Each check generates requests; the analyzer decides findings by comparing responses
([How it works](../how-it-works.md)). Run a subset with `--checks bola,auth,cors`; the default is `all`.
Unknown ids in `--checks` are ignored, so check the spelling against this table.

| Check | OWASP category | Rule ids | Needs | Requests (per endpoint unless noted) |
|---|---|---|---|---|
| [`bola`](bola.md) | API1:2023 Broken Object Level Authorization | `FUZZOWL-BOLA-001`, `-002` | `--second-token` for cross-user tests | 5 per id-like parameter, +1 with `--second-token` |
| [`auth`](auth.md) | API2:2023 Broken Authentication | `FUZZOWL-AUTH-*` | a token for the JWT attacks | 3 to 9 |
| [`user_enum`](user-enum.md) | API2:2023 Broken Authentication | `FUZZOWL-ENUM-001` | a login-like `POST` | 3 |
| [`mass_assignment`](mass-assignment.md) | API3:2023 Broken Object Property Level Authorization | `FUZZOWL-MASS-001` | a JSON object body | 1 + 1 confirmation |
| [`data_exposure`](data-exposure.md) | API3:2023 Broken Object Property Level Authorization | `FUZZOWL-EXPOSURE-001`, `-002` | `GET` endpoints | 1 |
| [`rate_limit`](rate-limit.md) | API4:2023 Unrestricted Resource Consumption | `FUZZOWL-RATE-001` | | 50 |
| [`redos`](redos.md) | API4:2023 Unrestricted Resource Consumption | `FUZZOWL-REDOS-001` | `--time-based` | 6 per regex-validated field |
| [`bfla`](bfla.md) | API5:2023 Broken Function Level Authorization | `FUZZOWL-BFLA-001` | `--low-priv-token` | 1 per privileged-looking operation |
| [`ssrf`](ssrf.md) | API7:2023 Server Side Request Forgery | `FUZZOWL-SSRF-001` | URL-like parameters; `--oob-url` for blind | 4 (+1) per parameter |
| [`cors`](cors.md) | API8:2023 Security Misconfiguration | `FUZZOWL-CORS-001` | | 4 |
| [`inventory`](inventory.md) | API9:2023 Improper Inventory Management | `FUZZOWL-INVENTORY-001`, `-002`, `-003` | | up to 25, once per scan |
| [`injection`](injection.md) | A03:2021 Injection (OWASP Top 10) | `FUZZOWL-INJECT-*` | string parameters or body fields | 11 to 13 per field, +9 with `--time-based` |

Coverage: API1, API2, API3, API4, API5, API7, API8 and API9. API6 (unrestricted access to sensitive business
flows) and API10 (unsafe consumption of APIs) are not tested. Injection has no API 2023 category and is reported
under the general OWASP Top 10 A03:2021.

Checks that compare with the endpoint's normal response (`auth`, `bfla`, `bola`, `injection`,
`mass_assignment`, `ssrf`) add one [baseline](../how-it-works.md#baselines) request per endpoint, except for
`DELETE`.

## Severity

| Severity | Findings |
|---|---|
| critical | BOLA cross-user access; auth bypass with no credentials, JWT `alg:none`, unverified signature, `kid` traversal, weak signing key; SQL, template and command injection; SSRF |
| high | BOLA ID enumeration; other auth bypasses (invalid/empty token, malformed scheme, expired JWT); mass assignment; sensitive data exposure; BFLA; CORS; NoSQL injection; actuator configuration and `.env` exposure |
| medium | rate limiting; ReDoS; user enumeration; reflected XSS; exposed spec, actuator, expvar, metrics, server-status; undocumented API version |
| low | response fields missing from the spec |

`--fail-on` (default `high`) sets which severities fail the run ([exit codes](../reference/output.md#exit-codes)).
