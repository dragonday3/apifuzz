# Comparison and limitations

## Where apifuzz fits

apifuzz is a small, spec-driven scanner for the OWASP API Security Top 10. Its focus:

- **Authorization comparisons**: cross-user BOLA with two real accounts, BFLA with a low-privilege account, auth
  bypasses judged against the authenticated response rather than the status code.
- **Firm vs tentative**: every finding says whether a comparison confirmed it.
- **CI output**: SARIF with stable fingerprints, `--fail-on`, an ignore file with expiry dates.
- **Measured precision**: [benchmarks](benchmarks.md) against each target's own vulnerability list, with every
  rule change made after seeing benchmark output disclosed.

It is not a replacement for the tools below, which are larger and more mature. A rough guide to what each
focuses on:

| Tool | Focus |
|---|---|
| [OWASP ZAP](https://www.zaproxy.org/) | General-purpose open-source web application scanner and intercepting proxy, with active and passive scan rules and add-ons; it can import API definitions such as OpenAPI. |
| [Burp Suite](https://portswigger.net/burp) | PortSwigger's toolkit for manual web security testing built around an intercepting proxy, with an automated scanner in its commercial editions. |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | Property-based testing that generates requests from OpenAPI or GraphQL schemas, focused on API robustness and conformance (server errors, responses that violate the schema). |
| [RESTler](https://github.com/microsoft/restler-fuzzer) | Microsoft Research's stateful REST API fuzzer, which infers dependencies between requests from an OpenAPI spec to explore sequences of calls. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ProjectDiscovery's template-based scanner for known vulnerabilities and misconfigurations, driven by a large community template library, built for scanning many hosts. |
| Commercial API security platforms | Hosted products that typically combine API discovery, testing and runtime monitoring, with vendor support. |

These tools are complementary: apifuzz works well alongside an intercepting proxy (`--proxy`) for verifying its
findings by hand.

!!! note
    The descriptions above are based on each project's public documentation; check current versions, since
    features change. They describe each tool's main focus, not a feature-by-feature comparison, and no
    comparative benchmark was run.

## Limitations

What apifuzz does not do, from the code and the benchmark misses:

**Coverage**

- **API6** (unrestricted access to sensitive business flows) and **API10** (unsafe consumption of APIs) are not
  tested, nor is business logic in general (crAPI's refund-by-quantity challenge).
- **JWT**: RS256 to HS256 algorithm confusion and `jku`/`x5u` header injection are not implemented. The weak-key
  attack only knows the bundled 10,000-entry wordlist.
- **Injection**: crAPI's coupon NoSQLi and SQLi were not detected. Nested body fields, headers and cookies are not
  injected; XSS is reflected-only, in `text/html` responses.
- **Data exposure** is judged by field name: other users' personal data under ordinary names (an `email` in a
  listing, crAPI's `posts/recent`) is not recognised.
- **Mass assignment** uses a fixed list of privileged field names, and needs the API to show the stored value
  somewhere (VAmPI's register endpoint stores `admin` but never returns it). Mass assignment through `PUT` was
  not confirmed on crAPI; fields documented as read-only are not specifically targeted.
- **SSRF** is selected by parameter name. Blind SSRF needs your own `--oob-url` collector, and apifuzz doesn't
  read the collector: you match callbacks to the probe map yourself.
- **ReDoS** is tuned for backtracking engines like Python's and PCRE; faster engines may need longer input, and
  polynomial ReDoS is not tested.
- **CORS**: only origin reflection with credentials.

**Model of the API**

- **No crawler**: apifuzz needs an OpenAPI/Swagger file, a HAR recording or a Postman collection. A HAR
  recording has concrete URLs, so no path parameters are inferred from it.
- **No GraphQL**, gRPC or SOAP.
- **No stateful sequences** beyond one step: it links a `POST` to the `GET` that reads what it created, but
  doesn't drive multi-step flows (create, then pay, then refund).
- Tokens are supplied by you; apifuzz doesn't log in, refresh expired tokens, or handle session cookies.

**Evidence**

- **Rate limiting** is judged from one client and one account: per-IP and per-user limits can't be told apart, a
  limit above 50 requests without headers looks like none, and the unthrottled-guessing signal uses the spec's
  example account, which may not exist (a false positive on crAPI's protected `v3/check-otp`).
- **Truncated bodies**: detection sees only the first `--max-body` characters of each response (8192 by
  default), and reports show a 500-character excerpt. A listing longer than `--max-body` is searched in its cut
  text only.
- **Tentative findings** need a person: a cross-user `PUT` answered `204`, objects that may be public by design,
  undocumented fields that may just be spec drift.
- The crAPI benchmark has no fixed secure build: its false-positive count comes from hand triage, and it
  reported 6 false positives after tuning (10 held-out).

**Side effects**

- `POST` endpoints are always tested and create records; with `--allow-destructive`, probes really modify and
  delete data. See [Safety and scope](safety.md).
