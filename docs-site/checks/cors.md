# cors: Origin reflection with credentials

| | |
|---|---|
| OWASP | API8:2023 Security Misconfiguration |
| Rule id | `APIFUZZ-CORS-001` (high, firm) |
| Needs | nothing |

## What it sends

Four requests per endpoint: the endpoint's normal request with `Origin: https://evil.com`,
`Origin: https://attacker.example.com` and `Origin: null`, and a preflight `OPTIONS` with
`Origin: https://evil.com`, `Access-Control-Request-Method: <the endpoint's method>` and
`Access-Control-Request-Headers: Authorization, Content-Type`.

## How it decides

A finding when the response's `Access-Control-Allow-Origin` is not `*`, contains the origin that was sent, and
`Access-Control-Allow-Credentials` is `true`: any website (or a sandboxed `null` origin) can then read
authenticated responses from a victim's browser.

## False-positive guards

- `Access-Control-Allow-Origin: *` is not reported: browsers refuse to send credentials with a wildcard.
- Reflection without `Allow-Credentials: true` is not reported.

## Remediation

Use a strict allowlist of origins. Never reflect `Origin` dynamically when `Access-Control-Allow-Credentials` is
`true`, and never allow `null`.

## Limitations

- Only reflection with credentials is checked. Other misconfigurations (permissive methods or headers, regexes
  that accept `evil-example.com`-style lookalikes, missing security headers, verbose errors, TLS settings) are
  not.
