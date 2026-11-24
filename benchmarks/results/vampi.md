# apifuzz vs vampi

Measured 2026-11-24 with apifuzz `d8653f0`. Scan settings: `{"allow_destructive": true, "exclude": ["/createdb"], "rate_limit_rps": 20}`. Requests: 998 (vulnerable) / 998 (secure); failed: none / none.

| Metric | Value |
|---|---|
| Documented vulnerabilities detected | 7 / 9 (78%) |
| ...of those apifuzz has a check for | 7 / 9 (78%) |
| ...detected with a firm finding | 6 / 9 |
| Findings on the vulnerable build | 22 (0 false positive) |
| ...of which rate-limit (one per endpoint) | 11 |
| Precision (all / firm only) | 100% / 100% |
| Precision excluding rate-limit, one per (rule, operation) | 100% |
| Findings on the secure build | 16 (11 rate-limit: VAmPI keeps that flaw in both builds) |
| False positives on the secure build (all / firm) | 0 / 0 |

## Per documented vulnerability

| Vulnerability | Endpoint | Check | Vulnerable build | Secure build |
|---|---|---|---|---|
| SQLi Injection | `GET /users/v1/{username}` | injection | detected (firm) | clean |
| Unauthorized Password Change | `PUT /users/v1/{username}/password` | bola | detected (tentative) | clean |
| Broken Object Level Authorization | `GET /books/v1/{book_title}` | bola | detected (firm) | clean |
| Mass Assignment | `POST /users/v1/register` | mass_assignment | missed | clean |
| Excessive Data Exposure through debug endpoint | `GET /users/v1/_debug` | data_exposure | detected (firm) | still present (not toggled) |
| User and Password Enumeration | `POST /users/v1/login` | user_enum | detected (firm) | clean |
| RegexDOS (Denial of Service) | `PUT /users/v1/{username}/email` | redos | missed | clean |
| Lack of Resources & Rate Limiting | `*` | rate_limit | detected (firm) | still present (not toggled) |
| JWT authentication bypass via weak signing key | `*` | auth | detected (firm) | still present (not toggled) |

## False positives, vulnerable build

None.

## False positives, secure build

None.
