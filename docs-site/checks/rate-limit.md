# rate_limit: Missing rate limiting

| | |
|---|---|
| OWASP | API4:2023 Unrestricted Resource Consumption |
| Rule id | `FUZZOWL-RATE-001` (medium; firm for accepted bursts, tentative for unthrottled guessing) |
| Needs | nothing; leave it out of `--checks` to avoid the bursts |

## What it sends

A burst of **50 identical requests** per endpoint (the spec's example request with the configured
credentials). Bursts are exempt from `--rate-limit` (a paced burst isn't a burst), never retried (a `429` is the
signal), sent in the last pass so they can't exhaust a real limit and turn other probes into `429`s, and sent
one endpoint at a time (concurrent bursts interfere with each other).

This is the most expensive check: 50 requests per endpoint, `POST` included, so it creates up to 50 records per
`POST` endpoint.

## How it decides

- No verdict unless all 50 requests completed (a failed request or `--max-requests` leaves the burst
  incomplete).
- **Protected**, no finding: any response was `429`, or carried `Retry-After`, an `X-RateLimit-*` or a
  `RateLimit-*` header. The limiter may simply allow more than 50 requests.
- **Firm finding**: at least 90% of the burst got a 2xx.
- **Tentative finding (unthrottled guessing)**: on authentication operations, where every wrong guess is
  answered with an error, "the burst wasn't accepted" doesn't mean anything. When the path mentions `login`,
  `signin`, `otp`, `verif`, `reset`, `passw`, `2fa`, `mfa`, `/token` or `check-code`, every attempt got the
  same status (not `503`) and the last answer resembles the first (no lockout appeared), the finding says wrong
  passwords or codes can be guessed at full speed.
- Otherwise (errors on an ordinary endpoint) the burst is treated as not accepted: no finding.

## False-positive guards

- Standard limiter headers count even without a `429`.
- A burst with any failed request gets no verdict.
- The unthrottled-guessing rule is tentative and limited to authentication-like paths.

## Example finding

From a scan of the test suite's petstore mock API (`tests/e2e/conftest.py` `MockAPI`) with no rate limiting configured (`rate_limit=None`, its default), token `token-alice`.

```json
{
  "rule_id": "FUZZOWL-RATE-001",
  "title": "Rate Limiting: Burst requests all succeeded",
  "severity": "medium",
  "confidence": "firm",
  "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
  "endpoint": "GET /pets",
  "endpoint_method": "GET",
  "endpoint_path": "http://testserver/pets",
  "evidence": "50/50 burst requests succeeded",
  "request_sample": "# RateLimit burst #1: GET /pets\nGET http://testserver/pets\nAuthorization: Bear****",
  "response_sample": "",
  "remediation": "Implement rate limiting (token bucket, sliding window) per IP or user."
}
```

## Remediation

Rate-limit per client and per user (token bucket or sliding window), and return `429` with `Retry-After`. On
login, one-time-code and reset operations, also limit attempts per account (lockout or growing delay after a
few failures).

## Limitations

- **One client, one account.** The burst comes from one IP with one credential, so per-IP and per-user limits
  can't be told apart, and a limit higher than 50 requests without headers looks like no limit.
- **Weak evidence for unthrottled guessing.** The burst uses the spec's example account. If it doesn't exist, a
  per-account lockout never shows: on crAPI the same signal fired on the protected `v3/check-otp` (a false
  positive, it locks out after 9 attempts with a real account) as on the vulnerable `v2/check-otp`.
- On crAPI, rate limiting on `contact_mechanic` was not reported; the cause has not been investigated.
- Business-flow abuse (API6) and resource-heavy payloads (large page sizes, uploads) are not tested.
