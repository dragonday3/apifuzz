# auth: Broken Authentication and JWT attacks

| | |
|---|---|
| OWASP | API2:2023 Broken Authentication |
| Rule ids | `APIFUZZ-AUTH-` + the first 10 characters of the strategy in upper case (table below) |
| Needs | nothing for the basic probes; a bearer JWT in `--token` for the JWT attacks |

## What it sends

Endpoints the spec marks as public (or with optional auth) are skipped. Every other endpoint gets probes
against the header the API authenticates with (the `--header-name` header for `--auth-type apikey`, else
`Authorization`). These requests carry only the probe's own headers: the configured token is never added.

| Strategy | Request | Rule id | Severity |
|---|---|---|---|
| `no_auth` | no credential at all (the custom API-key header is stripped too) | `APIFUZZ-AUTH-NO_AUTH` | critical |
| `invalid_token` | `Bearer INVALID_TOKEN_apifuzz`; for basic auth, `apifuzz:invalid`; for API keys, `INVALID_TOKEN_apifuzz` | `APIFUZZ-AUTH-INVALID_TO` | high |
| `empty_apikey` | API-key header with an empty value (apikey only) | `APIFUZZ-AUTH-EMPTY_APIK` | high |
| `empty_bearer` | `Authorization: Bearer` with no token (not for apikey) | `APIFUZZ-AUTH-EMPTY_BEAR` | high |
| `malformed_scheme` | `NotBearer token123` (not for apikey) | `APIFUZZ-AUTH-MALFORMED_` | high |
| `jwt_alg_none` | your JWT with header `{"alg":"none"}` and an empty signature | `APIFUZZ-AUTH-JWT_ALG_NO` | critical |
| `jwt_unsigned` | your JWT with its signature replaced by garbage | `APIFUZZ-AUTH-JWT_UNSIGN` | critical |
| `jwt_kid_trav` | your claims, header `kid: ../../../../../../dev/null`, signed HS256 with a null key (`\x00`) | `APIFUZZ-AUTH-JWT_KID_TR` | critical |
| `jwt_weak_key` | your claims re-signed with a cracked HS256 key (`iat`/`nbf`/`exp` refreshed when present) | `APIFUZZ-AUTH-JWT_WEAK_K` | critical |
| `jwt_expired` | the same, with `exp` an hour in the past | `APIFUZZ-AUTH-JWT_EXPIRE` | high |

So an endpoint gets 3 requests with an API key, 4 with basic auth, a non-JWT bearer token or no token, 7 with
a bearer JWT, and 9 when the JWT's key was cracked.

The JWT attacks run only when `--auth-type` is bearer and `--token` is a JWT (three parts, a JSON header with
`alg`).

### Weak HS256 signing key (offline)

When the token is HS256, apifuzz tries to crack its key **offline, without sending anything**: it recomputes
HMAC-SHA256 over the token's header and payload for each candidate of a bundled wordlist, once per scan. The
list is the first 10,000 entries of the public [wallarm/jwt-secrets](https://github.com/wallarm/jwt-secrets)
list (MIT), copied verbatim (provenance in `src/apifuzz/jwt_secrets.README.md`). A hit is not reported on its
own: it is proved by two requests per endpoint, a token re-signed with the cracked key (same identity) and an
expired one. The key appears masked in the evidence.

## How it decides

A 2xx alone is not a bypass (public data, `{"error": ...}` bodies with status 200, login pages). A probe is a
finding when it got a 2xx that **resembles the authenticated baseline**: same status, same content type, the
same top-level JSON fields, and a body of similar length (within 10%, at least 20 bytes).

- **Firm**: the probe resembles the baseline.
- **Tentative**: no baseline to compare with (`DELETE`, which never gets one).
- Nothing when the probe's response differs from the baseline.

## False-positive guards

- Public endpoints (spec `security: []`) are not probed; endpoints the spec doesn't document (HAR/Postman, no
  `security` anywhere) are.
- The comparison with the authenticated response, not the status code, decides. This removed v0.1.0's false
  bypasses, where the configured token overwrote the probe's headers.

## Remediation

Require valid authentication on every protected endpoint. For JWTs: pin the accepted algorithm(s) server-side
and reject `none`; always verify the signature; never derive the key from a header field such as `kid` without
an allowlist; use a long random HMAC key or an asymmetric algorithm; enforce `exp`.

## Limitations

- **Not implemented**: RS256 to HS256 algorithm confusion and `jku`/`x5u` header injection. Both need the
  server's published key or an attacker-hosted JWKS, which the current request model does not provide cleanly.
- The weak-key attack only finds keys in the bundled 10,000 entries. VAmPI's key (`random`) is at rank 2,836;
  crAPI's key is not in the upstream list at all.
- Only the configured token is attacked; tokens issued during the scan (login responses) are not.
- Session cookies are not tampered with.
