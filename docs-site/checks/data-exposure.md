# data_exposure: Sensitive and undocumented response fields

| | |
|---|---|
| OWASP | API3:2023 Broken Object Property Level Authorization (formerly "excessive data exposure") |
| Rule ids | `APIFUZZ-EXPOSURE-001` sensitive fields (high, firm or tentative), `APIFUZZ-EXPOSURE-002` undocumented fields (low, tentative) |
| Needs | `GET` operations; a documented response schema for `EXPOSURE-002` (OpenAPI only) |

## What it sends

One `GET` per `GET` operation with the configured credentials. These reads run in the first pass, with the
baselines.

## How it decides

**Sensitive fields (`APIFUZZ-EXPOSURE-001`)**: the JSON response is walked (nested objects, the first 50 items
of each list) for fields named `password`, `passwd`, `pwd`, `password_hash`, `hashed_password`,
`client_secret`, `secret_key`, `api_secret`, `api_key`, `private_key`, `access_token`, `refresh_token`, `ssn`,
`social_security_number`, `card_number`, `cvv` or `cvc` (case-insensitive, underscore optional) holding a real
string or number.

- **Firm** in general: these values should never reach a client.
- **Tentative** on the caller's own account pages (`/me`, `/self`, `/account`, `/profile`, `/settings`,
  `/current`, `/whoami`) when every flagged field is a key or token (`api_key`, `access_token`, `refresh_token`,
  `*secret*`): it may be the caller's own credential by design.

**Undocumented fields (`APIFUZZ-EXPOSURE-002`, tentative)**: fields present in the response but not declared in
the operation's documented 2xx response schema. Only objects with declared `properties` are compared (up to 4
levels deep, the first 3 items of a list); schemas with `additionalProperties`, `allOf`, `oneOf` or `anyOf` are
skipped, since what is undocumented can't be told there.

## False-positive guards

- Placeholder and masked values don't count as exposed: empty, `null`, `n/a`, `[redacted]`, `<hidden>`, runs of
  `*`/`x`/`•`, and PCI-style masks with at most the first 6 and last 4 digits visible (`XXXXXXXXXXXX9999`,
  `xxxx-xxxx-xxxx-1234`, `•••• 1234`, `***-**-6789`).
- A bare `secret` field is not on the list: it is often the resource's own content shown to its owner (VAmPI's
  book `secret`), which is a BOLA question.
- Undocumented fields with empty values (`null`, `""`, `[]`, `{}`) and pagination fields of the top-level
  envelope (`count`, `total`, `next`, `previous`, `offset`, `limit`, `page`, `next_offset`, `cursor`,
  `has_more`, ...) are ignored.
- Reported values are masked in the finding's response sample, so the report doesn't repeat the leak.

## Remediation

Return an explicit allowlist of fields per role; never serialise whole model objects. Document every response
field, or stop returning fields clients don't need.

## Limitations

- Field names only: personal data under ordinary names (another user's `email` or `phone` in a listing) is not
  recognised as sensitive. crAPI's `posts/recent` leaking other users' emails is missed for this reason; there
  is no low-noise generic rule without knowing who the caller is.
- Only `GET` responses are read; `POST`/`PUT` responses are not inspected for secrets.
- Detection sees only the first `--max-body` characters of each response (8192 by default).
- `EXPOSURE-002` needs an OpenAPI response schema; with HAR or Postman input there is nothing to compare.
