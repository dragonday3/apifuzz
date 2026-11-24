# mass_assignment: Privileged fields stored

| | |
|---|---|
| OWASP | API3:2023 Broken Object Property Level Authorization |
| Rule id | `APIFUZZ-MASS-001` (high; firm when stored, tentative when only echoed) |
| Needs | an operation with a JSON object request body; `--allow-destructive` for `PUT`/`PATCH` |

## What it sends

One request per operation that has a non-empty JSON object body: the spec's example body plus these fields:

```json
{"admin": true, "is_admin": true, "isAdmin": true, "role": "admin", "is_verified": true,
 "credits": 99999, "balance": 99999.99, "permissions": ["read", "write", "admin"]}
```

On a `POST`, top-level string fields that APIs usually keep unique (`username`, `user_name`, `login`, `email`,
`nickname`, `handle`, `slug`) get a random suffix (an email keeps its domain): the baseline already created the
example record, and an API that enforces uniqueness would reject the probe as a duplicate before it reached the
code that binds the extra fields.

A successful probe gets one **confirmation `GET`** of the object it created or changed: the `Location` header
(same origin only), the same URL for `PUT`/`PATCH`, `<url>/<id>` when a `POST` response has an `id`, or a
sibling `GET` found by [resource linking](../how-it-works.md#resource-linking) (`POST /users/register` with
`username` leads to `GET /users/{username}`).

## How it decides

The injected fields are looked for with the injected value, at the top level of the JSON or under a `data`,
`user` or `result` wrapper.

- **Firm**: the confirmation `GET` returns injected values that neither the probe endpoint's baseline nor (for
  a sibling `GET`) the sibling's normal read already had. The values were stored.
- **Tentative**: the probe's own response echoes injected values its baseline doesn't have, and no read
  confirmed them. An echo may just repeat the request.

## False-positive guards

- Values already in the baseline don't count (a scan run as an admin, an API where every user `is_verified`).
- A sibling `GET`'s normal read is a second baseline: values it always returns prove nothing.
- A `Location` header pointing to another origin is never followed.

## Remediation

Bind request bodies to an allowlist of writable fields per role; never bind the body directly to the model.

## Limitations

- The injected field names are a fixed list; API-specific privileged fields (an order `status`, a video's
  `conversion_params` on crAPI) are not tried.
- Nested fields are not injected, only top-level ones.
- If nothing the API returns shows the stored value, it can't be confirmed: VAmPI's register endpoint stores
  `admin`, but only `/me` (as the new user) and a debug endpoint show it, so it stays a miss.
- Mass assignment through `PUT` needs `--allow-destructive`, and was not confirmed on crAPI.
