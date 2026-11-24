# bola: Broken Object Level Authorization

| | |
|---|---|
| OWASP | API1:2023 Broken Object Level Authorization |
| Rule ids | `APIFUZZ-BOLA-001` cross-user access (critical), `APIFUZZ-BOLA-002` ID enumeration (high, always tentative) |
| Needs | `--second-token` (a second user's credential) for the cross-user tests; `--allow-destructive` to test `PUT`/`PATCH`/`DELETE` |

## What it sends

**Which parameters are object references.** On an endpoint the spec marks as secured, every path parameter
(`book_title`, `username`, ...). On an endpoint with no documented security (HAR, Postman, or a spec without
`security`), only path parameters whose name ends in `id`, `Id`, `ID`, `uuid`, `UUID`, `key` or `Key`. In both
cases also id-like query parameters: `id`, `uuid`, or a name ending in `_id`, `Id`, `ID` or `_uuid`
(`GET /reports?report_id=7`); `page` or `q` are not. Endpoints the spec marks as public are skipped (unless
auth is optional there).

For each such parameter:

- **ID enumeration**: 5 requests with the configured user, the parameter set to `0`, `1`, `2`, `999999` and
  `99999999` (an id that shouldn't exist). Not sent for `DELETE`.
- **Cross-user** (with `--second-token`): 1 request for the spec's example id, sent with user B's credential in
  the same scheme as user A's (bearer when `--auth-type` is `none`).

With `--second-token` there are two more kinds of request:

- **Listings**: every `GET` without path parameters or id-like query parameters is read once as user B. What
  user B sees there without asking for an id is used to recognise public objects (see below).
- **Objects created during the scan**: every secured `POST` gets a baseline request as user A. When
  [resource linking](../how-it-works.md#resource-linking) finds a sibling `GET` for the created object, user A
  reads it, then user B reads it (2 `GET`s). No seeded ids are needed.

## How it decides

Only 2xx responses are considered.

**Cross-user (`APIFUZZ-BOLA-001`)**: user B's response is compared with user A's baseline for the same object
(for a created object, with user A's own read of it).

- **Firm** when user B got user A's object back: the identifying fields agree (`id`, `uuid`, `username`,
  `email`, `*_id`, `*Id` and the probed parameter's name), or the bodies are identical when there are no such
  fields.
- **Tentative** when there is nothing to compare: user A's baseline had an empty body (a `204` after a `PUT`),
  or there is no baseline (`DELETE`).
- **Tentative** also when user B can see the same object in a listing (a `GET` without path parameters, read as
  B) and the probe is a `GET` or a `POST`: the object may be public by design, like a forum post that every
  user may read or comment on. The finding says which listing. A `PUT`/`PATCH` on it stays **firm**: a public
  object still has an owner.
- Nothing when user A's baseline has a body and user B got something else (B's own data, an error object).
- For a created object, nothing unless user A could read it and user B got the same object.

**ID enumeration (`APIFUZZ-BOLA-002`, tentative)**: a probed id returned an object with the same top-level
fields as the caller's own object (the baseline) but a different identity. A 2xx alone is not a finding; most
APIs have an object `1`.

## False-positive guards

- The answer for an id that can't exist (`99999999`) is a control: a probe whose response resembles it (a
  `200 {"message": "not found"}`) is not a finding.
- Empty bodies never prove that two responses are the same object.
- Volatile fields (`request_id`, `trace_id`, `session`, `nonce`, ...) are ignored when comparing objects.
- Public objects (found in user B's listings) are downgraded to tentative for reads and `POST`s.
- Endpoints the spec marks as public are not probed.

## Remediation

Enforce object-level authorization on every request that takes an object id: verify that the requesting user
owns (or may access) the object, server-side, and return the same error for "not yours" and "doesn't exist".

## Limitations

- Ids in request bodies or headers are not probed; only path parameters and id-like query parameters.
- HAR recordings have concrete paths (`/users/42`), so no path parameters are inferred from them.
- A listing longer than `--max-body` is cut mid-JSON. It is then searched as text for every identifying field
  as a `"key": value` pair; the pairs may come from different objects, which can only downgrade firm to
  tentative, never drop a finding.
- A cross-user `PUT` answered with `204` stays tentative (VAmPI's unauthorized password change is detected
  this way).
- Requires two real accounts for the cross-user test; ID enumeration alone is only a tentative hint.
