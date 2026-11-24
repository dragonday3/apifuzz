# bfla: Broken Function Level Authorization

| | |
|---|---|
| OWASP | API5:2023 Broken Function Level Authorization |
| Rule id | `APIFUZZ-BFLA-001` (high; firm, tentative without a baseline) |
| Needs | `--low-priv-token` (a low-privilege user's credential); `--token` should then be a privileged user |

## What it sends

Nothing without `--low-priv-token`. With it, one request per operation that the spec marks as privileged and
that isn't public, sent with the low-privilege user's credential in the same scheme as `--token`. An operation
counts as privileged when (first match wins):

1. it has an `x-admin`, `x-internal`, `x-privileged` or `x-admin-only` extension;
2. a whole path segment is a role word: `admin`, `administrator`, `internal`, `manage`, `management`, `staff`,
   `superuser`, `moderator`, `backoffice` or `root` (`/admin/users`, not `/users/{id}/manager`);
3. the operationId contains a role word as a word (`adminDeleteUser`, `admin_delete`);
4. the summary or description says so explicitly ("only admins", "admin only", "requires admin",
   "admin privileges/role/access/rights"); "admins can also..." doesn't count;
5. a tag is exactly a role word.

The finding names the hint that matched.

## How it decides

The endpoint's baseline is the same request with the privileged `--token`.

- **Firm**: the low-privilege request got a 2xx that resembles the privileged baseline (same status, content
  type, top-level fields, similar length).
- **Tentative**: a 2xx with no baseline to compare (`DELETE`).
- Nothing when the privileged call itself failed or the low-privilege user got something different.

## False-positive guards

- Privilege hints are anchored (whole segments, whole tags, explicit phrases), so a field or word that only
  contains "admin" doesn't select an operation.
- Public operations are skipped: any token may call them.
- The comparison with the privileged response, not the status code, decides.

## Remediation

Enforce role checks on every privileged function, server-side, and deny by default.

## Limitations

- It only knows what the spec says is privileged. An admin operation that looks ordinary in the spec is not
  tested. On the crAPI benchmark (run without `--low-priv-token`) the admin video delete was found by the BOLA
  probe instead.
- `DELETE` operations need `--allow-destructive`, and get no baseline, so their findings are tentative.
- Two real accounts with different roles are required.
