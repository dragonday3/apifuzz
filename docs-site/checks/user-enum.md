# user_enum: Login user enumeration

| | |
|---|---|
| OWASP | API2:2023 Broken Authentication |
| Rule id | `APIFUZZ-ENUM-001` (medium, firm) |
| Needs | a login-like `POST` whose example body has a username and a password field |

## What it sends

Only `POST` operations whose path, operationId or summary mentions `login`, `log-in`, `signin`, `sign-in`,
`auth`, `session` or `token`, and whose example body has a user field (`user`, `username`, `login`, `email`,
`e-mail`, `account`) and a password field (`pass`, `password`, `passwd`, `pwd`). Signup forms are left out on
purpose: they say "user already exists" by design, and probing them creates accounts.

Three requests, without credentials, all with the wrong password `apifuzz-Wr0ng-passw0rd`:

1. the spec's example user (the "known" user);
2. two **lookalikes** of it: same length, case and character classes, different letters and digits (an email
   keeps its domain), generated randomly for each scan, so they pass the same format validation and can't
   have been registered by an earlier run.

## How it decides

Firm finding when:

- none of the three answers is a `429` or a `5xx`;
- the two unknown users get the same answer (status and body, after replacing a whole-word echo of the
  username), so the difference isn't per-request noise;
- the known user's answer differs from theirs.

The evidence quotes both answers (for example "Given Email is not registered!" vs "Invalid Credentials" on
crAPI).

## False-positive guards

- Two unknown users act as a control for random tokens, timestamps or request ids in error bodies.
- An echoed username ("Invalid password for alice") is normalised before comparing, matching whole words only,
  so a username like `user` doesn't rewrite "Invalid username or password".
- Rate limiting or server errors cancel the verdict.

## Example finding

From a scan of a one-operation login spec (`POST /users/login`, example user `name1`) against a minimal respx handler (written for this page) that answers "Username does not exist" for unknown users and "Password is not correct for the given username." for `name1`.

```json
{
  "rule_id": "APIFUZZ-ENUM-001",
  "title": "User Enumeration: Login answers differently for existing users",
  "severity": "medium",
  "confidence": "firm",
  "owasp_category": "API2:2023 - Broken Authentication",
  "endpoint": "POST /users/login",
  "endpoint_method": "POST",
  "endpoint_path": "http://testserver/users/login",
  "evidence": "existing user: HTTP 401 '{\"status\":\"fail\",\"message\":\"Password is not correct for the given username.\"}'; unknown user: HTTP 401 '{\"status\":\"fail\",\"message\":\"Username does not exist\"}'",
  "request_sample": "# UserEnum: POST /users/login [known username, wrong password]\nPOST http://testserver/users/login\n\n{\"username\": \"name1\", \"password\": \"apif****\"}",
  "response_sample": "{\"status\":\"fail\",\"message\":\"Password is not correct for the given username.\"}",
  "remediation": "Return the same status and message for a wrong username and a wrong password."
}
```

## Remediation

Return the same status and message for a wrong username and a wrong password (and take the same time).

## Limitations

- It relies on the spec's example user being a real account. If it doesn't exist, the three answers will usually
  match and nothing is reported.
- The known user receives one wrong password per scan: on an API with account lockout, that counts towards it.
- Timing differences are not measured, only status and body. Password-reset and signup flows are not tested.
