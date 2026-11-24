# `jwt_secrets.txt` — bundled JWT HMAC secret wordlist

Used by the auth check's **offline** weak-HS256-key attack (`src/apifuzz/jwt_forge.py`).
No network requests are made against this list: apifuzz re-computes `HMAC-SHA256`
locally for each candidate against the configured bearer token's signing input and
stops at the first match. The list is only consulted when the configured token is an
HS256 JWT, once per scan (cached), never per endpoint.

## Source

- **Project:** wallarm/jwt-secrets ("JWT Heartbreaker" weak-secret list)
- **URL:** https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
- **Commit:** `85c852b479c491a0a917ea26af448dcc2655afa8` (2025-03-12)
- **Licence:** MIT — Copyright (c) 2020 Wallarm (full text below)

## What was copied

The upstream file has 103,978 non-empty entries. We bundle the **first 10,000**
entries **verbatim in upstream order** (a cost cap: cracking the whole 10k once per
scan is a few tens of milliseconds). The only changes are encoding normalisation —
CRLF line endings converted to LF, and the single leading blank line dropped. No
entries were added, removed, reordered, or edited.

Benchmark honesty note (apifuzz uses VAmPI / crAPI as benchmarks): the common secret
`random` (VAmPI's JWT secret) appears at **rank 2,836** of this bundled 10,000-entry
file, so it is within the cap. The string `crapi` (crAPI's `JWT_SECRET`) is **not
present** anywhere in the upstream list, so crAPI's token is not crackable by this
list at any N. These facts were observed, not engineered: no entry was added or
removed on account of them.

## MIT License (wallarm/jwt-secrets)

```
MIT License

Copyright (c) 2020 Wallarm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
