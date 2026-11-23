# Benchmarks

apifuzz is scored against deliberately vulnerable APIs, using each target's **own list of documented
vulnerabilities**, not a list we wrote to fit the scanner.

```bash
py -3.10 -m pip install -e ".[dev]"
docker compose -f benchmarks/vampi/docker-compose.yml up -d
py -3.10 benchmarks/run.py vampi          # writes benchmarks/results/vampi.{md,json}
```

## Method

- **Two builds of the same API.** [VAmPI](https://github.com/erev0s/VAmPI) has a switch that turns its flaws
  off (`vulnerable=0`). The scan runs against both builds:
  - On the **vulnerable** build, each documented vulnerability counts as detected or missed.
  - On the **secure** build, any finding for a flaw the switch removes is a false positive. Flaws VAmPI keeps
    in both builds (debug endpoint, rate limiting, weak JWT key) are still real there.
- **Expected list.** `vampi/expected.yaml` holds VAmPI's README list of 9 vulnerabilities, each mapped to the
  endpoint in VAmPI's source and to the apifuzz rules that count as detecting it. Vulnerabilities apifuzz has
  no check for are kept in the list and count as misses.
- **Matching.** A finding detects a vulnerability when its rule matches and its spec operation (`Finding.endpoint`)
  is the vulnerability's endpoint. Rate limiting is documented API-wide (`*`), so it matches any endpoint.
  Every finding that matches nothing is a false positive.
- **Reproducible setup, no hand edits.** `run.py` resets VAmPI's data, logs in two users (A and B), and writes
  A's real book title into the spec example before each scan (VAmPI's titles are random per reset), so
  cross-user BOLA tests hit an object that exists. The scan uses A's token and B's token as `--second-token`,
  with `--allow-destructive --exclude /createdb` (disposable target; `/createdb` resets the data mid-scan).
  The image is pinned by digest in `docker-compose.yml`.
- **One target setting changed:** `tokentimetolive=3600` instead of VAmPI's default 60 s, because a scan takes
  about 20 s per build plus setup and a token must outlive it. It doesn't change any flaw.
- **Counted as found:** a vulnerability is detected by a firm or a tentative finding. The tables below and
  `results/vampi.md` say which.
- **Precision** is reported per finding, and again excluding rate-limit findings (which match every endpoint)
  with each (rule, operation) counted once.

## Results

Latest run: [`results/vampi.md`](results/vampi.md).

| VAmPI (9 documented vulnerabilities) | v0.1.0 | current |
|---|---|---|
| Detected | 0 | 6: SQLi, BOLA, debug-endpoint data exposure, user enumeration, rate limiting (firm); unauthorized password change (tentative) |
| Detected, among the vulnerabilities apifuzz has a check for | 0 | 6 / 7 |
| False positives, vulnerable build | 25 with tokens / 12 without | 0 |
| False positives, secure build | 25 with tokens / 12 without | 0 |

**Rules changed after seeing benchmark output (disclosed).** Each change removed false positives that showed
up on VAmPI, so read the 0 with that in mind:

1. The first run with the new `inventory` check reported VAmPI's own spec and Swagger UI (`/openapi.json`,
   `/openapi.yaml`, `/ui/`) on both builds: 3 false positives each. An independent review flagged that every
   FastAPI-style app publishes these by default. `inventory` now reports a served spec only when it
   describes operations *missing* from the scanned spec (a shadow API), and no longer reports docs UIs
   (commit `6036d56`).
2. The first run with the `data_exposure` check also
flagged the `secret` field of `GET /books/v1/{book_title}` on both builds. That field is the book's own
content, shown to its owner; whether *other* users can read it is the BOLA finding. A bare `secret` field
name was dropped from the sensitive-field list (`client_secret`, `secret_key`, `api_secret` stay), which
removed that false positive (commit `078c980`).

v0.1.0 was measured on 2026-11-23 against the same targets, seeding, expected list and scoring, through a
compatibility adapter ([`compare_v010.py`](compare_v010.py); outputs in `results/vampi-v0.1.0*.json`). Its
scanner takes no safety options and its findings have no spec operation, so the adapter maps finding URLs to
spec templates and drops `/createdb`. With tokens configured (as `run.py` does) it hits v0.1.0's
auth-header bug: the real token overwrote the auth probes' headers, so all 25 findings are false broken-auth
reports. Without tokens (v0.1.0's documented default) it reports 12, also all broken-auth false positives
on endpoints VAmPI documents as public.

**Not detected:**
- Mass assignment on `POST /users/v1/register`. The `admin` flag is stored, but the response has no id or
  `Location` to confirm it with. It shows only on `/me` (logged in as the new user) and the debug endpoint.
- Two flaws apifuzz has no check for: RegexDoS and the weak JWT signing key.
