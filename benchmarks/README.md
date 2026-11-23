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

Other fixes from the same review (user_enum lookalike usernames, anchored BFLA hints, data_exposure placeholder
handling) also landed after benchmark runs; they did not change any VAmPI number.

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

## crAPI (held-out target)

[OWASP crAPI](https://github.com/OWASP/crAPI) was added as a second target **after** the VAmPI work, and
measured once with the code as it was (commit `b21ea70`, detection identical to `4bf7b6d`) before any rule
was changed for it. That number is the held-out baseline below; anything tuned later is reported separately
as "after tuning".

```bash
git clone --depth 1 --branch v1.1.6 https://github.com/OWASP/crAPI /path/to/crAPI
docker compose -p crapi -f /path/to/crAPI/deploy/docker/docker-compose.yml \
  -f benchmarks/crapi/docker-compose.pinned.yml up -d --wait # ~10 containers; :8888
py -3.10 benchmarks/run.py crapi                              # ~11 min (crAPI caps its services at 0.3 CPU)
```

How it differs from the VAmPI method:

- **Expected list.** `crapi/expected.yaml` holds crAPI's 18 documented challenges (`docs/challenges.md` at
  v1.1.6), each mapped to its endpoint from crAPI's solutions doc and service source, written before the
  first scan. Challenge 9 (refund by quantity) is business logic and the 3 chatbot challenges need an
  OpenAI key; they stay in the list as "not covered". crAPI's 3 undisclosed "secret challenges" aren't listed.
- **No fixed build**, so there is no false-positive run. Every finding that matches no documented challenge
  counts against precision in `results/crapi.md` and is triaged by hand below.
- **Setup.** `run.py` signs up two fresh users with random credentials, gives user A a vehicle (VIN and
  pincode from crAPI's own welcome email), an order, a mechanic report, a video and a forum post, and writes
  those ids into the spec's id parameters. Nothing else in the spec changes. The spec is crAPI's
  `openapi-spec/crapi-openapi-spec.json` (Apache-2.0, `crapi/LICENSE.crAPI.md`).
- **Images.** crAPI publishes no complete `1.1.6` image set, so the run used `latest`, pinned by digest in
  `crapi/docker-compose.pinned.yml`.

### Held-out result (`b21ea70`, before any tuning)

The full benchmark ran once at `b21ea70` (results committed in `6efe89e`); the setup alone was re-run
afterwards to triage findings by hand. After review fixes to the harness (no detection code changed) it was
**reproduced at `5a117ab` on a freshly created stack from the pinned images**: the same 5 detections with
the same firm/tentative split and the same 39 unmatched findings, 61 findings instead of 62 (the first run
had one more `alg:none` acceptance, on `change-email`), no failed requests (the first run had 6 timeouts).
[`results/crapi.md`](results/crapi.md) is the reproduction; the table below is the held-out run.

| crAPI (18 documented challenges) | held-out |
|---|---|
| Detected | 5 / 18: vehicle-location BOLA, unauthenticated order access, JWT `alg:none` accepted (firm); video internal property exposed, admin video delete by a normal user (tentative; found by the BOLA probe, since the `bfla` check needs `--low-priv-token` and the run passes none) |
| ...among the 14 apifuzz has a check for | 5 / 14 |
| Findings | 62 (23 match a documented challenge, 39 don't) |
| Unmatched findings, triaged by hand | 29 real but undocumented, **10 false positives** (4 firm, 6 tentative) |

Triage of the 39 unmatched findings (each re-checked against the live API):

| Finding | Count | Verdict |
|---|---|---|
| No rate limiting (`RATE-001`) on other endpoints | 22 | Real: 50-request bursts got no 429. crAPI documents rate limiting only for two challenges. |
| `/.env` served (`INVENTORY-002`) | 1 | Real: returns crAPI's database credentials; a random path returns 404. |
| Login reveals registered emails (`ENUM-001`) | 1 | Real: "Given Email is not registered!" vs "Invalid Credentials". |
| Other users' orders readable (`BOLA-001` firm, `BOLA-002` ×2) on `GET /workshop/api/shop/orders/{order_id}` | 3 | Real: the same unauthenticated order endpoint as challenge 14, seen as BOLA. |
| Sensitive field in the order response (`EXPOSURE-001`) | 1 | **False positive** (firm). The field it flagged is `payment.card_number`, and its value is already masked (`XXXXXXXXXXXX9999`), a shape the placeholder filter doesn't recognise. The response does expose the owner's email and phone to anyone, but apifuzz didn't report that. |
| Undocumented response fields (`EXPOSURE-002`): owner `email` in vehicle location (readable by other users), `payment` object in the unauthenticated order detail | 2 | Real. |
| Undocumented response field (`EXPOSURE-002`): `previousOwners` on the caller's own vehicles | 1 | **False positive** (tentative): an empty list for a new vehicle, so nothing was exposed. |
| Undocumented response fields (`EXPOSURE-002`): only pagination fields (`count`, `next_offset`, `previous_offset`; plus `transaction_id` on orders/all) | 5 | **False positive** (tentative): spec drift with no security impact. |
| BOLA on forum posts (`GET` post, `POST` comment) | 2 | **False positive** (firm): forum posts are public to every user by design. |
| Boolean SQLi on `POST .../posts/{postId}/comment` | 1 | **False positive** (firm): each probe adds a comment, so the post's response grows; the true/false difference isn't SQL. |

**Missed (held-out)**, each a gap in a check that exists:
- 2: BOLA on `mechanic_report`: the id is a **query** parameter and BOLA only probes path parameters.
- 3: rate limiting on `v2/check-otp`: the check counts only 2xx answers as accepted, and crAPI answers a
  wrong OTP with HTTP 500 ("Invalid OTP!"), so an unlimited brute force looks like a rejected burst.
- 6: rate limiting on `contact_mechanic`: not reported, in both runs (the reproduction had no timeouts);
  cause not investigated yet.
- 4: other users' data in `posts/recent` (author email, vehicle id): not in the sensitive-field list.
- 8, 10: mass assignment through `PUT` (order `status`, video `conversion_params`): not confirmed.
- 11: SSRF via `mechanic_api`: the run has no `--oob-url` collector, and crAPI has no cloud metadata to echo.
- 12, 13: NoSQLi and SQLi on the coupon endpoints: not detected.
