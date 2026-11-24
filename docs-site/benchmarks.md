# Benchmarks

apifuzz is scored against deliberately vulnerable APIs using each target's **own list of documented
vulnerabilities**, not a list written to fit the scanner. This page summarises the method, the results and
every disclosure. The full write-up, with hand triage of every finding, is
[`benchmarks/README.md`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/README.md); the numbers come
from the committed result files:

| Run | Result files |
|---|---|
| VAmPI, default scan | [`vampi.md`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/vampi.md), [`vampi.json`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/vampi.json) |
| VAmPI, `--time-based` | [`vampi-time-based.md`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/vampi-time-based.md), [`vampi-time-based.json`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/vampi-time-based.json) |
| VAmPI, v0.1.0 | [`vampi-v0.1.0.json`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/vampi-v0.1.0.json), [`vampi-v0.1.0-noauth.json`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/vampi-v0.1.0-noauth.json) |
| crAPI, held-out (reproduction) | [`crapi-held-out.md`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/crapi-held-out.md), [`crapi-held-out.json`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/crapi-held-out.json) |
| crAPI, after tuning | [`crapi.md`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/crapi.md), [`crapi.json`](https://github.com/dragonday3/apifuzz/blob/main/benchmarks/results/crapi.json) |

## VAmPI

### Method

- **Two builds of the same API.** [VAmPI](https://github.com/erev0s/VAmPI) has a switch that turns its flaws
  off. The scan runs against both builds. On the **vulnerable** build each documented vulnerability counts as
  detected or missed. On the **secure** build, any finding for a flaw the switch removes is a false positive;
  flaws VAmPI keeps in both builds (debug endpoint, rate limiting, weak JWT key) are still real there.
- **Expected list.** `benchmarks/vampi/expected.yaml` holds VAmPI's README list of 9 vulnerabilities, each
  mapped to its endpoint in VAmPI's source and to the apifuzz rules that count as detecting it.
  Vulnerabilities apifuzz has no check for stay in the list and count as misses.
- **Matching.** A finding detects a vulnerability when its rule matches and its spec operation is the
  vulnerability's endpoint. Rate limiting is documented API-wide, so it matches any endpoint. Every finding that
  matches nothing is a false positive.
- **Reproducible setup, no hand edits.** `benchmarks/run.py` resets VAmPI's data, logs in two users, and writes
  user A's real book title into the spec example before each scan (titles are random per reset). The scan uses
  A's token and B's token as `--second-token`, with `--allow-destructive --exclude /createdb` (disposable
  target; `/createdb` resets the data). The image is pinned by digest.
- **One target setting changed**: `tokentimetolive=3600` instead of VAmPI's default 60 s, so a token outlives
  the scan. It doesn't change any flaw.
- **Counted as found**: a firm or a tentative finding; the tables say which.

### Results

Latest runs at commit `d8653f0`:

| VAmPI (9 documented vulnerabilities) | v0.1.0 | 0.2.0 before the JWT and ReDoS checks (`6036d56`) | current, default scan | current, `--time-based` |
|---|---|---|---|---|
| Detected | 0 | 6 | 7: SQLi, BOLA, debug-endpoint data exposure, user enumeration, rate limiting, **weak JWT signing key** (firm); unauthorized password change (tentative) | 8: the same plus **RegexDoS** (firm) |
| Detected, among the vulnerabilities apifuzz has a check for | 0 | 6 / 7 | 7 / 9 | 8 / 9 |
| False positives, vulnerable build | 25 with tokens / 12 without | 0 | 0 | 0 |
| False positives, secure build | 25 with tokens / 12 without | 0 | 0 | 0 |

The default scan sent 998 requests per build and reported 22 findings on the vulnerable build (11 of them
rate-limit findings, one per endpoint) and 16 on the secure build (11 rate-limit: VAmPI keeps that flaw in both
builds). The `--time-based` run sent 1,127 requests per build and reported 25 findings on the vulnerable build.

**Not detected:** mass assignment on `POST /users/v1/register` (the `admin` flag is stored, but nothing the API
returns to the scan shows it; only `/me` as the new user and the debug endpoint do), and RegexDoS in the default
scan (the check is opt-in with `--time-based`).

**v0.1.0** was measured against the same targets, seeding, expected list and scoring through a compatibility
adapter (`benchmarks/compare_v010.py`). With tokens configured it hits v0.1.0's auth-header bug (the real token
overwrote the auth probes' headers), so all 25 findings are false broken-auth reports; without tokens (its
documented default) it reports 12, also all broken-auth false positives on endpoints VAmPI documents as public.

### Disclosures: rules changed after seeing benchmark output

Each change removed false positives or added detections that showed up on VAmPI, so read the numbers with this
in mind:

1. **inventory**: the first run reported VAmPI's own spec and Swagger UI (`/openapi.json`, `/openapi.yaml`,
   `/ui/`) on both builds, 3 false positives each. Every FastAPI-style app publishes these by default, so
   `inventory` now reports a served spec only when it describes operations *missing* from the scanned spec, and
   no longer reports docs UIs (`6036d56`).
2. **data_exposure**: the first run flagged the `secret` field of `GET /books/v1/{book_title}` on both builds.
   That field is the book's own content shown to its owner; whether *other* users can read it is the BOLA
   finding. A bare `secret` field name was dropped from the sensitive-field list (`client_secret`, `secret_key`,
   `api_secret` stay) (`078c980`).
3. **Weak JWT signing key**: the auth check cracks HS256 keys offline against a bundled public wordlist
   (wallarm/jwt-secrets, MIT, the first 10,000 of about 104,000 entries, copied verbatim and checked identical
   to upstream commit `85c852b`). VAmPI signs with `random`, which is at **rank 2,836**: the 10,000 cap was chosen
   for cost (about 45 ms per scan), and a 1,000-entry cap would have missed it. The check was written because
   VAmPI listed the weak key as uncovered.
4. **RegexDoS** (opt-in, `--time-based` only): the probe length (27 characters) and the control's shape
   (`"!" + "a"*27`, which fails a start-anchored regex at once) were calibrated by timing VAmPI's own email
   regex; a plain `"a"*N` control backtracks there too. The check was written because VAmPI listed RegexDoS as
   uncovered.
5. **Mass assignment on register** (still missed): resource linking (a sibling `GET` confirms what a `POST`
   stored) and unique usernames/emails in create probes were written for this miss. VAmPI still can't be
   confirmed: its `GET /users/v1/{username}` never returns the `admin` flag.

Because of 3 and 4, `benchmarks/vampi/expected.yaml` maps the weak key and RegexDoS to those checks (commit
`c3edaa3`). Other fixes from the same review (user_enum lookalike usernames, anchored BFLA hints, data_exposure
placeholder handling) also landed after benchmark runs; they did not change any VAmPI number.

## crAPI (held-out target)

[OWASP crAPI](https://github.com/OWASP/crAPI) was added as a second target **after** the VAmPI work and measured
once with the code as it was (commit `b21ea70`, detection identical to `4bf7b6d`) before any rule was changed for
it. That is the held-out number: how apifuzz does on an API it wasn't developed against. Anything tuned later is
reported separately as "after tuning".

### How the method differs

- **Expected list**: crAPI's 18 documented challenges (`docs/challenges.md` at v1.1.6), each mapped to its
  endpoint from crAPI's solutions doc and service source, written before the first scan. Challenge 9 (refund by
  quantity) is business logic and the 3 chatbot challenges need an OpenAI key: they stay in the list as "not
  covered", leaving 14 that apifuzz has a check for. crAPI's 3 undisclosed "secret challenges" aren't listed.
- **No fixed build**, so there is no false-positive run. Every finding that matches no documented challenge
  counts against precision and was re-checked by hand against the live API.
- **Setup**: `run.py` signs up two fresh users, gives user A a vehicle, an order, a mechanic report, a video
  and a forum post, and writes those ids into the spec's id parameters. Nothing else in the spec changes.
- **Images**: crAPI publishes no complete `1.1.6` image set, so the run used `latest`, pinned by digest.

### Results

| crAPI (18 documented challenges) | held-out (`b21ea70`; reproduced at `5a117ab`) | after tuning (`d8653f0`) |
|---|---|---|
| Documented challenges detected | 5 / 18 (3 firm): vehicle-location BOLA, unauthenticated order access, JWT `alg:none` accepted (firm); video internal property exposed, admin video delete by a normal user (tentative, via the BOLA probe) | **7 / 18 (4 firm)**: also mechanic-report BOLA (firm, an id in a query parameter) and OTP brute force (tentative, weak evidence) |
| ...among the 14 apifuzz has a check for | 5 / 14 | 7 / 14 |
| Findings | 62 (61 in the `5a117ab` reproduction) | 69 |
| Outside the documented list, triaged by hand | 39: 29 real, **10 false positives** (4 firm) | 38: 32 real, **6 false positives** (0 firm, all tentative) |

The held-out run was **reproduced at `5a117ab`** on a freshly created stack from the pinned images after review
fixes to the harness (no detection code changed): the same 5 detections with the same firm/tentative split and
the same 39 unmatched findings, 61 findings instead of 62 (the first run had one more `alg:none` acceptance) and
no failed requests (the first run had 6 timeouts). `crapi-held-out.md` is that reproduction.

Real findings outside the documented list (held-out run) include no rate limiting on 22 other endpoints,
`/.env` served with crAPI's database credentials, login user enumeration, and other users' orders readable.

### Disclosures: what changed because of the held-out run

Each rule is generic (none names a crAPI path or field):

- Required query parameters are now sent on every request (before, only the injection probes set them), and BOLA
  probes id-like query parameters: this found the mechanic-report BOLA.
- Rate limiting on login, one-time-code and reset operations is reported (tentative) when every attempt gets the
  same error with no throttling or lockout. **Weak evidence**: the burst uses the spec's example account, which
  doesn't exist, so a per-account lockout can't show; the same signal fires on crAPI's protected `v3/check-otp`
  (a false positive). Checked by hand with a real account: v2 answered 40 wrong codes without a lockout; v3
  locked out after 9.
- Boolean SQLi sends the control again after the true/false pair, and the four requests run in order with
  nothing in between: a response that grows per request (comments) no longer passes as SQL.
- BOLA reading or `POST`ing to an object user B also gets from a listing is tentative (public by design);
  `PUT`/`PATCH` stays firm. Two fixes to this rule were made after seeing crAPI output: listings longer than
  `--max-body` are searched in their cut text (`6cc112a`), and that search needs each identifying field as a
  `"key": value` pair (`d8653f0`), because matching bare values downgraded the real vehicle-location and
  mechanic-report BOLAs.
- Undocumented-field findings ignore empty values and top-level pagination fields; masked values
  (`XXXXXXXXXXXX9999`) no longer count as exposed secrets.

The held-out number stays the honest measure; the after-tuning number is shown next to it, never instead of it.

### Still missed

4 (other users' emails in `posts/recent`: no low-noise generic rule without knowing who the caller is),
6 (`contact_mechanic` rate limit; cause not investigated), 8 and 10 (mass assignment through `PUT`), 11 (SSRF
without an `--oob-url` collector), 12 and 13 (coupon NoSQLi/SQLi). Not covered: 9 (business logic) and 16-18
(LLM chatbot).

## Reproducing

```bash
py -3.10 -m pip install -e ".[dev]"
docker compose -f benchmarks/vampi/docker-compose.yml up -d     # vulnerable :5002, secure :5001
py -3.10 benchmarks/run.py vampi                                # writes benchmarks/results/vampi.{md,json}
py -3.10 benchmarks/run.py vampi --time-based

git clone --depth 1 --branch v1.1.6 https://github.com/OWASP/crAPI /path/to/crAPI
docker compose -p crapi -f /path/to/crAPI/deploy/docker/docker-compose.yml \
  -f benchmarks/crapi/docker-compose.pinned.yml up -d --wait   # ~10 containers; :8888
py -3.10 benchmarks/run.py crapi                                # ~11 min
```

A weekly workflow re-runs the VAmPI benchmark and fails if detection drops or false positives appear compared
with the committed `vampi.json`; the crAPI job runs on demand.

**Honesty rule.** Any rule change motivated by benchmark output is disclosed in `benchmarks/README.md`, and the
held-out crAPI number stays published next to any after-tuning number.
