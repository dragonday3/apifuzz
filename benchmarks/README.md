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
- **Counted as found:** a vulnerability is detected by a firm or a tentative finding; the table says which.

## Results

Latest run: [`results/vampi.md`](results/vampi.md).

| VAmPI (9 documented vulnerabilities) | v0.1.0 | current |
|---|---|---|
| Detected | 0 | 4 (SQLi, BOLA, unauthorized password change, rate limiting) |
| Detected, among the 5 apifuzz has a check for | 0 / 5 | 4 / 5 |
| False positives, vulnerable build | 25 | 0 |
| False positives, secure build | 25 | 0 |

v0.1.0 was measured on 2026-11-23 with the same harness, targets, seeding and scoring (its scanner takes no
safety options and its findings were mapped to spec operations by URL). All 25 of its findings were
broken-auth reports caused by the configured token overwriting the auth probes' headers.

**Not detected:**
- Mass assignment on `POST /users/v1/register`. The `admin` flag is stored, but the response has no id or
  `Location` to confirm it with, and it only shows on the debug endpoint.
- Four flaws apifuzz has no check for yet: debug-endpoint data exposure, user enumeration, RegexDoS and the weak JWT key.
