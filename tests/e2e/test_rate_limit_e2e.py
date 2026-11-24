"""Phase 0.6: bursts bypass the global throttle; one verdict per endpoint."""
import time

from fuzzowl.models.endpoint import AuthConfig
from fuzzowl.scanner import Scanner

from .conftest import BASE, PETSTORE

ALICE = AuthConfig(type="bearer", token="token-alice")


async def test_only_unlimited_endpoint_is_flagged(mock_api):
    mock_api(rate_limit=10, rate_limited_paths={"/pets"})
    start = time.monotonic()
    # rps=5 would take 40 s for 200 throttled burst requests; bursts must not be paced.
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, checks=["rate_limit"], rate_limit_rps=5,
                               allow_destructive=True).run()
    assert time.monotonic() - start < 5
    flagged = {(f.endpoint_method, f.endpoint_path) for f in findings}
    # /pets (GET, POST) answers 429 after 10 hits -> protected. /pets/1 (alice's pet) is not limited.
    assert flagged == {("GET", f"{BASE}/pets/1"), ("DELETE", f"{BASE}/pets/1")}


async def test_each_unlimited_endpoint_gets_its_own_finding(mock_api):
    mock_api()  # no rate limiting anywhere
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, checks=["rate_limit"], rate_limit_rps=0).run()
    endpoints = {(f.endpoint_method, f.endpoint_path) for f in findings}
    assert ("GET", f"{BASE}/pets") in endpoints
    assert ("POST", f"{BASE}/pets") in endpoints
    assert len(endpoints) == len(findings)


async def test_bursts_do_not_starve_other_checks(mock_api):
    # Rate-limited API that accepts any token: the invalid-token finding must survive on every
    # endpoint, i.e. the 50-request bursts must not use up the budget before the auth probes run.
    # Per-client budget of 30: enough for the 3 baselines + 20 auth probes, not for any burst.
    mock_api(rate_limit=30, rate_limit_global=True, accept_any_token=True)
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, checks=["auth", "rate_limit"], rate_limit_rps=0,
                               allow_destructive=True).run()
    invalid = {(f.endpoint_method, f.endpoint_path) for f in findings if "Invalid Token" in f.title}
    assert invalid == {("GET", f"{BASE}/pets"), ("POST", f"{BASE}/pets"),
                       ("GET", f"{BASE}/pets/1"), ("DELETE", f"{BASE}/pets/1")}
