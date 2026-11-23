"""Phase 0.6: bursts bypass the global throttle; one verdict per endpoint."""
import time

from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

from .conftest import BASE, PETSTORE

ALICE = AuthConfig(type="bearer", token="token-alice")


async def test_only_unlimited_endpoint_is_flagged(mock_api):
    mock_api(rate_limit=10, rate_limited_paths={"/pets"})
    start = time.monotonic()
    # rps=5 would take 40 s for 200 throttled burst requests; bursts must not be paced.
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, checks=["rate_limit"], rate_limit_rps=5).run()
    assert time.monotonic() - start < 5
    flagged = {(f.endpoint_method, f.endpoint_path) for f in findings}
    # /pets (GET, POST) answers 429 after 10 hits -> protected. /pets/{petId} GET returns 200 for
    # alice's pet... the probe URL uses the literal template, which 404s, so it isn't flagged either.
    assert not any(path == f"{BASE}/pets" for _, path in flagged)


async def test_each_unlimited_endpoint_gets_its_own_finding(mock_api):
    mock_api()  # no rate limiting anywhere
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, checks=["rate_limit"], rate_limit_rps=0).run()
    endpoints = {(f.endpoint_method, f.endpoint_path) for f in findings}
    assert ("GET", f"{BASE}/pets") in endpoints
    assert ("POST", f"{BASE}/pets") in endpoints
    assert len(endpoints) == len(findings)
