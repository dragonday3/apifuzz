"""Phase 0.1: configured auth must not overwrite the headers the auth/BOLA probes send."""
import pytest

from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

from .conftest import BASE, PETSTORE

ALICE = AuthConfig(type="bearer", token="token-alice", second_token="token-bob")


async def scan(checks: list[str], auth: AuthConfig = ALICE):
    return await Scanner(PETSTORE, BASE, auth=auth, checks=checks, rate_limit_rps=0).run()


async def test_secure_api_has_no_auth_findings(mock_api):
    mock_api()
    findings = await scan(["auth"])
    assert findings == []


async def test_secure_api_has_no_cross_user_bola(mock_api):
    mock_api()
    findings = await scan(["bola"])
    assert [f for f in findings if f.rule_id == "APIFUZZ-BOLA-001"] == []


async def test_api_accepting_any_token_is_flagged(mock_api):
    mock_api(accept_any_token=True)
    findings = await scan(["auth"])
    titles = {f.title for f in findings}
    assert "Broken Auth: Invalid Token accepted" in titles
    # The no-auth probe must still be rejected: it really went out without a token.
    assert "Broken Auth: No Auth accepted" not in titles


async def test_missing_ownership_check_is_flagged_cross_user(mock_api):
    mock_api(enforce_ownership=False)
    findings = await scan(["bola"])
    assert any(f.rule_id == "APIFUZZ-BOLA-001" for f in findings)


async def test_probe_headers_reach_the_wire(mock_api):
    api = mock_api()
    await scan(["auth"])
    assert None in api.auth_seen                              # no_auth
    assert "Bearer INVALID_TOKEN_apifuzz" in api.auth_seen    # invalid_token
    # The configured token only goes out on the baseline (one per non-DELETE endpoint: 3 in petstore),
    # never in place of a probe header.
    assert api.auth_seen.count("Bearer token-alice") == 3


# Per-(method, path) budget: above what one endpoint gets in the first pass, far below first pass + burst.
SECURE_BUDGET = 45


async def full_scan_secure(mock_api):
    api = mock_api(rate_limit=SECURE_BUDGET)
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, rate_limit_rps=0).run()
    # The secure-API claim only holds if the first-pass probes really reached the API (no 429 before bursts).
    for key, statuses in api.statuses.items():
        assert 429 not in statuses[:-50], f"{key} was rate limited before the burst pass"
    return findings


async def test_full_scan_secure_api_only_known_limitation(mock_api):
    """All checks against a secure, rate-limited API. The one remaining false positive is BOLA ID
    enumeration of the caller's own object (README known limitation, plan 1.3)."""
    assert {f.rule_id for f in await full_scan_secure(mock_api)} <= {"APIFUZZ-BOLA-002"}


@pytest.mark.xfail(strict=True, reason="BOLA ID enumeration flags any 200 until plan 1.3")
async def test_full_scan_secure_api_zero_findings(mock_api):
    assert await full_scan_secure(mock_api) == []
