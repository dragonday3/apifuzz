"""Phase 0.1: configured auth must not overwrite the headers the auth/BOLA probes send."""
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
    assert "Bearer token-alice" not in api.auth_seen          # configured token never replaced a probe
