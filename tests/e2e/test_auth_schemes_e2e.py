"""API-key and basic auth end to end: the probes must use the configured scheme, the second user's
credential must be sent in the same scheme, and a secure API must yield nothing."""
import pytest

from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

from .conftest import BASE, PETSTORE

SCHEMES = {
    "apikey": AuthConfig(type="apikey", header_name="X-API-Key", token="key-alice", second_token="key-bob"),
    "basic": AuthConfig(type="basic", token="alice:pw-alice", second_token="bob:pw-bob"),
}


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
async def test_secure_api_no_findings(mock_api, scheme):
    mock_api()
    assert await Scanner(PETSTORE, BASE, auth=SCHEMES[scheme], checks=["auth", "bola"], rate_limit_rps=0).run() == []


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
async def test_vulnerable_api_findings(mock_api, scheme):
    mock_api(accept_any_token=True, enforce_ownership=False)
    findings = await Scanner(PETSTORE, BASE, auth=SCHEMES[scheme], checks=["auth", "bola"], rate_limit_rps=0).run()
    rules = {(f.rule_id, f.endpoint) for f in findings}
    assert ("APIFUZZ-AUTH-INVALID_TO", "GET /pets") in rules          # garbage credential accepted
    assert ("APIFUZZ-BOLA-001", "GET /pets/{petId}") in rules         # bob's credential reads alice's pet
