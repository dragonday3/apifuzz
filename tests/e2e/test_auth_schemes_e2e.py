"""API-key and basic auth end to end: the probes must use the configured scheme, the second user's
credential must be sent in the same scheme, and a secure API must yield nothing."""
import pytest

from fuzzowl.models.endpoint import AuthConfig
from fuzzowl.scanner import Scanner

from .conftest import BASE, PETSTORE

SCHEMES = {
    "apikey": AuthConfig(type="apikey", header_name="X-API-Key", token="key-alice", second_token="key-bob"),
    "basic": AuthConfig(type="basic", token="alice:pw-alice", second_token="bob:pw-bob"),
}


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
async def test_secure_api_no_findings(mock_api, scheme):
    api = mock_api(scheme=scheme)
    assert await Scanner(PETSTORE, BASE, auth=SCHEMES[scheme], checks=["auth", "bola"], rate_limit_rps=0).run() == []
    # The baseline authenticated in the configured scheme (a wrong-scheme send would have been 401 everywhere).
    assert 200 in api.statuses[("GET", "/pets")]


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
async def test_vulnerable_api_findings(mock_api, scheme):
    mock_api(accept_any_token=True, enforce_ownership=False, scheme=scheme)
    findings = await Scanner(PETSTORE, BASE, auth=SCHEMES[scheme], checks=["auth", "bola"], rate_limit_rps=0).run()
    rules = {(f.rule_id, f.endpoint) for f in findings}
    assert ("FUZZOWL-AUTH-INVALID_TO", "GET /pets") in rules          # garbage credential accepted
    assert ("FUZZOWL-BOLA-001", "GET /pets/{petId}") in rules         # bob's credential reads alice's pet
