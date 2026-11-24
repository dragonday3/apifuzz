"""Phase 6.2: resource linking. A POST whose response has no id or Location is followed up through a sibling
GET whose path param matches a request/response field; objects user A creates are read as user B."""
from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

from .conftest import BASE, PETSTORE, REGISTER

ALICE = AuthConfig(type="bearer", token="token-alice")
ALICE_BOB = AuthConfig(type="bearer", token="token-alice", second_token="token-bob")


async def register_scan(mock_api, mode):
    api = mock_api(mass_assignment=mode)
    findings = await Scanner(REGISTER, BASE, auth=ALICE, checks=["mass_assignment"], rate_limit_rps=0).run()
    return api, [(f.rule_id, f.confidence, f.endpoint) for f in findings]


async def test_register_without_id_confirmed_through_sibling_get(mock_api):
    api, findings = await register_scan(mock_api, "persist")
    assert findings == [("APIFUZZ-MASS-001", "firm", "POST /users/register")]
    assert api.hits[("GET", "/users/newuser")] == 1  # the username from the request body


async def test_register_allowlisted_no_finding(mock_api):
    api, findings = await register_scan(mock_api, "none")
    assert findings == []
    assert api.statuses[("GET", "/users/newuser")] == [200]  # followed up, nothing injected was stored


async def bola_scan(mock_api, enforce_ownership):
    api = mock_api(enforce_ownership=enforce_ownership, store_created=True)
    findings = await Scanner(PETSTORE, BASE, auth=ALICE_BOB, checks=["bola"], rate_limit_rps=0).run()
    return api, [(f.rule_id, f.confidence, f.endpoint_path) for f in findings]


async def test_bob_reads_object_alice_created(mock_api):
    api, findings = await bola_scan(mock_api, enforce_ownership=False)
    assert ("APIFUZZ-BOLA-001", "firm", f"{BASE}/pets/3") in findings
    assert api.statuses[("GET", "/pets/3")] == [200, 200]  # alice's read + bob's read


async def test_ownership_enforced_on_created_object(mock_api):
    api, findings = await bola_scan(mock_api, enforce_ownership=True)
    assert not any(url == f"{BASE}/pets/3" for _, _, url in findings)
    assert sorted(api.statuses[("GET", "/pets/3")]) == [200, 403]


async def test_no_second_token_no_created_object_reads(mock_api):
    api = mock_api(enforce_ownership=False)
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["bola"], rate_limit_rps=0).run()
    assert ("GET", "/pets/3") not in api.hits and ("POST", "/pets") not in api.hits
