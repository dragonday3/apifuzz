"""Phase 6.2: resource linking. A POST whose response has no id or Location is followed up through a sibling
GET whose path param matches a request/response field; objects user A creates are read as user B."""
from fuzzowl.models.endpoint import AuthConfig
from fuzzowl.scanner import Scanner

from .conftest import BASE, PETSTORE, REGISTER

ALICE = AuthConfig(type="bearer", token="token-alice")
ALICE_BOB = AuthConfig(type="bearer", token="token-alice", second_token="token-bob")


async def register_scan(mock_api, mode, **kwargs):
    api = mock_api(mass_assignment=mode, **kwargs)
    findings = await Scanner(REGISTER, BASE, auth=ALICE, checks=["mass_assignment"], rate_limit_rps=0).run()
    return api, [(f.rule_id, f.confidence, f.endpoint) for f in findings]


def probe_reads(api):
    """Statuses of the follow-up GETs of the probe's user: the spec example "newuser" plus a unique suffix."""
    return [s for (m, path), st in api.statuses.items() if m == "GET" and path.startswith("/users/newuser")
            and path != "/users/newuser" for s in st]


async def test_register_without_id_confirmed_through_sibling_get(mock_api):
    api, findings = await register_scan(mock_api, "persist")
    assert findings == [("FUZZOWL-MASS-001", "firm", "POST /users/register")]
    assert probe_reads(api) == [200]  # the (unique) username from the probe's request body


async def test_register_allowlisted_no_finding(mock_api):
    api, findings = await register_scan(mock_api, "none")
    assert findings == []
    assert probe_reads(api) == [200]  # followed up, nothing injected was stored


async def test_register_enforcing_unique_usernames_still_confirmed(mock_api):
    # The baseline registers the spec's example user first; the probe needs its own username or it gets a 409.
    api, findings = await register_scan(mock_api, "persist", unique_users=True)
    assert findings == [("FUZZOWL-MASS-001", "firm", "POST /users/register")]
    assert api.statuses[("POST", "/users/register")] == [200, 200]


async def bola_scan(mock_api, enforce_ownership):
    api = mock_api(enforce_ownership=enforce_ownership, store_created=True)
    findings = await Scanner(PETSTORE, BASE, auth=ALICE_BOB, checks=["bola"], rate_limit_rps=0).run()
    return api, [(f.rule_id, f.confidence, f.endpoint_path) for f in findings]


async def test_bob_reads_object_alice_created(mock_api):
    api, findings = await bola_scan(mock_api, enforce_ownership=False)
    assert ("FUZZOWL-BOLA-001", "firm", f"{BASE}/pets/3") in findings
    assert api.statuses[("GET", "/pets/3")] == [200, 200]  # alice's read + bob's read


async def test_ownership_enforced_on_created_object(mock_api):
    api, findings = await bola_scan(mock_api, enforce_ownership=True)
    assert not any(url == f"{BASE}/pets/3" for _, _, url in findings)
    assert sorted(api.statuses[("GET", "/pets/3")]) == [200, 403]


async def test_no_second_token_no_created_object_reads(mock_api):
    api = mock_api(enforce_ownership=False)
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["bola"], rate_limit_rps=0).run()
    assert ("GET", "/pets/3") not in api.hits and ("POST", "/pets") not in api.hits


async def test_publicly_listed_object_read_by_bob_is_tentative(mock_api):
    # Forum-style objects: bob reads alice's pet directly, but GET /pets lists it to him anyway.
    api = mock_api(enforce_ownership=False, store_created=True, public_listing=True)
    findings = await Scanner(PETSTORE, BASE, auth=ALICE_BOB, checks=["bola"], rate_limit_rps=0).run()
    bola = [(f.confidence, f.endpoint_path) for f in findings if f.rule_id == "FUZZOWL-BOLA-001"]
    assert bola and all(c == "tentative" for c, _ in bola), bola
    assert any("also listed for user B in GET" in f.evidence for f in findings)
    assert api.hits[("GET", "/pets")] == 1  # bob's listing read, sent once


async def test_private_listing_keeps_bola_firm(mock_api):
    # Same API, but GET /pets lists only the caller's own pets: bob reading alice's pet stays firm.
    api, findings = await bola_scan(mock_api, enforce_ownership=False)
    assert ("FUZZOWL-BOLA-001", "firm", f"{BASE}/pets/1") in findings
    assert api.statuses[("GET", "/pets")] == [200]
