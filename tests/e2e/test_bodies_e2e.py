"""Phase 0.2: body-based probes must send example bodies a real API accepts, not the schema."""
from fuzzowl.models.endpoint import AuthConfig
from fuzzowl.scanner import Scanner

from .conftest import BASE, PETSTORE

ALICE = AuthConfig(type="bearer", token="token-alice")


async def test_mass_assignment_body_is_accepted(mock_api):
    api = mock_api()
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["mass_assignment"], rate_limit_rps=0).run()
    # The mock returns 422 unless "name" is a string: a schema dict body would never get past it.
    assert api.statuses[("POST", "/pets")] == [201, 201]  # baseline + mass-assignment probe


async def test_probes_hit_concrete_path(mock_api):
    api = mock_api()
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["auth"], rate_limit_rps=0).run()
    assert not any("{" in path or "%7B" in path for _, path in api.hits)


async def test_baseline_only_for_checks_that_use_it_and_never_delete(mock_api):
    api = mock_api()
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["injection"], rate_limit_rps=0).run()
    assert "Bearer token-alice" in api.auth_seen       # baseline sent for injection
    assert ("DELETE", "/pets/1") not in api.hits       # ...but never a destructive baseline


async def mass_scan(mock_api, mode):
    mock_api(mass_assignment=mode)
    findings = await Scanner(PETSTORE, BASE, auth=ALICE, checks=["mass_assignment"], rate_limit_rps=0).run()
    return [(f.rule_id, f.confidence) for f in findings]


async def test_mass_assignment_persisted_is_firm(mock_api):
    assert await mass_scan(mock_api, "persist") == [("FUZZOWL-MASS-001", "firm")]


async def test_mass_assignment_echo_only_is_tentative(mock_api):
    # Echoed back, and the follow-up GET /pets/3 finds nothing stored.
    assert await mass_scan(mock_api, "reflect") == [("FUZZOWL-MASS-001", "tentative")]


async def test_allowlisted_fields_no_finding(mock_api):
    assert await mass_scan(mock_api, "none") == []
