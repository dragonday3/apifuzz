"""Phase 0.2: body-based probes must send example bodies a real API accepts, not the schema."""
from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

from .conftest import BASE, PETSTORE

ALICE = AuthConfig(type="bearer", token="token-alice")


async def test_mass_assignment_body_is_accepted(mock_api):
    api = mock_api()
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["mass_assignment"], rate_limit_rps=0).run()
    # The mock returns 422 unless "name" is a string: a schema dict body would never get past it.
    assert api.statuses[("POST", "/pets")] == [201]


async def test_probes_hit_concrete_path(mock_api):
    api = mock_api()
    await Scanner(PETSTORE, BASE, auth=ALICE, checks=["auth"], rate_limit_rps=0).run()
    assert not any("{" in path or "%7B" in path for _, path in api.hits)
