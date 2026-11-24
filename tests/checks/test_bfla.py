import textwrap

import httpx
import respx

from fuzzowl.checks.bfla import BFLACheck
from fuzzowl.models.endpoint import AuthConfig, Endpoint
from fuzzowl.scanner import Scanner

AUTH = AuthConfig(type="bearer", token="admin-tok", low_priv_token="user-tok")


def test_needs_low_priv_token_and_privileged_hint():
    admin_path = Endpoint(method="GET", path="/admin/stats", base_url="http://api")
    by_summary = Endpoint(method="DELETE", path="/users/{u}", base_url="http://api", summary="Deletes user (Only Admins)")
    plain = Endpoint(method="GET", path="/books", base_url="http://api")
    check = BFLACheck()
    assert check.generate(admin_path, AuthConfig(type="bearer", token="t")) == []
    assert check.generate(plain, AUTH) == []
    [tc] = check.generate(by_summary, AUTH)
    assert tc.headers == {"Authorization": "Bearer user-tok"} and tc.auth_mode == "override"
    assert check.generate(admin_path, AUTH)


SPEC = textwrap.dedent("""
    openapi: "3.0.3"
    info: {title: t, version: "1"}
    paths:
      /admin/stats: {get: {responses: {"200": {description: ok}}}}
      /books: {get: {responses: {"200": {description: ok}}}}
""")


async def scan(tmp_path, enforce_roles: bool, auth=AUTH):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)

    def api(request):
        tok = request.headers.get("authorization", "")
        if request.url.path == "/admin/stats":
            if tok == "Bearer admin-tok" or (tok == "Bearer user-tok" and not enforce_roles):
                return httpx.Response(200, json={"users": 42, "revenue": 1000})
            return httpx.Response(403, json={"error": "admins only"})
        return httpx.Response(200, json=[{"title": "b"}])
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=api)
        return await Scanner(str(spec), "http://api", auth=auth, checks=["bfla"], rate_limit_rps=0).run()


async def test_low_priv_reaching_admin_function_is_firm(tmp_path):
    [f] = await scan(tmp_path, enforce_roles=False)
    assert (f.rule_id, f.endpoint, f.confidence) == ("FUZZOWL-BFLA-001", "GET /admin/stats", "firm")
    assert "user-tok" not in f.request_sample  # low-privilege token redacted too


async def test_role_check_enforced_no_finding(tmp_path):
    assert await scan(tmp_path, enforce_roles=True) == []


async def test_configured_token_not_privileged_no_finding(tmp_path):
    # If the "privileged" token can't call it either, a low-priv 403 vs 403 proves nothing.
    weak = AuthConfig(type="bearer", token="user-tok", low_priv_token="user-tok")
    assert await scan(tmp_path, enforce_roles=True, auth=weak) == []
