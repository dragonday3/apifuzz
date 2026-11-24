"""Phase 1.4: endpoints the spec declares public must not be reported as auth bypasses (the v0.1.0
VAmPI false positives), and a 200 that doesn't resemble the authenticated response isn't a bypass."""
import textwrap

import httpx
import respx

from fuzzowl.models.endpoint import AuthConfig
from fuzzowl.scanner import Scanner

BASE = "http://testserver"
SPEC = textwrap.dedent("""
    openapi: "3.0.3"
    info: {title: vampi-like, version: "1"}
    components:
      securitySchemes:
        bearerAuth: {type: http, scheme: bearer}
    paths:
      /books:
        get:
          responses: {"200": {description: public list}}
      /me:
        get:
          security: [{bearerAuth: []}]
          responses: {"200": {description: own profile}}
      /status:
        get:
          security: [{bearerAuth: []}]
          responses: {"200": {description: soft-fail endpoint}}
""")
PROFILE = {"username": "alice", "email": "alice@example.com", "admin": False, "books": ["a", "b", "c"]}


def api(request: httpx.Request) -> httpx.Response:
    authed = request.headers.get("authorization") == "Bearer token-alice"
    if request.url.path == "/books":
        return httpx.Response(200, json=[{"title": "public book"}])
    if request.url.path == "/me":
        return httpx.Response(200, json=PROFILE) if authed else httpx.Response(401, json={"error": "no"})
    # Soft-fail: always 200, but the body says unauthorized unless the token is valid.
    if authed:
        return httpx.Response(200, json=PROFILE)
    return httpx.Response(200, json={"status": "fail", "message": "Invalid token"})


async def scan(tmp_path, handler, auth):
    spec = tmp_path / "spec.yaml"
    spec.write_text(SPEC)
    with respx.mock(assert_all_called=False) as router:
        route = router.route(host="testserver").mock(side_effect=handler)
        findings = await Scanner(str(spec), BASE, auth=auth, checks=["auth"], rate_limit_rps=0).run()
    return findings, route


async def test_public_and_soft_fail_endpoints_yield_no_auth_findings(tmp_path):
    findings, route = await scan(tmp_path, api, AuthConfig(type="bearer", token="token-alice"))
    assert findings == []
    assert not any(c.request.url.path == "/books" and c.request.headers.get("authorization") != "Bearer token-alice"
                   for c in route.calls), "public endpoint should not be auth-probed"


async def test_secured_endpoint_open_to_anyone_is_firm(tmp_path):
    def broken(request):
        return httpx.Response(200, json=PROFILE)  # never checks the token
    findings, _ = await scan(tmp_path, broken, AuthConfig(type="bearer", token="token-alice"))
    by_path = {(f.endpoint_path.removeprefix(BASE), f.confidence) for f in findings}
    assert ("/me", "firm") in by_path and ("/status", "firm") in by_path
    assert not any(path == "/books" for path, _ in by_path)
