import httpx
import respx

from apifuzz.checks.inventory import InventoryCheck
from apifuzz.models.endpoint import AuthConfig, Endpoint
from apifuzz.scanner import Scanner

EPS = [Endpoint(method="GET", path="/api/v1/users", base_url="http://api"),
       Endpoint(method="GET", path="/openapi.json", base_url="http://api")]  # documented: not probed


def test_global_probes():
    cases = InventoryCheck().generate_global(EPS, AuthConfig())
    paths = [c.extra["path"] for c in cases]
    assert cases[0].extra["strategy"] == "inventory_control"
    assert "/openapi.json" not in paths and "/actuator/env" in paths
    assert {"/api/v2/users", "/api/v0/users"} <= set(paths)
    assert InventoryCheck().generate(EPS[0], AuthConfig()) == []


async def scan(handler, tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text('openapi: "3.0.3"\ninfo: {title: t, version: "1"}\n'
                    'paths:\n  /api/v1/users: {get: {responses: {"200": {description: ok}}}}\n')
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=handler)
        return await Scanner(str(spec), "http://api", checks=["inventory"], rate_limit_rps=0).run()


async def test_exposed_items_need_matching_content(tmp_path):
    def api(request):
        return {
            "/actuator/env": httpx.Response(200, json={"activeProfiles": [], "propertySources": []}),
            "/.env": httpx.Response(200, text="DB_PASSWORD=x\nSECRET_KEY=y\n"),
            "/swagger.json": httpx.Response(200, json={"openapi": "3.0.0"}),
            "/api/v2/users": httpx.Response(200, json=[{"id": 1}]),
            "/metrics": httpx.Response(200, text="all good"),          # 200, but not Prometheus output
        }.get(request.url.path, httpx.Response(404))
    found = {(f.rule_id, f.endpoint_path.removeprefix("http://api")) for f in await scan(api, tmp_path)}
    assert found == {("APIFUZZ-INVENTORY-002", "/actuator/env"), ("APIFUZZ-INVENTORY-002", "/.env"),
                     ("APIFUZZ-INVENTORY-001", "/swagger.json"), ("APIFUZZ-INVENTORY-003", "/api/v2/users")}


async def test_catch_all_server_yields_nothing(tmp_path):
    def spa(request):  # answers every path with the same app shell, which mentions swagger-ui
        return httpx.Response(200, text="<html><div id=app>swagger-ui loader</div></html>")
    assert await scan(spa, tmp_path) == []
