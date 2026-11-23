"""Phase 0.4: an API that echoes input back must yield no injection findings; a vulnerable one must."""
import json
import textwrap

import httpx
import respx

from apifuzz.scanner import Scanner

BASE = "http://testserver"
SPEC = textwrap.dedent("""
    openapi: "3.0.3"
    info: {title: search, version: "1"}
    paths:
      /search:
        get:
          parameters:
            - {name: q, in: query, schema: {type: string}}
          responses: {"200": {description: ok}}
      /users/{username}:
        get:
          parameters:
            - {name: username, in: path, required: true, schema: {type: string, example: name1}}
          responses: {"200": {description: ok}}
""")


def echo_api(request: httpx.Request) -> httpx.Response:
    """Secure but chatty: reflects every input verbatim in JSON, prices contain 49."""
    q = request.url.params.get("q") or request.url.path.rsplit("/", 1)[-1]
    return httpx.Response(200, json={"query": q, "price": 49, "note": "costs $ 49"})


def vulnerable_api(request: httpx.Request) -> httpx.Response:
    """SQL built by string concatenation, Jinja-style template rendering of q."""
    from urllib.parse import unquote
    q = request.url.params.get("q")
    if q is not None:
        rendered = q.replace("{{1337*7331}}", "9801547")
        return httpx.Response(200, json={"results": [], "title": rendered})
    username = unquote(request.url.path.rsplit("/", 1)[-1])
    # WHERE username = '<input>': a true condition still finds name1, a false one finds nobody.
    if username.startswith("name1' AND '1'='1"):
        return httpx.Response(200, json={"username": "name1"})
    if username.startswith("name1' AND '1'='2"):
        return httpx.Response(404, json={"message": "User not found"})
    if username.count("'") % 2:
        return httpx.Response(500, text=f"sqlite3.OperationalError: unrecognized token: \"'{username}'\"")
    return httpx.Response(200, json={"username": username})


async def run(tmp_path, handler):
    spec = tmp_path / "search.yaml"
    spec.write_text(SPEC)
    with respx.mock(assert_all_called=False) as router:
        router.route(host="testserver").mock(side_effect=handler)
        return await Scanner(str(spec), BASE, checks=["injection"], rate_limit_rps=0).run()


async def test_echoing_api_has_no_injection_findings(tmp_path):
    findings = await run(tmp_path, echo_api)
    assert findings == [], json.dumps([f.title for f in findings])


async def test_vulnerable_api_findings(tmp_path):
    rules = {(f.rule_id, f.endpoint_path.split("/")[3].split("?")[0]) for f in await run(tmp_path, vulnerable_api)}
    assert ("APIFUZZ-INJECT-SQLI", "users") in rules     # lone-quote payload on the path param
    assert ("APIFUZZ-INJECT-SSTI", "search") in rules
    assert ("APIFUZZ-INJECT-SQLI-BOOL", "users") in rules  # true/false conditions differ
