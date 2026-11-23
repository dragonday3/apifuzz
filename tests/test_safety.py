"""Phase 2: safety and scope."""
import base64
import json
import textwrap

import httpx
import pytest
import respx
from typer.testing import CliRunner

from apifuzz.analyzer import Analyzer
from apifuzz.cli import app
from apifuzz.executor import Executor, RequestBudget
from apifuzz.executor import TestCase as Case
from apifuzz.executor import TestResult as Result
from apifuzz.models.endpoint import AuthConfig
from apifuzz.redact import mask, scrub, secrets_for
from apifuzz.scanner import Scanner

SPEC = textwrap.dedent("""
    openapi: "3.0.3"
    info: {title: t, version: "1"}
    paths:
      /items:
        get: {responses: {"200": {description: ok}}}
        post:
          requestBody: {content: {application/json: {schema: {type: object, properties: {name: {type: string}}}}}}
          responses: {"201": {description: ok}}
      /items/{itemId}:
        parameters: [{name: itemId, in: path, required: true, schema: {type: integer}}]
        get: {responses: {"200": {description: ok}}}
        put: {responses: {"200": {description: ok}}}
        patch: {responses: {"200": {description: ok}}}
        delete: {responses: {"204": {description: ok}}}
      /admin/stats:
        get: {responses: {"200": {description: ok}}}
""")


@pytest.fixture
def spec(tmp_path):
    p = tmp_path / "spec.yaml"
    p.write_text(SPEC)
    return str(p)


def case(url="http://api/items", **kw):
    return Case(method="GET", url=url, headers={}, params={}, body=None, label="t", check_id="auth", **kw)


# 2.1 safe by default, dry run

def test_destructive_methods_skipped_by_default(spec):
    scanner = Scanner(spec, "http://api", checks=["auth"])
    methods = {tc.method for tc in scanner.plan()}
    assert methods == {"GET", "POST"}
    assert sorted(s.split(" (")[0] for s in scanner.skipped) == [
        "DELETE /items/{itemId}", "PATCH /items/{itemId}", "PUT /items/{itemId}"]


def test_allow_destructive_includes_them(spec):
    scanner = Scanner(spec, "http://api", checks=["auth"], allow_destructive=True)
    assert {"PUT", "PATCH", "DELETE"} <= {tc.method for tc in scanner.plan()}


@respx.mock(assert_all_called=False)
def test_dry_run_sends_nothing(spec, respx_mock):
    route = respx_mock.route(host="api").mock(return_value=httpx.Response(200))
    result = CliRunner().invoke(app, [spec, "--target", "http://api", "--dry-run"])
    assert result.exit_code == 0 and route.call_count == 0
    assert "Test plan" in result.output and "Total:" in result.output and "destructive" in result.output


# 2.2 scope lock

async def test_out_of_scope_url_is_never_sent():
    with respx.mock(assert_all_called=False) as router:
        evil = router.get("http://evil.example/x").mock(return_value=httpx.Response(200))
        [r] = await Executor(AuthConfig(type="bearer", token="secret-token"), scope="http://api").run(
            [case("http://evil.example/x")])
    assert evil.call_count == 0 and r.error.startswith("OutOfScope")


async def test_off_host_redirect_is_not_followed():
    with respx.mock(assert_all_called=False) as router:
        router.get("http://api/items").mock(return_value=httpx.Response(302, headers={"Location": "http://evil.example/"}))
        evil = router.get("http://evil.example/").mock(return_value=httpx.Response(200))
        [r] = await Executor(AuthConfig(), scope="http://api").run([case()])
    assert evil.call_count == 0 and r.error.startswith("OutOfScope")


async def test_same_host_redirect_is_followed():
    with respx.mock(assert_all_called=False) as router:
        router.get("http://api/items").mock(return_value=httpx.Response(302, headers={"Location": "/items/"}))
        router.get("http://api/items/").mock(return_value=httpx.Response(200, text="ok"))
        [r] = await Executor(AuthConfig(), scope="http://api").run([case()])
    assert r.status_code == 200


def test_target_overrides_recorded_hosts():
    scanner = Scanner("tests/fixtures/sample.har", "http://scanme.local", checks=["auth"])
    assert {tc.url.split("/")[2] for tc in scanner.plan()} == {"scanme.local"}


def test_include_and_exclude_globs(spec):
    s = Scanner(spec, "http://api", checks=["auth"], include=["/items*"], exclude=["/items/*"])
    assert {tc.url for tc in s.plan()} == {"http://api/items"}
    assert any("/admin/stats (not in --include)" in x for x in s.skipped)


# 2.3 budget and politeness

async def test_max_requests_budget():
    with respx.mock() as router:
        route = router.get("http://api/items").mock(return_value=httpx.Response(200))
        results = await Executor(AuthConfig(), budget=RequestBudget(3)).run([case() for _ in range(5)])
    assert route.call_count == 3
    assert sum(1 for r in results if (r.error or "").startswith("BudgetExhausted")) == 2


async def test_retry_honours_retry_after_then_succeeds():
    with respx.mock() as router:
        route = router.get("http://api/items").mock(side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(503, headers={"Retry-After": "0"}),
            httpx.Response(200)])
        [r] = await Executor(AuthConfig(), rate_limit_rps=0, retries=2).run([case()])
    assert r.status_code == 200 and route.call_count == 3


async def test_bursts_are_never_retried():
    with respx.mock() as router:
        route = router.get("http://api/items").mock(return_value=httpx.Response(429, headers={"Retry-After": "0"}))
        [r] = await Executor(AuthConfig(), retries=2).run([case(throttle=False)])
    assert r.status_code == 429 and route.call_count == 1


# 2.4 TLS and proxy

def test_tls_verified_by_default_and_flags_reach_scanner(spec, monkeypatch):
    assert Executor(AuthConfig())._verify is True
    seen = {}

    class FakeScanner(Scanner):
        def __init__(self, *a, **kw):
            seen.update(kw)
            super().__init__(*a, **kw)

        def plan(self):
            return []

    monkeypatch.setattr("apifuzz.cli.Scanner", FakeScanner)
    CliRunner().invoke(app, [spec, "--target", "https://api", "--insecure", "--proxy", "http://127.0.0.1:8080",
                             "--dry-run"])
    assert seen["verify"] is False and seen["proxy"] == "http://127.0.0.1:8080"


# 2.5 redaction

def test_mask_and_scrub():
    assert mask("Bearer eyJhbGciOi.payload.sig") == "Bear****"
    assert mask("short") == "****"
    secrets = secrets_for("user:pass1234")
    assert base64.b64encode(b"user:pass1234").decode() in secrets
    assert "pass1234" not in scrub("creds user:pass1234 here", secrets)


async def test_findings_never_contain_credentials(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(textwrap.dedent("""
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /me: {get: {responses: {"200": {description: ok}}}}
    """))
    token = "s3cr3t-api-key-value-123"

    def api(request):  # CORS misconfigured, and echoes the custom key header back in the body
        origin = request.headers.get("origin", "")
        return httpx.Response(200, json={"key": request.headers.get("x-custom-key", "")}, headers={
            "access-control-allow-origin": origin, "access-control-allow-credentials": "true"})

    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=api)
        findings = await Scanner(str(spec), "http://api", checks=["cors"], rate_limit_rps=0,
                                 auth=AuthConfig(type="apikey", token=token, header_name="X-Custom-Key")).run()
    dumped = json.dumps([f.model_dump() for f in findings])
    assert findings, "the misconfigured CORS API should yield a finding"
    assert token not in dumped
    assert "X-Custom-Key: s3cr****" in dumped  # custom header isn't on the sensitive list: scrubbed by value



def test_request_sample_is_the_real_request_redacted():
    r = Result(test_case=Case(method="POST", url="http://api/items", headers={}, params={"q": "1"},
                              body={"name": "x"}, label="probe", check_id="auth",
                              extra={"strategy": "no_auth"}),
               status_code=200, response_body="{}", response_headers={}, elapsed_ms=1.0,
               request_headers={"Authorization": "Bearer abcdefghijkl", "Cookie": "sid=0123456789"},
               truncated=True)
    [f] = Analyzer().analyze([r])
    assert f.request_sample.splitlines()[:2] == ["# probe", "POST http://api/items?q=1"]
    assert "Authorization: Bear****" in f.request_sample and "sid=0123456789" not in f.request_sample
    assert '{"name": "x"}' in f.request_sample
    assert "response truncated at 8192 bytes" in f.response_sample


def test_cors_sample_masks_set_cookie():
    tc = Case(method="GET", url="http://api/x", headers={}, params={}, body=None, label="c", check_id="cors",
              extra={"origin": "https://evil.com"})
    headers = {"access-control-allow-origin": "https://evil.com", "access-control-allow-credentials": "true",
               "set-cookie": "session=supersecretvalue"}
    [f] = Analyzer().analyze([Result(test_case=tc, status_code=200, response_body="", response_headers=headers,
                                     elapsed_ms=1.0)])
    assert "supersecretvalue" not in f.response_sample
