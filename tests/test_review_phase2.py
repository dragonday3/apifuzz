"""Regression tests for the Phase 2 review."""
import json
import textwrap

import httpx
import respx
from typer.testing import CliRunner

from apifuzz.analyzer import Analyzer
from apifuzz.cli import app
from apifuzz.executor import Executor, RequestBudget, origin
from apifuzz.executor import TestCase as Case
from apifuzz.executor import TestResult as Result
from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

SEARCH_SPEC = textwrap.dedent("""
    openapi: "3.0.3"
    info: {title: t, version: "1"}
    paths:
      /search:
        get:
          parameters: [{name: q, in: query, schema: {type: string}}]
          responses: {"200": {description: ok}}
""")


def case(url="http://api/items", method="GET", **kw):
    return Case(method=method, url=url, headers={}, params={}, body=None, label="t", check_id="auth", **kw)


def test_origin_normalises_default_ports_and_idn():
    assert origin("http://api:80/x") == origin("http://api/y") == ("http", "api", 80)
    assert origin("https://API:443") == ("https", "api", 443)
    assert origin("http://bücher.de/") == ("http", "xn--bcher-kva.de", 80)
    assert origin("http://api:8080") != origin("http://api")


async def test_target_with_explicit_default_port_is_in_scope():
    with respx.mock() as router:
        route = router.get("http://api/items").mock(return_value=httpx.Response(200))
        [r] = await Executor(AuthConfig(), scope="http://api:80").run([case()])
    assert r.status_code == 200 and route.call_count == 1


def test_burst_cut_short_gives_no_rate_limit_verdict():
    burst = []
    for i in range(50):
        tc = case(throttle=False, extra={"burst_index": i, "burst_total": 50})
        tc.check_id = "rate_limit"
        error = None if i < 3 else "BudgetExhausted: --max-requests reached"
        burst.append(Result(test_case=tc, status_code=200 if i < 3 else 0, response_body="", response_headers={},
                            elapsed_ms=1.0, error=error))
    assert Analyzer().analyze_rate_limit(burst) == []


def _spec(tmp_path, text=SEARCH_SPEC):
    p = tmp_path / "s.yaml"
    p.write_text(text)
    return str(p)


def test_all_requests_failing_is_inconclusive_exit_2(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=httpx.ConnectError("refused"))
        result = CliRunner().invoke(app, [_spec(tmp_path), "--target", "http://api", "--rate-limit", "0",
                                          "--checks", "injection"])
    assert result.exit_code == 2
    assert "inconclusive" in result.output and "ConnectError" in result.output


def test_partial_failures_are_reported(tmp_path):
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        if calls["n"] % 2:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json={})
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=flaky)
        result = CliRunner().invoke(app, [_spec(tmp_path), "--target", "http://api", "--rate-limit", "0",
                                          "--checks", "injection"])
    assert result.exit_code == 0 and "request(s) failed: ConnectError" in result.output


async def test_garbage_retry_after_does_not_crash():
    with respx.mock() as router:
        router.get("http://api/items").mock(side_effect=[httpx.Response(429, headers=[(b"Retry-After", bytes([0xB2]))]),
                                                         httpx.Response(200)])
        [r] = await Executor(AuthConfig(), rate_limit_rps=0, retries=1).run([case()])
    assert r.status_code == 200


async def test_negative_retries_clamped_and_rejected_by_cli(tmp_path):
    with respx.mock() as router:
        router.get("http://api/items").mock(return_value=httpx.Response(200))
        [r] = await Executor(AuthConfig(), retries=-3).run([case()])
    assert r.status_code == 200
    for flag in (["--retries", "-1"], ["--max-requests", "0"]):
        assert CliRunner().invoke(app, [_spec(tmp_path), "--target", "http://api", *flag]).exit_code == 2


async def test_post_503_is_not_retried():
    with respx.mock() as router:
        route = router.post("http://api/items").mock(return_value=httpx.Response(503))
        [r] = await Executor(AuthConfig(), rate_limit_rps=0, retries=2).run([case(method="POST")])
    assert r.status_code == 503 and route.call_count == 1


def test_budget_warning_only_when_requests_were_denied():
    b = RequestBudget(2)
    assert b.take() and b.take() and b.denied == 0
    assert not b.take() and b.denied == 1


async def test_userinfo_password_and_echoed_token_are_scrubbed(tmp_path):
    token = "s3cr3t-api-key-value-123"

    def api(request):  # SQL error page echoing the request's key
        if "'" in request.url.params.get("q", ""):
            return httpx.Response(500, text=f"sqlite3.OperationalError near key={request.headers.get('x-key')}")
        return httpx.Response(200, json={"results": []})
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=api)
        findings = await Scanner(_spec(tmp_path), "http://bob:hunter2pass@api", checks=["injection"],
                                 rate_limit_rps=0,
                                 auth=AuthConfig(type="apikey", token=token, header_name="X-Key")).run()
    dumped = json.dumps([f.model_dump() for f in findings])
    assert findings
    assert token not in dumped and "hunter2pass" not in dumped
    assert "key=s3cr****" in dumped  # the echo in the response body is masked too


def test_recorded_body_secrets_and_custom_header_masked_without_scanner():
    tc = Case(method="POST", url="http://api/login", headers={}, params={}, check_id="auth", label="l",
              body={"username": "alice", "password": "hunter2pass", "nested": {"api_key": "k-123456789"}},
              extra={"strategy": "no_auth"})
    r = Result(test_case=tc, status_code=200, response_body="{}", response_headers={}, elapsed_ms=1.0,
               request_headers={"X-Key": "s3cr3t-api-key-value-123"})
    [f] = Analyzer(sensitive_headers=("X-Key",)).analyze([r])
    assert "hunter2pass" not in f.request_sample and "k-123456789" not in f.request_sample
    assert "X-Key: s3cr****" in f.request_sample and '"username": "alice"' in f.request_sample


def test_invalid_target_is_a_clean_cli_error(tmp_path):
    for bad in ("http://localhost:5055:80", "ftp://api", "not a url"):
        result = CliRunner().invoke(app, [_spec(tmp_path), "--target", bad])
        assert result.exit_code == 2 and "Traceback" not in result.output, bad


async def test_every_auth_probe_is_actually_sent():
    from apifuzz.checks.auth import AuthCheck
    from apifuzz.models.endpoint import Endpoint
    cases = AuthCheck().generate(Endpoint(method="GET", path="/me", base_url="http://api"),
                                 AuthConfig(type="bearer", token="a.b.c"))
    with respx.mock() as router:
        router.get("http://api/me").mock(return_value=httpx.Response(401))
        results = await Executor(AuthConfig(type="bearer", token="a.b.c"), rate_limit_rps=0).run(cases)
    assert [r.error for r in results if r.is_error] == []
