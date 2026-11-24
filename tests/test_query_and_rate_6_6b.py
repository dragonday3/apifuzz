"""Phase 6.6b (crAPI held-out misses): required query params on every request, unthrottled guessing on
authentication operations."""
import httpx
import respx

from apifuzz.analyzer import Analyzer
from apifuzz.executor import TestCase, TestResult
from apifuzz.scanner import Scanner

SPEC = """openapi: "3.0.3"
info: {title: t, version: "1"}
paths:
  /reports:
    get:
      security: [{b: []}]
      parameters: [{name: report_id, in: query, required: true, schema: {type: string, example: "7"}},
                   {name: page, in: query, schema: {type: integer}}]
      responses: {"200": {description: ok}}
components: {securitySchemes: {b: {type: http, scheme: bearer}}}
"""


def test_required_query_param_is_on_every_request(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    cases = Scanner(str(spec), "http://api", checks=["auth", "cors", "rate_limit"]).plan()
    assert cases and all(tc.params.get("report_id") == "7" for tc in cases)
    assert not any("page" in tc.params for tc in cases)  # optional params stay off


async def test_cross_user_read_through_a_query_id(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)

    def handler(request):  # report 7 is alice's; no ownership check, so anyone with a token reads it
        if request.url.params.get("report_id") != "7":
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(200, json={"id": 7, "owner": "alice", "problem": "brakes"})

    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=handler)
        from apifuzz.models.endpoint import AuthConfig
        findings = await Scanner(str(spec), "http://api", checks=["bola"], rate_limit_rps=0,
                                 auth=AuthConfig(type="bearer", token="a", second_token="b")).run()
    assert any(f.rule_id == "APIFUZZ-BOLA-001" and f.confidence == "firm" for f in findings)


def burst(path, status, n=50, headers=None, body=b'{"message":"Invalid OTP"}'):
    out = []
    for _ in range(n):
        tc = TestCase(method="POST", url=f"http://api{path}", headers={}, params={}, body={},
                      label="burst", check_id="rate_limit",
                      extra={"burst_total": n, "endpoint_key": f"POST {path}"}, throttle=False)
        out.append(TestResult(test_case=tc, status_code=status, response_headers=dict(headers or
                              {"content-type": "application/json"}), response_body=body.decode(),
                              elapsed_ms=5.0))
    return out


def test_unthrottled_otp_guessing_is_tentative():
    [f] = Analyzer().analyze_rate_limit(burst("/auth/v2/check-otp", 500))
    assert f.confidence == "tentative" and "HTTP 500" in f.evidence


def test_errors_elsewhere_or_with_a_limiter_are_not_reported():
    assert Analyzer().analyze_rate_limit(burst("/workshop/products", 400)) == []
    limited = burst("/login", 401, headers={"content-type": "application/json", "Retry-After": "30"})
    assert Analyzer().analyze_rate_limit(limited) == []


def test_lockout_mid_burst_is_not_reported():
    b = burst("/login", 401)
    for r in b[25:]:
        r.status_code = 403  # locked out after 25 attempts
    assert Analyzer().analyze_rate_limit(b) == []


def _listing(body, truncated):
    tc = TestCase(method="GET", url="http://api/posts/recent", headers={}, params={}, body=None,
                  label="listing", check_id="bola_listing")
    return TestResult(test_case=tc, status_code=200, response_headers={"content-type": "application/json"},
                      response_body=body, elapsed_ms=1.0, truncated=truncated)


def test_listing_cut_by_max_body_is_still_searched():
    from apifuzz.analyzer import _listed_in
    a_post = '{"id": "zctHL6b7", "title": "mine"}'
    cut = '{"posts": [{"id": "other"}, {"id": "zctHL6b7", "title": "mine"}, {"id": "x", "tit'  # cut mid-JSON
    assert _listed_in(a_post, [_listing(cut, truncated=True)]) is not None
    assert _listed_in(a_post, [_listing('{"posts": [{"id": "other"}, {"id": "y", "ti', truncated=True)]) is None
    assert _listed_in(a_post, [_listing('{"posts": [{"id": "zctHL6b7"', truncated=False)]) is None  # just broken
