"""Regression tests for the Phase 1 review: each case produced a wrong result before the fix."""
import textwrap

import pytest

from apifuzz.analyzer import Analyzer
from apifuzz.checks.auth import AuthCheck
from apifuzz.checks.bola import BOLACheck
from apifuzz.executor import TestCase as Case, TestResult as Result
from apifuzz.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation
from apifuzz.models.finding import Finding, OWASPCategory, Severity
from apifuzz.parsers.openapi import OpenAPIParser
from apifuzz.reporters.sarif import SARIFReporter
from apifuzz.scanner import Scanner

KEY = "GET /items/{itemId}"
JSON = {"content-type": "application/json"}


def res(check_id, status=200, body="", *, method="GET", url="http://api/items/1", headers=None, **extra):
    tc = Case(method=method, url=url, headers={}, params={}, body=None, label=check_id,
                  check_id=check_id, extra={"endpoint_key": KEY, **extra})
    return Result(test_case=tc, status_code=status, response_body=body,
                      response_headers=JSON if headers is None else headers, elapsed_ms=10.0)


@pytest.fixture
def analyzer():
    return Analyzer()


def test_offhost_location_is_never_followed(analyzer):
    for loc in ("http://169.254.169.254/latest/meta-data/", "//evil.example/x", "https://api/items/7"):
        probe = res("mass_assignment", 201, "{}", method="POST", url="http://api/items",
                    headers={"location": loc}, injected_values={"role": "admin"})
        assert analyzer.followups([probe]) == []
    same = res("mass_assignment", 201, "{}", method="POST", url="http://api/items",
               headers={"Location": "/items/7"}, injected_values={"role": "admin"})
    assert [tc.url for tc in analyzer.followups([same])] == ["http://api/items/7"]


def test_error_body_of_similar_length_is_not_an_auth_bypass(analyzer):
    base = res("baseline", body='{"user": "alice", "id": 7}')
    probe = res("auth", body='{"error": "Unauthorized"}', strategy="no_auth")
    assert analyzer.analyze([base, probe]) == []


def test_different_content_type_is_not_an_auth_bypass(analyzer):
    base = res("baseline", body='{"user": "alice"}')
    probe = res("auth", body='<html>login</html>', headers={"content-type": "text/html"}, strategy="no_auth")
    assert analyzer.analyze([base, probe]) == []


def test_generic_not_found_200_is_not_cross_user_bola(analyzer):
    nf = '{"message": "Book not found"}'
    results = [res("baseline", body=nf), res("bola", body=nf, strategy="id_enumeration", probe_id="99999999"),
               res("bola", body=nf, strategy="cross_user", param_name="itemId")]
    assert analyzer.analyze(results) == []


def test_volatile_ids_and_wrappers_do_not_hide_identity(analyzer):
    base = res("baseline", body='{"data": {"id": 1, "owner": "alice"}, "meta": {"request_id": "r1"}}')
    own = res("bola", body='{"data": {"id": 1, "owner": "alice"}, "meta": {"request_id": "r2"}}',
              strategy="id_enumeration", probe_id="1", param_name="itemId")
    leak = res("bola", body='{"data": {"id": 1, "owner": "alice"}, "meta": {"request_id": "r3"}}',
               strategy="cross_user", param_name="itemId")
    findings = analyzer.analyze([base, own, leak])
    assert [(f.rule_id, f.confidence) for f in findings] == [("APIFUZZ-BOLA-001", "firm")]


def test_values_already_present_are_not_mass_assignment(analyzer):
    base = res("baseline", body='{"id": 5, "is_verified": true}', method="PUT", url="http://api/items/5")
    probe = res("mass_assignment", body='{"id": 5, "is_verified": true}', method="PUT",
                url="http://api/items/5", injected_values={"is_verified": True})
    verify_tc = analyzer.followups([probe])[0]
    verify = Result(test_case=verify_tc, status_code=200, response_body='{"id": 5, "is_verified": true}',
                        response_headers=JSON, elapsed_ms=1.0)
    assert analyzer.analyze([base, probe, verify]) == []


def test_tentative_sarif_rule_is_separate_and_capped():
    f = Finding(title="t", description="d", severity=Severity.CRITICAL, owasp_category=OWASPCategory.API1_BOLA,
                endpoint_method="GET", endpoint_path="/x", rule_id="APIFUZZ-BOLA-001", confidence="tentative")
    sarif = SARIFReporter().generate([f])["runs"][0]
    [rule] = sarif["tool"]["driver"]["rules"]
    assert rule["id"] == sarif["results"][0]["ruleId"] == "APIFUZZ-BOLA-001/tentative"
    assert float(rule["properties"]["security-severity"]) < 7.0


def test_no_id_enumeration_deletes():
    ep = Endpoint(method="DELETE", path="/items/{itemId}", base_url="http://api", secured=True,
                  parameters=[Parameter(name="itemId", location=ParamLocation.PATH)])
    cases = BOLACheck().generate(ep, AuthConfig(type="bearer", token="a", second_token="b"))
    assert not [c for c in cases if c.extra["strategy"] == "id_enumeration"]


def test_timed_out_sleep_probe_counts_as_delayed(analyzer):
    control = res("injection", injection_type="sqli", strategy="sqli_bool", pair_id="P", polarity="control")
    timed = []
    for _ in range(3):
        r = res("injection", 0, injection_type="sqli", strategy="sqli_time", pair_id="P sleep",
                polarity="probe", control_id="P")
        r.error, r.elapsed_ms = "ReadTimeout: timed out", 3000.0  # --timeout 3
        timed.append(r)
    [f] = analyzer.analyze([control, *timed])
    assert f.rule_id == "APIFUZZ-INJECT-SQLI-TIME"


def _spec(tmp_path, text):
    p = tmp_path / "s.yaml"
    p.write_text(textwrap.dedent(text))
    return OpenAPIParser().parse(str(p))


def test_optional_auth_skips_auth_check_but_keeps_bola(tmp_path):
    [ep] = _spec(tmp_path, """
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /items/{itemId}:
            get:
              security: [{bearer: []}, {}]
              parameters: [{name: itemId, in: path, required: true, schema: {type: integer}}]
              responses: {"200": {description: ok}}
    """)
    assert (ep.secured, ep.auth_optional) == (False, True)
    auth = AuthConfig(type="bearer", token="a", second_token="b")
    assert AuthCheck().generate(ep, auth) == []
    assert any(c.extra["strategy"] == "cross_user" for c in BOLACheck().generate(ep, auth))


def test_swagger2_security(tmp_path):
    eps = _spec(tmp_path, """
        swagger: "2.0"
        info: {title: t, version: "1"}
        security: [{api_key: []}]
        paths:
          /a: {get: {responses: {"200": {description: ok}}}}
          /b: {get: {security: [], responses: {"200": {description: ok}}}}
    """)
    assert {e.path: e.secured for e in eps} == {"/a": True, "/b": False}


async def test_scan_pass_order(tmp_path, monkeypatch):
    calls: list[set[str]] = []
    scanner = Scanner(str(tmp_path / "unused.yaml"), "http://api", checks=["auth", "injection", "rate_limit"],
                      time_based=True)
    ep = Endpoint(method="GET", path="/search", base_url="http://api",
                  parameters=[Parameter(name="q", location=ParamLocation.QUERY)])
    monkeypatch.setattr(scanner, "_parse", lambda path: [ep])

    async def fake_run(self, cases):
        calls.append({tc.extra.get("strategy") or tc.check_id for tc in cases} if cases else set())
        return []
    monkeypatch.setattr("apifuzz.executor.Executor.run", fake_run)
    await scanner.run()
    assert calls[0] == {"baseline"}
    assert "baseline" not in calls[1] and "sqli_time" not in calls[1] and "burst" not in calls[1]
    assert calls[2] == {"sqli_time"} and calls[-1] == {"burst"}
