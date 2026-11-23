import pytest
from apifuzz.analyzer import Analyzer
from apifuzz.executor import TestCase, TestResult
from apifuzz.models.finding import Severity, OWASPCategory


def make_tc(check_id="bola", method="GET", url="http://api.example.com/users/1", extra=None):
    return TestCase(
        method=method,
        url=url,
        headers={},
        params={},
        body=None,
        label=f"{check_id} test",
        check_id=check_id,
        extra=extra or {},
    )


def make_result(tc, status_code=200, body="", headers=None, error=None):
    return TestResult(
        test_case=tc,
        status_code=status_code,
        response_body=body,
        response_headers=headers or {},
        elapsed_ms=50.0,
        error=error,
    )


@pytest.fixture
def analyzer():
    return Analyzer()


class TestAnalyzerBOLA:
    def test_cross_user_200_is_critical(self, analyzer):
        tc = make_tc("bola", extra={"strategy": "cross_user"})
        result = make_result(tc, 200)
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].owasp_category == OWASPCategory.API1_BOLA

    def test_cross_user_403_no_finding(self, analyzer):
        tc = make_tc("bola", extra={"strategy": "cross_user"})
        result = make_result(tc, 403)
        assert analyzer.analyze([result]) == []

    def test_id_enumeration_200_is_high(self, analyzer):
        tc = make_tc("bola", extra={"strategy": "id_enumeration", "probe_id": "2"})
        result = make_result(tc, 200)
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_id_enumeration_404_no_finding(self, analyzer):
        tc = make_tc("bola", extra={"strategy": "id_enumeration", "probe_id": "2"})
        result = make_result(tc, 404)
        assert analyzer.analyze([result]) == []

    def test_error_results_skipped(self, analyzer):
        tc = make_tc("bola", extra={"strategy": "cross_user"})
        result = make_result(tc, 0, error="Connection refused")
        assert analyzer.analyze([result]) == []


class TestAnalyzerAuth:
    def test_no_auth_200_is_critical(self, analyzer):
        tc = make_tc("auth", extra={"strategy": "no_auth"})
        result = make_result(tc, 200)
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].owasp_category == OWASPCategory.API2_AUTH

    def test_jwt_alg_none_200_is_critical(self, analyzer):
        tc = make_tc("auth", extra={"strategy": "jwt_alg_none"})
        result = make_result(tc, 200)
        findings = analyzer.analyze([result])
        assert findings[0].severity == Severity.CRITICAL

    def test_invalid_token_200_is_high(self, analyzer):
        tc = make_tc("auth", extra={"strategy": "invalid_token"})
        result = make_result(tc, 200)
        findings = analyzer.analyze([result])
        assert findings[0].severity == Severity.HIGH

    def test_auth_401_no_finding(self, analyzer):
        tc = make_tc("auth", extra={"strategy": "no_auth"})
        result = make_result(tc, 401)
        assert analyzer.analyze([result]) == []


class TestAnalyzerMassAssignment:
    def test_reflected_privileged_field_is_high(self, analyzer):
        tc = make_tc("mass_assignment", extra={"injected_fields": ["isAdmin", "role"]})
        result = make_result(tc, 200, body='{"isAdmin": true, "name": "test"}')
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].owasp_category == OWASPCategory.API3_BOPLA

    def test_no_reflection_no_finding(self, analyzer):
        tc = make_tc("mass_assignment", extra={"injected_fields": ["isAdmin", "role"]})
        result = make_result(tc, 200, body='{"name": "test"}')
        assert analyzer.analyze([result]) == []

    def test_non_200_no_finding(self, analyzer):
        tc = make_tc("mass_assignment", extra={"injected_fields": ["isAdmin"]})
        result = make_result(tc, 400, body='{"isAdmin": true}')
        assert analyzer.analyze([result]) == []


class TestAnalyzerSSRF:
    def test_metadata_in_response_is_critical(self, analyzer):
        tc = make_tc("ssrf", extra={"payload": "http://169.254.169.254/latest/meta-data/"})
        result = make_result(tc, 200, body="ami-id: ami-12345678")
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].owasp_category == OWASPCategory.API7_SSRF

    def test_no_metadata_no_finding(self, analyzer):
        tc = make_tc("ssrf", extra={"payload": "http://169.254.169.254/"})
        result = make_result(tc, 200, body="OK")
        assert analyzer.analyze([result]) == []


class TestAnalyzerInjection:
    def test_sqli_error_in_response_is_critical(self, analyzer):
        tc = make_tc("injection", extra={"injection_type": "sqli"})
        result = make_result(tc, 500, body="You have an error in your SQL syntax near '1'='1'")
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ssti_canary_product_is_critical(self, analyzer):
        tc = make_tc("injection", extra={"injection_type": "ssti"})
        result = make_result(tc, 200, body="Hello 9801547")
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_cmd_injection_uid_in_response(self, analyzer):
        tc = make_tc("injection", extra={"injection_type": "cmd_injection"})
        result = make_result(tc, 200, body="uid=1000(www-data) gid=1000(www-data)")
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_no_error_no_finding(self, analyzer):
        tc = make_tc("injection", extra={"injection_type": "sqli"})
        result = make_result(tc, 200, body='{"data": "clean response"}')
        assert analyzer.analyze([result]) == []


class TestAnalyzerRateLimit:
    def test_all_burst_succeed_triggers_finding(self, analyzer):
        tc = make_tc("rate_limit", extra={"burst_index": 0, "burst_total": 50})
        results = [make_result(tc, 200) for _ in range(50)]
        findings = analyzer.analyze_rate_limit(results)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].owasp_category == OWASPCategory.API4_RATE

    def test_most_burst_blocked_no_finding(self, analyzer):
        tc = make_tc("rate_limit", extra={"burst_index": 0})
        success = [make_result(tc, 200) for _ in range(10)]
        blocked = [make_result(tc, 429) for _ in range(40)]
        findings = analyzer.analyze_rate_limit(success + blocked)
        assert findings == []

    def test_empty_burst_no_finding(self, analyzer):
        assert analyzer.analyze_rate_limit([]) == []


class TestAnalyzerCORS:
    def test_origin_reflection_with_credentials_is_high(self, analyzer):
        tc = make_tc("cors", extra={"strategy": "origin_reflection", "origin": "https://evil.com"})
        result = make_result(tc, 200, headers={
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "true",
        })
        findings = analyzer.analyze([result])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_wildcard_acao_no_finding(self, analyzer):
        tc = make_tc("cors", extra={"strategy": "origin_reflection", "origin": "https://evil.com"})
        result = make_result(tc, 200, headers={
            "access-control-allow-origin": "*",
        })
        assert analyzer.analyze([result]) == []

    def test_no_acac_no_finding(self, analyzer):
        tc = make_tc("cors", extra={"strategy": "origin_reflection", "origin": "https://evil.com"})
        result = make_result(tc, 200, headers={
            "access-control-allow-origin": "https://evil.com",
        })
        assert analyzer.analyze([result]) == []


class TestAnalyzerDedup:
    def test_dedup_keeps_highest_severity(self, analyzer):
        high = make_result(make_tc("bola", url="http://api.example.com/items/1",
                                   extra={"strategy": "id_enumeration", "probe_id": "1"}), 200)
        critical = make_result(make_tc("bola", url="http://api.example.com/items/1",
                                       extra={"strategy": "cross_user"}), 200)
        findings = analyzer.analyze([high, critical])
        # Both have different rule_ids so both kept
        rule_ids = {f.rule_id for f in findings}
        assert "APIFUZZ-BOLA-001" in rule_ids
        assert "APIFUZZ-BOLA-002" in rule_ids

    def test_dedup_same_rule_id_keeps_one(self, analyzer):
        tc1 = make_tc("auth", url="http://api.example.com/items/1",
                      extra={"strategy": "no_auth"})
        tc2 = make_tc("auth", url="http://api.example.com/items/1",
                      extra={"strategy": "no_auth"})
        findings = analyzer.analyze([make_result(tc1, 200), make_result(tc2, 200)])
        assert len(findings) == 1


class TestOWASP2023Labels:
    def test_mass_assignment_is_api3(self, analyzer):
        tc = make_tc("mass_assignment", extra={"injected_fields": ["role"]})
        [f] = analyzer.analyze([make_result(tc, 201, body='{"role": "admin"}')])
        assert f.owasp_category.value.startswith("API3:2023")

    def test_injection_is_not_an_api_category(self, analyzer):
        tc = make_tc("injection", extra={"injection_type": "sqli"})
        [f] = analyzer.analyze([make_result(tc, 500, body="You have an error in your SQL syntax")])
        assert f.owasp_category.value == "A03:2021 Injection (OWASP Top 10)"

    def test_cors_is_api8_misconfiguration(self, analyzer):
        tc = make_tc("cors", extra={"origin": "https://evil.com"})
        headers = {"access-control-allow-origin": "https://evil.com", "access-control-allow-credentials": "true"}
        [f] = analyzer.analyze([make_result(tc, 200, headers=headers)])
        assert f.owasp_category.value == "API8:2023 - Security Misconfiguration"

    def test_member_names_match_values(self):
        from apifuzz.models.finding import OWASPCategory
        for member in OWASPCategory:
            if member.name.startswith("API"):
                assert member.value.startswith(member.name.split("_")[0] + ":2023")



def probe(injection_type, body, *, headers=None, payload="", key="GET /x", status=200, check_id="injection"):
    tc = make_tc(check_id, extra={"injection_type": injection_type, "payload": payload, "endpoint_key": key})
    return make_result(tc, status, body=body, headers=headers)


def baseline(body, key="GET /x"):
    return make_result(make_tc("baseline", extra={"endpoint_key": key}), 200, body=body)


class TestDetectionFalsePositives:
    """Phase 0.4: ordinary responses must not trigger injection/SSRF findings."""

    def test_number_49_is_not_ssti(self, analyzer):
        assert analyzer.analyze([probe("ssti", '{"price": 49, "count": 49}')]) == []

    def test_literal_payload_reflection_is_not_ssti(self, analyzer):
        assert analyzer.analyze([probe("ssti", "you searched {{1337*7331}} 9801547")]) == []

    def test_product_already_in_baseline_is_not_ssti(self, analyzer):
        assert analyzer.analyze([baseline("id 9801547"), probe("ssti", "id 9801547")]) == []

    def test_currency_and_markdown_are_not_cmd_injection(self, analyzer):
        assert analyzer.analyze([probe("cmd_injection", "Total: $ 12.00\n# Heading\n")]) == []

    def test_cmd_canary_detected(self, analyzer):
        [f] = analyzer.analyze([probe("cmd_injection", "out: apifuzz9801547")])
        assert f.rule_id == "APIFUZZ-INJECT-CMD"

    def test_uid_with_hyphenated_user_detected(self, analyzer):
        assert len(analyzer.analyze([probe("cmd_injection", "uid=33(www-data) gid=33(www-data)")])) == 1

    def test_sqli_error_already_in_baseline_is_ignored(self, analyzer):
        page = "docs: what is a syntax error?"
        assert analyzer.analyze([baseline(page), probe("sqli", page)]) == []

    def test_vampi_sqlite_error_detected(self, analyzer):
        body = "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token"
        assert len(analyzer.analyze([probe("sqli", body, status=500)])) == 1

    def test_xss_needs_html_content_type(self, analyzer):
        payload = "<script>apifuzz(1337)</script>"
        json_resp = probe("xss", f'{{"q": "{payload}"}}', payload=payload,
                          headers={"content-type": "application/json"})
        html_resp = probe("xss", f"<p>{payload}</p>", payload=payload,
                          headers={"content-type": "text/html; charset=utf-8"})
        assert analyzer.analyze([json_resp]) == []
        [f] = analyzer.analyze([html_resp])
        assert f.rule_id == "APIFUZZ-INJECT-XSS"

    def test_nosql_error_detected(self, analyzer):
        [f] = analyzer.analyze([probe("nosqli", "MongoServerError: unknown operator: $eq", status=500)])
        assert f.rule_id == "APIFUZZ-INJECT-NOSQLI"

    def test_ssrf_reflected_localhost_is_not_a_finding(self, analyzer):
        body = '{"error": "could not fetch http://localhost:8080 or http://169.254.169.254/latest/meta-data/"}'
        assert analyzer.analyze([probe("", body, check_id="ssrf")]) == []

    def test_ssrf_marker_in_baseline_is_ignored(self, analyzer):
        assert analyzer.analyze([baseline("instance-id docs"), probe("", "instance-id docs", check_id="ssrf")]) == []

    def test_ssrf_metadata_detected(self, analyzer):
        [f] = analyzer.analyze([probe("", "ami-id\ninstance-id\nhostname", check_id="ssrf")])
        assert f.rule_id == "APIFUZZ-SSRF-001"


def nosqli_pair(true_status, true_body, false_status, false_body):
    out = []
    for polarity, status, body in (("true", true_status, true_body), ("false", false_status, false_body)):
        tc = make_tc("injection", extra={"injection_type": "nosqli", "strategy": "nosqli_pair",
                                         "pair_id": "GET /u query.name", "polarity": polarity})
        out.append(make_result(tc, status, body=body))
    return out


class TestNoSQLiPairs:
    def test_differing_pair_is_flagged(self, analyzer):
        users = '[{"name": "alice"}, {"name": "bob"}, {"name": "carol"}]'
        [f] = analyzer.analyze(nosqli_pair(200, users, 200, "[]"))
        assert f.rule_id == "APIFUZZ-INJECT-NOSQLI-BOOL"

    def test_identical_pair_is_not_flagged(self, analyzer):
        assert analyzer.analyze(nosqli_pair(200, "[]", 200, "[]")) == []

    def test_rejected_pair_is_not_flagged(self, analyzer):
        assert analyzer.analyze(nosqli_pair(422, "bad", 400, "bad request")) == []


def test_auth_bypass_with_201_is_flagged(analyzer):
    tc = make_tc("auth", method="POST", extra={"strategy": "invalid_token"})
    assert len(analyzer.analyze([make_result(tc, 201)])) == 1



class TestReviewRegressions:
    def test_duplicate_key_and_cast_errors_are_not_nosqli(self, analyzer):
        for body in ("E11000 duplicate key error collection: app.users",
                     'CastError: Cast to string failed for value "{ \'$ne\': null }"'):
            assert analyzer.analyze([probe("nosqli", body, status=400)]) == []

    def test_pair_split_by_rate_limit_is_not_flagged(self, analyzer):
        assert analyzer.analyze(nosqli_pair(200, '[{"a": 1}]', 429, "slow down")) == []

    def test_pair_split_by_server_error_is_not_flagged(self, analyzer):
        assert analyzer.analyze(nosqli_pair(200, '[{"a": 1}]', 503, "unavailable")) == []

    def test_pair_404_vs_200_is_flagged(self, analyzer):
        assert len(analyzer.analyze(nosqli_pair(200, '[{"name": "alice"}]', 404, "not found"))) == 1

    def test_cross_user_204_is_flagged(self, analyzer):
        tc = make_tc("bola", method="DELETE", extra={"strategy": "cross_user"})
        assert len(analyzer.analyze([make_result(tc, 204)])) == 1

    def test_empty_apikey_wording(self, analyzer):
        [f] = analyzer.analyze([make_result(make_tc("auth", extra={"strategy": "empty_apikey"}), 200)])
        assert "API key" in f.description
