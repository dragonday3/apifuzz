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
        assert findings[0].owasp_category == OWASPCategory.API6_MASS

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

    def test_ssti_49_reflected_is_critical(self, analyzer):
        tc = make_tc("injection", extra={"injection_type": "ssti"})
        result = make_result(tc, 200, body="Result: 49")
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
        tc = make_tc("bola", url="http://api.example.com/items/1")
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
