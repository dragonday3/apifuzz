import json
import pytest
from apifuzz.reporters.json_reporter import JSONReporter
from apifuzz.models.finding import Finding, Severity, OWASPCategory


def make_finding(rule_id="APIFUZZ-BOLA-001", severity=Severity.HIGH):
    return Finding(
        title="BOLA finding",
        description="Object returned for another user.",
        severity=severity,
        owasp_category=OWASPCategory.API1_BOLA,
        endpoint_method="GET",
        endpoint_path="/api/users/1",
        evidence="HTTP 200",
        remediation="Check object ownership.",
        rule_id=rule_id,
    )


@pytest.fixture
def reporter():
    return JSONReporter()


class TestJSONReporter:
    def test_returns_list(self, reporter):
        assert isinstance(reporter.generate([make_finding()]), list)

    def test_one_finding_one_dict(self, reporter):
        result = reporter.generate([make_finding()])
        assert len(result) == 1
        assert isinstance(result[0], dict)

    def test_contains_title(self, reporter):
        result = reporter.generate([make_finding()])
        assert result[0]["title"] == "BOLA finding"

    def test_severity_serialized_as_string(self, reporter):
        result = reporter.generate([make_finding(severity=Severity.CRITICAL)])
        assert result[0]["severity"] == "critical"

    def test_owasp_category_serialized_as_string(self, reporter):
        result = reporter.generate([make_finding()])
        assert result[0]["owasp_category"] == OWASPCategory.API1_BOLA.value

    def test_rule_id_present(self, reporter):
        result = reporter.generate([make_finding(rule_id="APIFUZZ-TEST-001")])
        assert result[0]["rule_id"] == "APIFUZZ-TEST-001"

    def test_empty_findings_returns_empty_list(self, reporter):
        assert reporter.generate([]) == []

    def test_multiple_findings_length(self, reporter):
        findings = [make_finding(rule_id=f"RULE-{i}") for i in range(5)]
        assert len(reporter.generate(findings)) == 5

    def test_write_produces_valid_json(self, reporter, tmp_path):
        out = tmp_path / "findings.json"
        reporter.write([make_finding()], str(out))
        content = json.loads(out.read_text())
        assert isinstance(content, list)
        assert content[0]["title"] == "BOLA finding"

    def test_all_finding_fields_present(self, reporter):
        result = reporter.generate([make_finding()])[0]
        for field in ("title", "description", "severity", "owasp_category",
                      "endpoint_method", "endpoint_path", "evidence",
                      "remediation", "rule_id"):
            assert field in result


def test_oob_probes_wrap_findings_in_an_object(tmp_path):
    probes = {"apifuzz-ab12cd34": "GET /fetch [url]"}
    assert JSONReporter().generate([make_finding()], {}) == [make_finding().model_dump()]  # no probes: still a list
    out = tmp_path / "r.json"
    JSONReporter().write([make_finding()], str(out), probes)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["oob_probes"] == probes and data["findings"][0]["rule_id"] == "APIFUZZ-BOLA-001"
