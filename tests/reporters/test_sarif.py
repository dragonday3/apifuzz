import json
import pytest
from apifuzz.reporters.sarif import SARIFReporter, SARIF_VERSION, TOOL_NAME
from apifuzz.models.finding import Finding, Severity, OWASPCategory


def make_finding(
    title="SQL Injection found",
    rule_id="APIFUZZ-INJECT-SQLI",
    severity=Severity.CRITICAL,
    owasp=OWASPCategory.API8_INJECT,
    method="GET",
    path="/api/users",
):
    return Finding(
        title=title,
        description="Injection vulnerability detected.",
        severity=severity,
        owasp_category=owasp,
        endpoint_method=method,
        endpoint_path=path,
        evidence="DB error in response",
        remediation="Use parameterized queries.",
        rule_id=rule_id,
    )


@pytest.fixture
def reporter():
    return SARIFReporter()


@pytest.fixture
def single_finding():
    return [make_finding()]


class TestSARIFReporter:
    def test_output_has_schema_field(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        assert "$schema" in sarif

    def test_sarif_version_is_2_1_0(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        assert sarif["version"] == SARIF_VERSION

    def test_runs_array_present(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_driver_name(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        assert sarif["runs"][0]["tool"]["driver"]["name"] == TOOL_NAME

    def test_rules_populated(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "APIFUZZ-INJECT-SQLI"

    def test_results_populated(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "APIFUZZ-INJECT-SQLI"

    def test_critical_maps_to_error_level(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning_level(self, reporter):
        findings = [make_finding(severity=Severity.MEDIUM)]
        sarif = reporter.generate(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note_level(self, reporter):
        findings = [make_finding(severity=Severity.LOW)]
        sarif = reporter.generate(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_rule_dedup_across_findings(self, reporter):
        findings = [
            make_finding(rule_id="APIFUZZ-BOLA-001"),
            make_finding(rule_id="APIFUZZ-BOLA-001"),
        ]
        sarif = reporter.generate(findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # deduped

    def test_location_uri_is_endpoint_path(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "/api/users"

    def test_owasp_category_in_properties(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["owasp_category"] == OWASPCategory.API8_INJECT.value

    def test_empty_findings_valid_sarif(self, reporter):
        sarif = reporter.generate([])
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_total_findings_in_run_properties(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        assert sarif["runs"][0]["properties"]["totalFindings"] == 1

    def test_write_produces_valid_json_file(self, reporter, single_finding, tmp_path):
        out = tmp_path / "results.sarif"
        reporter.write(single_finding, str(out))
        content = json.loads(out.read_text())
        assert content["version"] == SARIF_VERSION

    def test_security_severity_critical_is_high_score(self, reporter, single_finding):
        sarif = reporter.generate(single_finding)
        sec_sev = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
        assert float(sec_sev) >= 9.0
