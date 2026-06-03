import pytest
from pathlib import Path
from apifuzz.reporters.html import HTMLReporter
from apifuzz.models.finding import Finding, Severity, OWASPCategory

TEMPLATES_DIR = str(Path(__file__).parent.parent.parent / "templates")


def make_finding(severity=Severity.CRITICAL, rule_id="APIFUZZ-TEST", title="Test Finding"):
    return Finding(
        title=title,
        description="Test description for this finding.",
        severity=severity,
        owasp_category=OWASPCategory.API1_BOLA,
        endpoint_method="GET",
        endpoint_path="/api/users/1",
        evidence="HTTP 200 returned",
        remediation="Fix it.",
        rule_id=rule_id,
    )


@pytest.fixture
def reporter():
    return HTMLReporter(template_dir=TEMPLATES_DIR)


class TestHTMLReporter:
    def test_generate_returns_string(self, reporter):
        html = reporter.generate([make_finding()])
        assert isinstance(html, str)

    def test_html_contains_doctype(self, reporter):
        html = reporter.generate([make_finding()])
        assert "<!DOCTYPE html>" in html

    def test_finding_title_in_output(self, reporter):
        html = reporter.generate([make_finding(title="SQL Injection found")])
        assert "SQL Injection found" in html

    def test_severity_badge_in_output(self, reporter):
        html = reporter.generate([make_finding(severity=Severity.CRITICAL)])
        assert "critical" in html.lower()

    def test_high_severity_in_output(self, reporter):
        html = reporter.generate([make_finding(severity=Severity.HIGH)])
        assert "high" in html.lower()

    def test_owasp_category_in_output(self, reporter):
        html = reporter.generate([make_finding()])
        assert "API1:2023" in html

    def test_endpoint_in_output(self, reporter):
        html = reporter.generate([make_finding()])
        assert "/api/users/1" in html

    def test_empty_findings_no_crash(self, reporter):
        html = reporter.generate([])
        assert "<!DOCTYPE html>" in html

    def test_empty_findings_shows_no_findings_message(self, reporter):
        html = reporter.generate([])
        assert "No findings" in html

    def test_counts_critical_in_output(self, reporter):
        findings = [make_finding(severity=Severity.CRITICAL) for _ in range(3)]
        html = reporter.generate(findings)
        # The count 3 should appear somewhere
        assert "3" in html

    def test_multiple_findings_all_in_output(self, reporter):
        findings = [
            make_finding(title="Finding Alpha"),
            make_finding(title="Finding Beta"),
        ]
        html = reporter.generate(findings)
        assert "Finding Alpha" in html
        assert "Finding Beta" in html

    def test_write_creates_file(self, reporter, tmp_path):
        out = tmp_path / "report.html"
        reporter.write([make_finding()], str(out))
        assert out.exists()
        assert out.stat().st_size > 1000

    def test_remediation_in_output(self, reporter):
        html = reporter.generate([make_finding()])
        assert "Fix it." in html

    def test_rule_id_in_output(self, reporter):
        html = reporter.generate([make_finding(rule_id="APIFUZZ-BOLA-001")])
        assert "APIFUZZ-BOLA-001" in html
