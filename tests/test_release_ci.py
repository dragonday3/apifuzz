"""Phase 4.2: SARIF fingerprints, --fail-on, ignore file."""
import datetime
import json

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from fuzzowl import ignore
from fuzzowl.cli import app
from fuzzowl.models.finding import Finding, OWASPCategory, Severity
from fuzzowl.reporters.sarif import SARIFReporter


def finding(rule="FUZZOWL-BOLA-001", url="http://api/books/bookTitle12", endpoint="GET /books/{t}",
            severity=Severity.HIGH):
    return Finding(title="t", description="d", severity=severity, owasp_category=OWASPCategory.API1_BOLA,
                   endpoint_method="GET", endpoint_path=url, rule_id=rule, endpoint=endpoint)


def fp(f):
    return SARIFReporter().generate([f])["runs"][0]["results"][0]["partialFingerprints"]["fuzzowlFinding/v1"]


def test_fingerprint_stable_across_runs_and_distinct_per_rule_and_operation():
    assert fp(finding(url="http://api/books/bookTitle12")) == fp(finding(url="http://api/books/bookTitle87"))
    assert fp(finding()) != fp(finding(rule="FUZZOWL-BOLA-002"))
    assert fp(finding()) != fp(finding(endpoint="GET /users/{u}"))


def test_ignore_matching_globs_and_expiry():
    rules = [ignore.IgnoreRule("FUZZOWL-RATE-*"),
             ignore.IgnoreRule("FUZZOWL-BOLA-001", "GET /books/*"),
             ignore.IgnoreRule("FUZZOWL-AUTH-*", expires=datetime.date(2020, 1, 1))]
    fs = [finding(rule="FUZZOWL-RATE-001", endpoint="GET /x"), finding(),
          finding(endpoint="GET /users/{u}"), finding(rule="FUZZOWL-AUTH-NO_AUTH")]
    kept, suppressed, expired = ignore.apply(fs, rules, today=datetime.date(2026, 11, 23))
    assert [f.endpoint for f in suppressed] == ["GET /x", "GET /books/{t}"]
    assert [f.rule_id for f in kept] == ["FUZZOWL-BOLA-001", "FUZZOWL-AUTH-NO_AUTH"]  # expired entry: not suppressed
    assert [r.rule_id for r in expired] == ["FUZZOWL-AUTH-*"]


def test_ignore_file_round_trip_and_validation(tmp_path):
    p = tmp_path / "ig.yaml"
    assert ignore.write([finding(), finding(url="http://api/books/other")], p) == 1  # one per rule+operation
    [rule] = ignore.load(p)
    assert (rule.rule_id, rule.endpoint) == ("FUZZOWL-BOLA-001", "GET /books/{t}")
    p.write_text(yaml.safe_dump({"ignore": [{"endpoint": "GET /x"}]}))
    with pytest.raises(ValueError):
        ignore.load(p)


SPEC = """openapi: "3.0.3"
info: {title: t, version: "1"}
paths:
  /me: {get: {responses: {"200": {description: ok}}}}
"""


def run_cli(tmp_path, *args):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    with respx.mock(assert_all_called=False) as router:
        # No auth enforced at all: a CRITICAL "No Auth accepted" finding.
        router.route(host="api").mock(return_value=httpx.Response(200, json={"me": "alice"}))
        return CliRunner().invoke(app, [str(spec), "--target", "http://api", "--checks", "auth", "--quiet",
                                        "--rate-limit", "0", *args])


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # a stray .fuzzowl-ignore.yaml where pytest runs must not change results


@pytest.mark.parametrize("level,code", [("critical", 1), ("high", 1), ("never", 0)])
def test_fail_on(tmp_path, level, code):
    assert run_cli(tmp_path, "--fail-on", level).exit_code == code


def test_fail_on_rejects_unknown_level(tmp_path):
    assert run_cli(tmp_path, "--fail-on", "severe").exit_code == 2


def test_write_ignore_then_suppressed_run_passes(tmp_path):
    ig = tmp_path / "accepted.yaml"
    assert run_cli(tmp_path, "--write-ignore", str(ig)).exit_code == 0
    result = run_cli(tmp_path, "--ignore-file", str(ig))
    assert result.exit_code == 0 and json.loads(result.stdout) == []


def test_default_ignore_file_is_picked_up_and_expired_entries_warned(tmp_path):
    (tmp_path / ".fuzzowl-ignore.yaml").write_text(yaml.safe_dump({"ignore": [
        {"rule_id": "FUZZOWL-AUTH-*", "reason": "staging only"},
        {"rule_id": "FUZZOWL-CORS-*", "expires": "2020-01-01"}]}))
    result = run_cli(tmp_path)
    assert result.exit_code == 0 and json.loads(result.stdout) == []
    assert "expired on 2020-01-01" in result.output


def test_write_ignore_keeps_existing_entries_and_reasons(tmp_path):
    ig = tmp_path / ".fuzzowl-ignore.yaml"
    ig.write_text(yaml.safe_dump({"ignore": [
        {"rule_id": "FUZZOWL-AUTH-NO_AUTH", "endpoint": "GET /me", "reason": "reviewed by sec team",
         "expires": "2099-01-01"}]}))
    assert run_cli(tmp_path, "--write-ignore", str(ig)).exit_code == 0
    entries = yaml.safe_load(ig.read_text())["ignore"]
    kept = [e for e in entries if e["rule_id"] == "FUZZOWL-AUTH-NO_AUTH"]
    assert kept == [{"rule_id": "FUZZOWL-AUTH-NO_AUTH", "endpoint": "GET /me", "reason": "reviewed by sec team",
                     "expires": "2099-01-01"}]
    assert len(entries) > 1  # the other (previously unaccepted) findings were added


@pytest.mark.parametrize("content", [
    "ignore:\n",                                    # empty list: fine, no rules
    "# nothing yet\n",
])
def test_ignore_load_accepts_empty(tmp_path, content):
    p = tmp_path / "i.yaml"
    p.write_text(content)
    assert ignore.load(p) == []


@pytest.mark.parametrize("content", [
    "- rule_id: X\n",                                       # top-level list
    "ignore: {rule_id: X}\n",                               # not a list
    "ignore:\n  - {rule_id: X, expires: 20270131}\n",       # int date
    "ignore:\n  - {rule_id: X, expires: soon}\n",
])
def test_ignore_load_rejects_bad_files_before_the_scan(tmp_path, content):
    p = tmp_path / "i.yaml"
    p.write_text(content)
    with pytest.raises(ValueError):
        ignore.load(p)


def test_ignore_datetime_expiry_is_normalised(tmp_path):
    p = tmp_path / "i.yaml"
    p.write_text("ignore:\n  - {rule_id: X, expires: 2027-01-31T00:00:00}\n")
    assert ignore.load(p)[0].expires == datetime.date(2027, 1, 31)


def test_fingerprint_distinguishes_parameters_and_location_uses_operation():
    a = finding()
    b = finding()
    b.parameter = "title"
    assert fp(a) != fp(b)
    loc = SARIFReporter().generate([a])["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "/books/%7Bt%7D"


def test_sarif_reports_the_package_version():
    from fuzzowl import __version__
    driver = SARIFReporter().generate([finding()])["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__ != "0.1.0"
