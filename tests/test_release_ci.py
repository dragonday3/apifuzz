"""Phase 4.2: SARIF fingerprints, --fail-on, ignore file."""
import datetime
import json

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from apifuzz import ignore
from apifuzz.cli import app
from apifuzz.models.finding import Finding, OWASPCategory, Severity
from apifuzz.reporters.sarif import SARIFReporter


def finding(rule="APIFUZZ-BOLA-001", url="http://api/books/bookTitle12", endpoint="GET /books/{t}",
            severity=Severity.HIGH):
    return Finding(title="t", description="d", severity=severity, owasp_category=OWASPCategory.API1_BOLA,
                   endpoint_method="GET", endpoint_path=url, rule_id=rule, endpoint=endpoint)


def fp(f):
    return SARIFReporter().generate([f])["runs"][0]["results"][0]["partialFingerprints"]["apifuzzFinding/v1"]


def test_fingerprint_stable_across_runs_and_distinct_per_rule_and_operation():
    assert fp(finding(url="http://api/books/bookTitle12")) == fp(finding(url="http://api/books/bookTitle87"))
    assert fp(finding()) != fp(finding(rule="APIFUZZ-BOLA-002"))
    assert fp(finding()) != fp(finding(endpoint="GET /users/{u}"))


def test_ignore_matching_globs_and_expiry():
    rules = [ignore.IgnoreRule("APIFUZZ-RATE-*"),
             ignore.IgnoreRule("APIFUZZ-BOLA-001", "GET /books/*"),
             ignore.IgnoreRule("APIFUZZ-AUTH-*", expires=datetime.date(2020, 1, 1))]
    fs = [finding(rule="APIFUZZ-RATE-001", endpoint="GET /x"), finding(),
          finding(endpoint="GET /users/{u}"), finding(rule="APIFUZZ-AUTH-NO_AUTH")]
    kept, suppressed, expired = ignore.apply(fs, rules, today=datetime.date(2026, 11, 23))
    assert [f.endpoint for f in suppressed] == ["GET /x", "GET /books/{t}"]
    assert [f.rule_id for f in kept] == ["APIFUZZ-BOLA-001", "APIFUZZ-AUTH-NO_AUTH"]  # expired entry: not suppressed
    assert [r.rule_id for r in expired] == ["APIFUZZ-AUTH-*"]


def test_ignore_file_round_trip_and_validation(tmp_path):
    p = tmp_path / "ig.yaml"
    assert ignore.write([finding(), finding(url="http://api/books/other")], p) == 1  # one per rule+operation
    [rule] = ignore.load(p)
    assert (rule.rule_id, rule.endpoint) == ("APIFUZZ-BOLA-001", "GET /books/{t}")
    p.write_text(yaml.safe_dump({"ignore": [{"endpoint": "GET /x"}]}))
    with pytest.raises(ValueError):
        ignore.load(p)


SPEC = """openapi: "3.0.3"
info: {title: t, version: "1"}
paths:
  /me: {get: {responses: {"200": {description: ok}}}}
"""


def run_cli(tmp_path, *args, cwd_ignore=None):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    with respx.mock(assert_all_called=False) as router:
        # No auth enforced at all: a CRITICAL "No Auth accepted" finding.
        router.route(host="api").mock(return_value=httpx.Response(200, json={"me": "alice"}))
        return CliRunner().invoke(app, [str(spec), "--target", "http://api", "--checks", "auth", "--quiet",
                                        "--rate-limit", "0", *args])


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
