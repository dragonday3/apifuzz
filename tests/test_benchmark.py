"""The benchmark scoring is what published numbers come from: test it like product code."""
import importlib.util
from pathlib import Path

from apifuzz.models.finding import Finding, OWASPCategory, Severity

_spec = importlib.util.spec_from_file_location("bench_run", Path(__file__).parent.parent / "benchmarks" / "run.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

VULNS = [
    {"id": "sqli", "name": "SQLi", "endpoint": "GET /u/{n}", "check": "injection",
     "rules": ["APIFUZZ-INJECT-SQLI"], "toggled": True},
    {"id": "rate", "name": "Rate", "endpoint": "*", "check": "rate_limit", "rules": ["APIFUZZ-RATE-001"],
     "toggled": False},
    {"id": "jwt", "name": "JWT", "endpoint": "*", "check": None, "rules": [], "toggled": False},
]


def f(rule, endpoint, confidence="firm"):
    return Finding(title="t", description="d", severity=Severity.HIGH, owasp_category=OWASPCategory.API1_BOLA,
                   endpoint_method="GET", endpoint_path="http://x", rule_id=rule, endpoint=endpoint,
                   confidence=confidence)


def test_scoring_detection_fp_and_secure_build():
    vulnerable = [f("APIFUZZ-INJECT-SQLI", "GET /u/{n}"), f("APIFUZZ-RATE-001", "GET /a"),
                  f("APIFUZZ-INJECT-SQLI", "GET /other"),                     # right rule, wrong endpoint: FP
                  f("APIFUZZ-AUTH-NO_AUTH", "GET /u/{n}", "tentative")]      # undocumented: FP
    secure = [f("APIFUZZ-RATE-001", "GET /a"),                               # not toggled: still real
              f("APIFUZZ-INJECT-SQLI", "GET /u/{n}")]                        # toggled off: FP
    s = bench.score(VULNS, vulnerable, secure)
    assert (s["detected"], s["covered"], s["documented"]) == (2, 2, 3)
    assert (s["vulnerable_findings"], s["vulnerable_fp"], s["precision"]) == (4, 2, 0.5)
    assert s["precision_firm"] == round(2 / 3, 3)
    assert (s["secure_findings"], s["secure_fp"]) == (2, 1)
    assert [p["detected"] for p in s["per_vulnerability"]] == [True, True, False]


def test_seed_param_sets_examples():
    spec = {"paths": {"/books/{title}": {"get": {"parameters": [{"name": "title", "in": "path",
                                                                   "schema": {"type": "string"}}]}}}}
    bench.seed_param(spec, "title", "bookTitle42")
    p = spec["paths"]["/books/{title}"]["get"]["parameters"][0]
    assert p["example"] == p["schema"]["example"] == "bookTitle42"


def test_rule_globs_and_query_param_seeding():
    vulns = [{"id": "auth", "name": "A", "endpoint": "GET /o/{id}", "check": "auth", "rules": ["APIFUZZ-AUTH-*"],
              "toggled": False}]
    assert bench.matching(f("APIFUZZ-AUTH-NO_AUTH", "GET /o/{id}"), vulns) == vulns
    assert bench.matching(f("APIFUZZ-BOLA-001", "GET /o/{id}"), vulns) == []
    spec = {"paths": {"/r": {"get": {"parameters": [{"name": "report_id", "in": "query"}]}}}}
    bench.seed_param(spec, "report_id", "7")
    assert spec["paths"]["/r"]["get"]["parameters"][0]["example"] == "7"


def test_report_without_a_fixed_build_lists_unmatched_findings():
    s = bench.score(VULNS, [f("APIFUZZ-INJECT-SQLI", "GET /u/{n}"), f("APIFUZZ-CORS-001", "GET /x")], [])
    meta = {"date": "d", "commit": "c", "scan": "{}", "sent_vulnerable": 5, "errors_vulnerable": {},
            "has_secure": False}
    md = bench.markdown("t", meta, s)
    assert "no fixed build" in md and "secure" not in md.lower()
    assert "`APIFUZZ-CORS-001` (firm) on `GET /x`" in md
