"""Regression tests for the Phase 3 review."""
import json
import random
import re
import textwrap

import pytest

from apifuzz.analyzer import Analyzer, _undocumented_fields
from apifuzz.checks.bfla import BFLACheck, privilege_hint
from apifuzz.checks.user_enum import UserEnumCheck, lookalike
from apifuzz.executor import TestCase as Case
from apifuzz.executor import TestResult as Result
from apifuzz.models.endpoint import AuthConfig, Endpoint
from apifuzz.parsers.openapi import OpenAPIParser
from apifuzz.scanner import Scanner


def enum(known_user, responses):
    ep = Endpoint(method="POST", path="/login", base_url="http://api",
                  body_example={"username": known_user, "password": "pw"})
    cases = UserEnumCheck().generate(ep, AuthConfig())
    return Analyzer().analyze([
        Result(test_case=c, status_code=status(c.body["username"]), response_body=body(c.body["username"]),
               response_headers={}, elapsed_ms=1.0)
        for c, (status, body) in zip(cases, responses)])


@pytest.mark.parametrize("user", ["user", "test", "string"])
def test_identical_generic_error_with_common_word_username(user):
    same = (lambda u: 401, lambda u: '{"error": "Invalid username or password"}')
    assert enum(user, [same, same, same]) == []


def test_case_folded_echo_is_not_a_difference():
    echo = (lambda u: 401, lambda u: f'{{"error": "bad credentials for {u.lower()}"}}')
    assert enum("Alice", [echo, echo, echo]) == []


def test_unknown_users_share_the_known_users_format():
    rng = random.Random(1)
    for known in ("alice", "Bob42", "jane.doe@corp.io", "u_123"):
        fake = lookalike(known, rng)
        assert fake != known and len(fake) == len(known)
        assert [c.isdigit() for c in fake] == [c.isdigit() for c in known]
        assert [c.isupper() for c in fake] == [c.isupper() for c in known]
        assert fake.partition("@")[2] == known.partition("@")[2]


def test_format_validating_server_is_not_enumeration():
    # 400 for anything that isn't 3-16 alphanumerics, 401 for everyone else: nobody "exists".
    def status(u):
        return 401 if re.fullmatch(r"[A-Za-z0-9]{3,16}", u) else 400
    resp = (status, lambda u: '{"error": "no"}')
    assert enum("alice", [resp, resp, resp]) == []


@pytest.mark.parametrize("ep,expected", [
    (Endpoint(method="GET", path="/users/{id}/manager", summary="Get a user's manager"), None),
    (Endpoint(method="GET", path="/docs", summary="Admins can also edit these docs"), None),
    (Endpoint(method="GET", path="/rootkit-scan"), None),
    (Endpoint(method="GET", path="/admin/stats"), "admin"),
    (Endpoint(method="DELETE", path="/users/{u}", summary="Deletes user (Only Admins)"), "Only Admins"),
    (Endpoint(method="POST", path="/x", operation_id="adminResetPassword"), "admin"),
    (Endpoint(method="GET", path="/x", tags=["Management"]), "Management"),
    (Endpoint(method="GET", path="/x", privileged=True), "x-admin/x-internal extension"),
])
def test_privilege_hints_are_anchored(ep, expected):
    assert privilege_hint(ep) == expected


def test_bfla_skips_public_endpoints():
    ep = Endpoint(method="POST", path="/admin/login", secured=False)
    assert BFLACheck().generate(ep, AuthConfig(type="bearer", token="a", low_priv_token="b")) == []


def _spec(tmp_path, text):
    p = tmp_path / "s.yaml"
    p.write_text(textwrap.dedent(text))
    return str(p)


def test_inventory_respects_globs_and_unfiltered_spec(tmp_path):
    spec = _spec(tmp_path, """
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /metrics: {get: {responses: {"200": {description: ok}}}}
          /api/users: {get: {responses: {"200": {description: ok}}}}
    """)
    s = Scanner(spec, "http://api", checks=["inventory"], exclude=["/actuator*", "/metrics"])
    paths = {tc.extra["path"] for tc in s.plan()}
    assert not {p for p in paths if p.startswith("/actuator")}
    assert "/metrics" not in paths  # documented in the spec AND excluded: never probed as "not in spec"


def test_parser_response_schema_summary_and_extension(tmp_path):
    [ep3] = OpenAPIParser().parse(_spec(tmp_path, """
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /u:
            get:
              summary: List users
              description: Admins only
              x-admin: true
              responses:
                "200":
                  description: ok
                  content:
                    application/vnd.api+json:
                      schema: {$ref: "#/components/schemas/U"}
        components:
          schemas:
            U: {type: object, properties: {name: {type: string}}}
    """))
    assert ep3.response_schema["properties"]["name"]["type"] == "string"
    assert ep3.summary == "List users Admins only" and ep3.privileged
    [ep2] = OpenAPIParser().parse(_spec(tmp_path, """
        swagger: "2.0"
        info: {title: t, version: "1"}
        paths:
          /u: {get: {responses: {"200": {description: ok, schema: {type: array, items: {type: string}}}}}}
    """))
    assert ep2.response_schema == {"type": "array", "items": {"type": "string"}}


@pytest.mark.parametrize("body,expected", [
    ({"password": True}, None),                     # bool, not a password
    ({"password": "[FILTERED]"}, None),
    ({"password": "<redacted>"}, None),
    ({"api_key": "k-123456789"}, "tentative"),      # the caller's own settings page
    ({"password": "hunter22"}, "firm"),             # never fine, even on /me
])
def test_exposure_placeholders_and_caller_scope(body, expected):
    tc = Case(method="GET", url="http://api/me", headers={}, params={}, body=None, label="x",
              check_id="data_exposure", extra={"endpoint_key": "GET /me"})
    found = [f.confidence for f in Analyzer().analyze([Result(test_case=tc, status_code=200,
                                                              response_body=json.dumps(body),
                                                              response_headers={}, elapsed_ms=1.0)])
             if f.rule_id == "APIFUZZ-EXPOSURE-001"]
    assert found == ([expected] if expected else [])


def test_open_or_composed_schema_has_no_undocumented_fields():
    doc = {"a": 1, "b": 2}
    assert _undocumented_fields(doc, {"properties": {"a": {}}, "additionalProperties": {"type": "integer"}}) == []
    assert _undocumented_fields(doc, {"properties": {"a": {}}, "allOf": [{"properties": {"b": {}}}]}) == []


async def test_exposure_reads_run_with_baselines(tmp_path, monkeypatch):
    calls: list[set[str]] = []
    s = Scanner(str(tmp_path / "x.yaml"), "http://api", checks=["data_exposure", "auth"])
    monkeypatch.setattr(s, "_parse", lambda path: [Endpoint(method="GET", path="/a", base_url="http://api")])

    async def fake_run(self, cases):
        calls.append({tc.check_id for tc in cases})
        return []
    monkeypatch.setattr("apifuzz.executor.Executor.run", fake_run)
    await s.run()
    assert calls[0] == {"baseline", "data_exposure"} and "data_exposure" not in calls[1]
