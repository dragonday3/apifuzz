import json

import pytest

from apifuzz.analyzer import Analyzer
from apifuzz.checks.data_exposure import DataExposureCheck
from apifuzz.executor import TestCase as Case
from apifuzz.executor import TestResult as Result
from apifuzz.models.endpoint import AuthConfig, Endpoint

SCHEMA = {"type": "object", "properties": {"users": {"type": "array", "items": {
    "type": "object", "properties": {"username": {"type": "string"}, "email": {"type": "string"}}}}}}


def run(body, schema=None, status=200):
    tc = Case(method="GET", url="http://api/users", headers={}, params={}, body=None, label="x",
              check_id="data_exposure", extra={"response_schema": schema or {}})
    return Analyzer().analyze([Result(test_case=tc, status_code=status, response_body=json.dumps(body),
                                      response_headers={}, elapsed_ms=1.0)])


def test_only_get_endpoints_probed():
    check = DataExposureCheck()
    assert check.generate(Endpoint(method="GET", path="/u", base_url="http://api"), AuthConfig())
    assert check.generate(Endpoint(method="POST", path="/u", base_url="http://api"), AuthConfig()) == []


def test_plaintext_passwords_flagged_and_masked_in_report():
    findings = {f.rule_id: f for f in run({"users": [{"username": "a", "email": "e", "password": "hunter22"}]},
                                          SCHEMA)}
    f = findings["APIFUZZ-EXPOSURE-001"]  # (002 also fires: password isn't in the schema either)
    assert f.confidence == "firm" and set(findings) == {"APIFUZZ-EXPOSURE-001", "APIFUZZ-EXPOSURE-002"}
    assert "users[].password" in f.evidence and "hunter22" not in f.response_sample


@pytest.mark.parametrize("body", [
    {"username": "a", "password": ""},            # empty
    {"username": "a", "password": "********"},    # masked
    {"username": "a", "password": None},          # null
    {"password_policy": "min 8 chars"},           # name merely contains "password"
    {"token_type": "bearer", "expires_in": 3600},
])
def test_not_sensitive(body):
    assert [f.rule_id for f in run(body)] == []


def test_undocumented_fields_tentative_low():
    [f] = run({"users": [{"username": "a", "email": "e", "internal_notes": "vip"}]}, SCHEMA)
    assert f.rule_id == "APIFUZZ-EXPOSURE-002" and f.confidence == "tentative"
    assert "users[].internal_notes" in f.evidence


def test_no_schema_or_open_schema_means_no_undocumented_finding():
    assert run({"anything": 1}) == []
    assert run({"anything": 1}, {"type": "object", "properties": {}, "additionalProperties": True}) == []


def test_error_responses_ignored():
    assert run({"password": "x1y2z3"}, status=403) == []


def test_resource_secret_field_is_not_exposure_but_client_secret_is():
    assert run({"book_title": "b", "owner": "alice", "secret": "my note"}) == []
    [f] = run({"app": "x", "client_secret": "s3cr3tvalue"})
    assert "client_secret" in f.evidence


@pytest.mark.parametrize("card", ["XXXXXXXXXXXX9999", "************1234", "xxxx-xxxx-xxxx-1234", "•••• 1234",
                                  "411111******1234", "***-**-6789"])
def test_masked_values_are_placeholders(card):
    assert run({"payment": {"card_number": card}}) == []


@pytest.mark.parametrize("card", ["4111111111111111", "4111 1111 1111 1111"])
def test_unmasked_card_number_still_flagged(card):
    assert [f.rule_id for f in run({"payment": {"card_number": card}})] == ["APIFUZZ-EXPOSURE-001"]


def test_pagination_envelope_and_empty_fields_not_undocumented():
    schema = {"type": "object", "properties": {"posts": SCHEMA["properties"]["users"]}}
    body = {"posts": [{"username": "a", "email": "e", "previousOwners": [], "note": None, "bio": "", "meta": {}}],
            "count": 1, "next_offset": None, "previous_offset": 0, "nextPage": "/p?2", "total": 1}
    assert run(body, schema) == []


def test_non_empty_undocumented_field_still_reported_next_to_pagination():
    schema = {"type": "object", "properties": {"posts": SCHEMA["properties"]["users"]}}
    [f] = run({"posts": [{"username": "a", "email": "e", "count": 3}], "count": 1, "debug": {"sql": "SELECT"}},
              schema)
    # pagination names are skipped only on the top-level envelope; an item's "count" is still data
    assert "debug" in f.evidence and "posts[].count" in f.evidence and "'count'" not in f.evidence
