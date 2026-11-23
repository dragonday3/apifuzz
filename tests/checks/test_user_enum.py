import pytest

from apifuzz.analyzer import Analyzer
from apifuzz.checks.user_enum import WRONG_PASSWORD, UserEnumCheck
from apifuzz.executor import TestResult as Result
from apifuzz.models.endpoint import AuthConfig, Endpoint

LOGIN = Endpoint(method="POST", path="/auth/login", base_url="http://api",
                 body_example={"username": "alice", "password": "pw"})


def test_probes_known_and_two_random_unknown_users_with_wrong_password():
    cases = UserEnumCheck().generate(LOGIN, AuthConfig())
    users = [c.body["username"] for c in cases]
    assert users[0] == "alice" and len(set(users)) == 3
    assert {c.body["password"] for c in cases} == {WRONG_PASSWORD}
    assert all(c.auth_mode == "none" for c in cases)
    again = [c.body["username"] for c in UserEnumCheck().generate(LOGIN, AuthConfig())]
    assert set(again[1:]).isdisjoint(users[1:])  # never reuse a name a previous run might have registered


@pytest.mark.parametrize("ep", [
    Endpoint(method="POST", path="/users/register", base_url="http://api",
             body_example={"username": "a", "password": "b"}),                      # signup, not login
    Endpoint(method="GET", path="/login", base_url="http://api"),
    Endpoint(method="POST", path="/login", base_url="http://api", body_example={"q": "x"}),
])
def test_only_login_operations(ep):
    assert UserEnumCheck().generate(ep, AuthConfig()) == []


def analyze(known, u1, u2):
    cases = UserEnumCheck().generate(LOGIN, AuthConfig())
    results = [Result(test_case=c, status_code=s, response_body=b.replace("{u}", c.body["username"]),
                      response_headers={}, elapsed_ms=1.0) for c, (s, b) in zip(cases, (known, u1, u2))]
    return Analyzer().analyze(results)


def test_different_answers_flagged():
    [f] = analyze((401, '{"m": "wrong password"}'), (401, '{"m": "no such user"}'), (401, '{"m": "no such user"}'))
    assert f.rule_id == "APIFUZZ-ENUM-001" and f.confidence == "firm"


def test_same_answer_not_flagged_even_with_username_echo():
    same = (401, '{"m": "bad credentials for {u}"}')
    assert analyze(same, same, same) == []


def test_noisy_responses_not_flagged():
    assert analyze((401, '{"id": 1}'), (401, '{"id": 2}'), (401, '{"id": 3}')) == []


def test_rate_limited_not_flagged():
    assert analyze((401, "wrong password"), (429, "slow"), (429, "slow")) == []
