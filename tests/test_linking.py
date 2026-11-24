"""Phase 6.2: resource linking (sibling GET for a created object), its mass-assignment confirmation and
cross-user BOLA reads of objects user A created during the scan."""
import re

from fuzzowl.analyzer import Analyzer, _link
from fuzzowl.executor import TestCase, TestResult
from fuzzowl.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation


def ep(method, path, secured=None, **examples):
    params = [Parameter(name=n, location=ParamLocation.PATH, example=examples.get(n))
              for n in re.findall(r"\{([^}]+)\}", path)]
    return Endpoint(method=method, path=path, parameters=params, base_url="http://api", secured=secured)


def tc(check_id, method="GET", url="http://api/x", body=None, extra=None):
    return TestCase(method=method, url=url, headers={}, params={}, body=body, label=check_id,
                    check_id=check_id, extra=extra or {})


def res(case, status=200, body=""):
    return TestResult(test_case=case, status_code=status, response_body=body, response_headers={}, elapsed_ms=5.0)


class TestLink:
    def test_request_field_matches_path_param(self):
        gets = [ep("GET", "/users/v1/{username}"), ep("GET", "/books/v1/{username}")]
        e, url = _link(gets, "/users/v1/register", {"username": "a b/c", "password": "x"}, '{"message": "ok"}')
        assert e.path == "/users/v1/{username}" and url == "http://api/users/v1/a%20b%2Fc"

    def test_response_field_wins_over_request(self):
        _, url = _link([ep("GET", "/users/{name}")], "/users", {"name": "sent"}, '{"data": {"name": "stored"}}')
        assert url == "http://api/users/stored"

    def test_resource_id_param_takes_response_id(self):
        _, url = _link([ep("GET", "/orders/{order_id}")], "/orders", {"item": 1}, '{"id": 42}')
        assert url == "http://api/orders/42"

    def test_no_match(self):
        assert _link([ep("GET", "/orders/{order_id}")], "/orders", {}, '{"message": "ok"}') is None  # no value
        assert _link([ep("GET", "/carts/{id}")], "/orders", {}, '{"id": 4}') is None  # other collection
        assert _link([ep("GET", "/{id}")], "/orders", {}, '{"id": 4}') is None  # no parent
        assert _link([ep("GET", "/orders/{id}/items")], "/orders", {}, '{"id": 4}') is None  # not an item path
        assert _link([ep("GET", "/users/{active}")], "/users", {"active": True}, "{}") is None  # bool isn't an id

    def test_ambiguous_is_deterministic(self):
        gets = [ep("GET", "/users/{username}"), ep("GET", "/users/{email}")]
        body = {"username": "u", "email": "e@x"}
        assert _link(gets, "/users", body, "{}")[1] == "http://api/users/e%40x"  # same rank: alphabetical
        assert _link(gets[::-1], "/users", body, "{}")[1] == "http://api/users/e%40x"

    def test_longest_parent_wins(self):
        gets = [ep("GET", "/api/{id}"), ep("GET", "/api/orders/{id}")]
        assert _link(gets, "/api/orders", {}, '{"id": 7}')[1] == "http://api/api/orders/7"

    def test_multiple_params_parent_keeps_creating_paths_values(self):
        gets = [ep("GET", "/users/{uid}/orders/{orderId}", uid=5)]
        assert _link(gets, "/users/{uid}/orders", {}, '{"id": 9}')[1] == "http://api/users/5/orders/9"


class TestLinkedMassAssignment:
    VALUES = {"role": "admin", "isAdmin": True}

    def _analyzer(self):
        a = Analyzer()
        a.endpoints = [ep("POST", "/users/v1/register"), ep("GET", "/users/v1/{username}")]
        return a

    def _probe(self, body='{"message": "registered"}'):
        case = tc("mass_assignment", "POST", "http://api/users/v1/register", body={"username": "u1", **self.VALUES},
                  extra={"injected_values": self.VALUES, "endpoint_key": "POST /users/v1/register"})
        return res(case, 200, body)

    def test_sibling_get_followup(self):
        [v] = self._analyzer().followups([self._probe()])
        assert v.method == "GET" and v.url == "http://api/users/v1/u1"
        assert v.extra["baseline_key"] == "GET /users/v1/{username}"

    def test_stored_values_are_firm(self):
        a, probe = self._analyzer(), self._probe()
        [v] = a.followups([probe])
        [f] = a.analyze([probe, res(v, 200, '{"username": "u1", "role": "admin"}')])
        assert f.confidence == "firm" and "'role'" in f.evidence and f.endpoint == "POST /users/v1/register"

    def test_not_stored_stays_tentative(self):
        a, probe = self._analyzer(), self._probe(body='{"username": "u1", "role": "admin"}')  # echoed only
        [v] = a.followups([probe])
        [f] = a.analyze([probe, res(v, 200, '{"username": "u1", "role": "user"}')])
        assert f.confidence == "tentative"

    def test_value_every_user_has_is_not_proof(self):
        a, probe = self._analyzer(), self._probe()
        [v] = a.followups([probe])
        sibling_base = res(tc("baseline", url="http://api/users/v1/1",
                              extra={"endpoint_key": "GET /users/v1/{username}"}),
                           200, '{"username": "1", "role": "admin"}')
        assert a.analyze([sibling_base, probe, res(v, 200, '{"username": "u1", "role": "admin"}')]) == []


class TestCreatedObjectBOLA:
    OBJ = '{"id": 3, "name": "rex", "owner": "alice"}'

    def _analyzer(self, create_secured=None, get_secured=None):
        a = Analyzer()
        a.bola_auth = AuthConfig(type="bearer", token="ta", second_token="tb")
        a.endpoints = [ep("POST", "/pets", secured=create_secured), ep("GET", "/pets/{petId}", secured=get_secured)]
        return a

    def _created(self):
        return res(tc("baseline", "POST", "http://api/pets", body={"name": "rex"},
                      extra={"endpoint_key": "POST /pets"}), 201, self.OBJ)

    def _verdict(self, owner, other):
        a = self._analyzer()
        owner_tc, other_tc = a.followups([self._created()])
        return a.analyze([res(owner_tc, *owner), res(other_tc, *other)])

    def test_followups_owner_read_and_second_token_read(self):
        owner, other = self._analyzer().followups([self._created()])
        assert owner.url == other.url == "http://api/pets/3"
        assert owner.check_id == "bola_owner" and owner.auth_mode == "default"
        assert other.auth_mode == "override" and other.headers == {"Authorization": "Bearer tb"}

    def test_b_gets_a_object_is_firm(self):
        [f] = self._verdict((200, self.OBJ), (200, self.OBJ))
        assert f.rule_id == "FUZZOWL-BOLA-001" and f.confidence == "firm" and f.endpoint == "GET /pets/{petId}"

    def test_b_denied_or_other_object_or_owner_failed_no_finding(self):
        assert self._verdict((200, self.OBJ), (403, '{"error": "forbidden"}')) == []
        assert self._verdict((200, self.OBJ), (200, '{"id": 4, "owner": "bob"}')) == []
        assert self._verdict((404, '{"error": "nf"}'), (200, self.OBJ)) == []
        assert self._verdict((200, ""), (200, "")) == []  # empty bodies prove nothing

    def test_no_followups_without_second_token_or_for_public_ops(self):
        a = self._analyzer()
        a.bola_auth = None
        assert a.followups([self._created()]) == []
        assert self._analyzer(create_secured=False).followups([self._created()]) == []
        assert self._analyzer(get_secured=False).followups([self._created()]) == []
