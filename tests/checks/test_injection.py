from apifuzz.models.endpoint import Endpoint, AuthConfig, Parameter, ParamLocation
from apifuzz.checks.injection import InjectionCheck, INJECTION_PAYLOADS


def make_endpoint(path="/search", method="GET", params=None, body_schema=None):
    return Endpoint(
        method=method,
        path=path,
        parameters=params or [],
        body_example=body_schema or None,
        base_url="http://api.example.com",
    )


class TestInjectionCheck:
    def setup_method(self):
        self.check = InjectionCheck()
        self.auth = AuthConfig()

    def test_no_string_params_no_body_returns_empty(self):
        ep = make_endpoint(params=[
            Parameter(name="count", location=ParamLocation.QUERY, schema_type="integer"),
        ])
        results = self.check.generate(ep, self.auth)
        assert results == []

    def test_single_string_query_param_generates_payload_count_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(INJECTION_PAYLOADS) + 4 + 2  # + SQLi control/true/false/control again + NoSQLi pair

    def test_integer_param_not_targeted(self):
        ep = make_endpoint(params=[
            Parameter(name="page", location=ParamLocation.QUERY, schema_type="integer"),
        ])
        results = self.check.generate(ep, self.auth)
        assert results == []

    def test_query_param_payload_in_params_dict(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        probes = [tc for tc in results if tc.extra["strategy"] == "injection_probe"]
        for tc in probes:
            assert tc.params["q"] in [p["payload"] for p in INJECTION_PAYLOADS]
        pair = [tc.params for tc in results if tc.extra["strategy"] == "nosqli_pair"]
        assert pair == [{"q[$ne]": "apifuzz-nonexistent"}, {"q[$eq]": "apifuzz-nonexistent"}]

    def test_path_param_generates_cases_with_path_override(self):
        ep = make_endpoint(
            path="/users/{name}",
            params=[
                Parameter(name="name", location=ParamLocation.PATH, schema_type="string"),
            ],
        )
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(INJECTION_PAYLOADS) + 4  # + SQLi control/true/false/control again
        for tc in results:
            assert "{name}" not in tc.url

    def test_check_id_is_injection_on_all_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert all(tc.check_id == "injection" for tc in results)

    def test_extra_injection_type_valid_values(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        valid_types = {"sqli", "ssti", "nosqli", "cmd_injection", "xss"}
        for tc in results:
            assert tc.extra["injection_type"] in valid_types

    def test_body_schema_generates_body_injection_cases(self):
        ep = make_endpoint(
            method="POST",
            body_schema={"username": "alice", "email": "alice@example.com"},
        )
        results = self.check.generate(ep, self.auth)
        assert len(results) == 2 * (len(INJECTION_PAYLOADS) + 4 + 2)  # per field: payloads, SQLi quad, NoSQLi pair

    def test_body_injection_one_field_at_a_time(self):
        example = {"username": "alice", "email": "alice@example.com", "age": 30}
        ep = make_endpoint(method="POST", body_schema=example)
        results = [tc for tc in self.check.generate(ep, self.auth) if tc.extra["strategy"] == "injection_probe"]
        for tc in results:
            field = tc.extra["param_name"]
            assert tc.body[field] == tc.extra["payload"]
            assert {k: v for k, v in tc.body.items() if k != field} == {
                k: v for k, v in example.items() if k != field}
        assert {tc.extra["param_name"] for tc in results} == {"username", "email"}  # non-strings skipped

    def test_sqli_payload_appears_in_test_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        payloads = [tc.params.get("q", "") for tc in results]
        assert "' OR '1'='1" in payloads

    def test_ssti_payload_appears_in_test_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        payloads = [tc.params.get("q", "") for tc in results]
        assert "{{1337*7331}}" in payloads and "${1337*7331}" in payloads

    def test_labels_contain_injection_type(self):
        ep = make_endpoint(params=[
            Parameter(name="q", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        for tc in results:
            injection_type = tc.extra["injection_type"]
            assert injection_type in tc.label

    def test_body_injection_extra_has_target_body(self):
        ep = make_endpoint(
            method="POST",
            body_schema={"field": "value"},
        )
        results = self.check.generate(ep, self.auth)
        for tc in results:
            assert tc.extra.get("target") == "body"
            assert tc.extra["strategy"] in ("injection_probe", "nosqli_pair", "sqli_bool")

    def test_body_nosqli_pair_uses_operator_objects(self):
        ep = make_endpoint(method="POST", body_schema={"user": "a", "n": 1})
        pair = [tc.body for tc in self.check.generate(ep, self.auth) if tc.extra["strategy"] == "nosqli_pair"]
        assert pair == [{"user": {"$ne": None}, "n": 1}, {"user": {"$eq": "apifuzz-nonexistent"}, "n": 1}]

    def test_quote_breaker_sqli_payload_present(self):
        # VAmPI: "' OR '1'='1" is valid SQL there (200, no error); a lone quote raises the DB error.
        assert {"payload": "'", "type": "sqli"} in INJECTION_PAYLOADS


class TestBlindSQLiProbes:
    def _ep(self, method="GET"):
        return make_endpoint(path="/users/{name}", method=method, params=[
            Parameter(name="name", location=ParamLocation.PATH, schema_type="string", example="bob")])

    def test_boolean_triple_appends_to_original_value(self):
        cases = [c for c in InjectionCheck().generate(self._ep(), AuthConfig()) if c.extra["strategy"] == "sqli_bool"]
        # The control is repeated after the pair, in this order (the serial pass keeps it).
        assert [(c.extra["polarity"], c.extra["payload"]) for c in cases] == [
            ("control", "bob"), ("true", "bob' AND '1'='1"), ("false", "bob' AND '1'='2"), ("control_again", "bob")]

    def test_time_probes_only_when_enabled(self):
        check = InjectionCheck()
        assert not [c for c in check.generate(self._ep(), AuthConfig()) if c.extra["strategy"] == "sqli_time"]
        check.time_based = True
        timed = [c for c in check.generate(self._ep(), AuthConfig()) if c.extra["strategy"] == "sqli_time"]
        assert len(timed) == 3 * 3 and all(c.extra["control_id"] for c in timed)

    def test_no_value_probes_on_delete(self):
        cases = InjectionCheck().generate(self._ep("DELETE"), AuthConfig())
        assert not [c for c in cases if c.extra["strategy"] in ("sqli_bool", "sqli_time")]
