import pytest
from apifuzz.models.endpoint import Endpoint, AuthConfig, Parameter, ParamLocation
from apifuzz.checks.injection import InjectionCheck, INJECTION_PAYLOADS


def make_endpoint(path="/search", method="GET", params=None, body_schema=None):
    return Endpoint(
        method=method,
        path=path,
        parameters=params or [],
        body_schema=body_schema or {},
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
        assert len(results) == len(INJECTION_PAYLOADS)

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
        for tc in results:
            assert "q" in tc.params
            assert tc.params["q"] in [p["payload"] for p in INJECTION_PAYLOADS]

    def test_path_param_generates_cases_with_path_override(self):
        ep = make_endpoint(
            path="/users/{name}",
            params=[
                Parameter(name="name", location=ParamLocation.PATH, schema_type="string"),
            ],
        )
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(INJECTION_PAYLOADS)
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
        assert len(results) == len(INJECTION_PAYLOADS)

    def test_body_injection_all_keys_set_to_payload(self):
        ep = make_endpoint(
            method="POST",
            body_schema={"username": "alice", "email": "alice@example.com"},
        )
        results = self.check.generate(ep, self.auth)
        for tc in results:
            payload = tc.extra["payload"]
            assert tc.body["username"] == payload
            assert tc.body["email"] == payload

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
        assert "{{7*7}}" in payloads

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
            assert tc.extra["strategy"] == "injection_probe"
