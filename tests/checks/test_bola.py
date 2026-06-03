import pytest
from apifuzz.checks.bola import BOLACheck
from apifuzz.models.endpoint import Endpoint, Parameter, ParamLocation, AuthConfig


def make_endpoint(path="/users/{userId}", method="GET", params=None, body=None):
    parameters = params or [Parameter(name="userId", location=ParamLocation.PATH, required=True, schema_type="integer")]
    return Endpoint(
        method=method,
        path=path,
        parameters=parameters,
        body_schema=body or {},
        base_url="https://api.example.com",
    )


class TestBOLACheck:
    def setup_method(self):
        self.check = BOLACheck()

    def test_check_id(self):
        assert self.check.check_id == "bola"

    def test_returns_empty_for_no_id_params(self):
        ep = Endpoint(method="GET", path="/users", parameters=[], base_url="https://api.example.com")
        results = self.check.generate(ep, AuthConfig())
        assert results == []

    def test_returns_empty_for_query_param_only(self):
        ep = Endpoint(
            method="GET", path="/users",
            parameters=[Parameter(name="userId", location=ParamLocation.QUERY)],
            base_url="https://api.example.com",
        )
        results = self.check.generate(ep, AuthConfig())
        assert results == []

    def test_generates_test_cases_for_path_id_param(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        assert len(results) > 0

    def test_all_cases_have_correct_check_id(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        assert all(r.check_id == "bola" for r in results)

    def test_url_contains_probe_id(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        urls = [r.url for r in results]
        assert any("0" in url or "1" in url or "999999" in url for url in urls)

    def test_url_replaces_param_placeholder(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        for r in results:
            assert "{userId}" not in r.url

    def test_no_cross_user_case_without_second_token(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig(type="bearer", token="tok-a"))
        cross_user = [r for r in results if r.extra.get("strategy") == "cross_user"]
        assert len(cross_user) == 0

    def test_cross_user_case_with_second_token(self):
        ep = make_endpoint()
        auth = AuthConfig(type="bearer", token="tok-a", second_token="tok-b")
        results = self.check.generate(ep, auth)
        cross_user = [r for r in results if r.extra.get("strategy") == "cross_user"]
        assert len(cross_user) == 1
        assert "tok-b" in cross_user[0].headers.get("Authorization", "")

    def test_extra_metadata_present(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        for r in results:
            assert "param_name" in r.extra
            assert "strategy" in r.extra

    def test_non_id_path_param_ignored(self):
        ep = Endpoint(
            method="GET", path="/users/{username}",
            parameters=[Parameter(name="username", location=ParamLocation.PATH, required=True)],
            base_url="https://api.example.com",
        )
        results = self.check.generate(ep, AuthConfig())
        assert results == []

    def test_uuid_param_detected(self):
        ep = Endpoint(
            method="GET", path="/items/{itemUUID}",
            parameters=[Parameter(name="itemUUID", location=ParamLocation.PATH, required=True)],
            base_url="https://api.example.com",
        )
        results = self.check.generate(ep, AuthConfig())
        assert len(results) > 0
