import pytest
from apifuzz.models.endpoint import Endpoint, AuthConfig, Parameter, ParamLocation
from apifuzz.checks.ssrf import SSRFCheck, SSRF_PARAM_NAMES, SSRF_PAYLOADS


def make_endpoint(path="/search", method="GET", params=None, body_schema=None):
    return Endpoint(
        method=method,
        path=path,
        parameters=params or [],
        body_schema=body_schema or {},
        base_url="http://api.example.com",
    )


class TestSSRFCheck:
    def setup_method(self):
        self.check = SSRFCheck()
        self.auth = AuthConfig()

    def test_no_ssrf_prone_params_returns_empty(self):
        ep = make_endpoint(params=[
            Parameter(name="username", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert results == []

    def test_query_param_url_generates_payload_count_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="url", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(SSRF_PAYLOADS)

    def test_uppercase_param_name_matches_case_insensitive(self):
        ep = make_endpoint(params=[
            Parameter(name="URL", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(SSRF_PAYLOADS)

    def test_query_param_payload_in_params_dict(self):
        ep = make_endpoint(params=[
            Parameter(name="url", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        for tc in results:
            assert "url" in tc.params
            assert tc.params["url"] in SSRF_PAYLOADS

    def test_path_param_redirect_generates_cases(self):
        ep = make_endpoint(
            path="/goto/{redirect}",
            params=[
                Parameter(name="redirect", location=ParamLocation.PATH, schema_type="string"),
            ],
        )
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(SSRF_PAYLOADS)

    def test_path_param_payload_in_url(self):
        ep = make_endpoint(
            path="/goto/{redirect}",
            params=[
                Parameter(name="redirect", location=ParamLocation.PATH, schema_type="string"),
            ],
        )
        results = self.check.generate(ep, self.auth)
        for tc in results:
            assert any(payload in tc.url for payload in SSRF_PAYLOADS)

    def test_callback_param_generates_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="callback", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(SSRF_PAYLOADS)

    def test_check_id_is_ssrf_on_all_cases(self):
        ep = make_endpoint(params=[
            Parameter(name="url", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert all(tc.check_id == "ssrf" for tc in results)

    def test_extra_strategy_is_ssrf_probe(self):
        ep = make_endpoint(params=[
            Parameter(name="url", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        assert all(tc.extra["strategy"] == "ssrf_probe" for tc in results)

    def test_extra_payload_matches_ssrf_payloads(self):
        ep = make_endpoint(params=[
            Parameter(name="url", location=ParamLocation.QUERY, schema_type="string"),
        ])
        results = self.check.generate(ep, self.auth)
        for tc in results:
            assert tc.extra["payload"] in SSRF_PAYLOADS

    def test_non_ssrf_param_not_targeted(self):
        ep = make_endpoint(params=[
            Parameter(name="username", location=ParamLocation.QUERY, schema_type="string"),
            Parameter(name="page", location=ParamLocation.QUERY, schema_type="integer"),
        ])
        results = self.check.generate(ep, self.auth)
        assert results == []

    def test_body_param_named_url_generates_cases(self):
        ep = make_endpoint(
            method="POST",
            params=[
                Parameter(name="url", location=ParamLocation.BODY, schema_type="string"),
            ],
            body_schema={"url": "http://example.com"},
        )
        results = self.check.generate(ep, self.auth)
        assert len(results) == len(SSRF_PAYLOADS)
        for tc in results:
            assert tc.body["url"] in SSRF_PAYLOADS
