import pytest
from apifuzz.checks.cors import CORSCheck, EVIL_ORIGINS
from apifuzz.models.endpoint import Endpoint, AuthConfig


def make_endpoint(method="GET", path="/items", body_schema=None):
    return Endpoint(
        method=method,
        path=path,
        base_url="http://api.example.com",
        body_schema=body_schema or {},
    )


@pytest.fixture
def check():
    return CORSCheck()


@pytest.fixture
def auth():
    return AuthConfig()


class TestCORSCheck:
    def test_generates_evil_origins_plus_preflight(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        # len(EVIL_ORIGINS) origin tests + 1 preflight
        assert len(cases) == len(EVIL_ORIGINS) + 1

    def test_origin_headers_set_on_cases(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        # non-preflight cases have Origin header
        origin_cases = [tc for tc in cases if tc.extra.get("strategy") == "origin_reflection"]
        assert all("Origin" in tc.headers for tc in origin_cases)

    def test_evil_com_origin_present(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        origins_used = [tc.headers.get("Origin") for tc in cases if "Origin" in tc.headers]
        assert "https://evil.com" in origins_used

    def test_null_origin_present(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        origins_used = [tc.headers.get("Origin") for tc in cases]
        assert "null" in origins_used

    def test_preflight_uses_options_method(self, check, auth):
        ep = make_endpoint(method="POST")
        cases = check.generate(ep, auth)
        preflight = [tc for tc in cases if tc.extra.get("strategy") == "preflight_probe"]
        assert len(preflight) == 1
        assert preflight[0].method == "OPTIONS"

    def test_preflight_has_acr_method_header(self, check, auth):
        ep = make_endpoint(method="DELETE")
        cases = check.generate(ep, auth)
        preflight = [tc for tc in cases if tc.extra.get("strategy") == "preflight_probe"][0]
        assert preflight.headers["Access-Control-Request-Method"] == "DELETE"

    def test_check_id_is_cors(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        assert all(tc.check_id == "cors" for tc in cases)

    def test_origin_reflection_strategy_on_non_preflight(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        origin_cases = [tc for tc in cases if tc.extra.get("strategy") == "origin_reflection"]
        assert len(origin_cases) == len(EVIL_ORIGINS)

    def test_url_built_correctly(self, check, auth):
        ep = make_endpoint(path="/api/v1/resource")
        cases = check.generate(ep, auth)
        assert all(tc.url == "http://api.example.com/api/v1/resource" for tc in cases)

    def test_preflight_body_is_none(self, check, auth):
        ep = make_endpoint(body_schema={"field": "value"})
        cases = check.generate(ep, auth)
        preflight = [tc for tc in cases if tc.extra.get("strategy") == "preflight_probe"][0]
        assert preflight.body is None

    def test_extra_origin_matches_header(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        for tc in cases:
            if "Origin" in tc.headers:
                assert tc.extra["origin"] == tc.headers["Origin"]
