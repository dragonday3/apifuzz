import pytest
from apifuzz.checks.rate_limit import RateLimitCheck, BURST_COUNT
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
    return RateLimitCheck()


@pytest.fixture
def auth():
    return AuthConfig()


class TestRateLimitCheck:
    def test_generates_burst_count_test_cases(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        assert len(cases) == BURST_COUNT

    def test_burst_count_is_50(self):
        assert BURST_COUNT == 50

    def test_all_cases_same_method(self, check, auth):
        ep = make_endpoint(method="POST")
        cases = check.generate(ep, auth)
        assert all(tc.method == "POST" for tc in cases)

    def test_all_cases_same_url(self, check, auth):
        ep = make_endpoint(path="/users")
        cases = check.generate(ep, auth)
        expected_url = "http://api.example.com/users"
        assert all(tc.url == expected_url for tc in cases)

    def test_check_id_is_rate_limit(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        assert all(tc.check_id == "rate_limit" for tc in cases)

    def test_burst_index_sequential(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        indices = [tc.extra["burst_index"] for tc in cases]
        assert indices == list(range(BURST_COUNT))

    def test_burst_total_in_extra(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        assert all(tc.extra["burst_total"] == BURST_COUNT for tc in cases)

    def test_strategy_is_burst(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        assert all(tc.extra["strategy"] == "burst" for tc in cases)

    def test_body_passed_through(self, check, auth):
        ep = make_endpoint(body_schema={"name": "test"})
        cases = check.generate(ep, auth)
        assert all(tc.body == {"name": "test"} for tc in cases)

    def test_no_body_schema_body_is_none(self, check, auth):
        ep = make_endpoint(body_schema={})
        cases = check.generate(ep, auth)
        assert all(tc.body is None for tc in cases)

    def test_labels_contain_burst_index(self, check, auth):
        ep = make_endpoint()
        cases = check.generate(ep, auth)
        assert "#1" in cases[0].label
        assert "#50" in cases[-1].label
