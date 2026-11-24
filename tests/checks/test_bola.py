from fuzzowl.checks.bola import BOLACheck
from fuzzowl.models.endpoint import Endpoint, Parameter, ParamLocation, AuthConfig


def make_endpoint(path="/users/{userId}", method="GET", params=None, body=None):
    parameters = params or [Parameter(name="userId", location=ParamLocation.PATH, required=True, schema_type="integer")]
    return Endpoint(
        method=method,
        path=path,
        parameters=parameters,
        body_example=body or None,
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

    def test_probes_an_id_in_the_query(self):
        # GET /reports?report_id= carries the object reference in the query (crAPI held-out miss).
        ep = Endpoint(
            method="GET", path="/reports",
            parameters=[Parameter(name="report_id", location=ParamLocation.QUERY, required=True, example="7")],
            base_url="https://api.example.com", secured=True,
        )
        results = self.check.generate(ep, AuthConfig(type="bearer", token="a", second_token="b"))
        assert {tc.params["report_id"] for tc in results} >= {"0", "1", "7"}
        cross = [tc for tc in results if tc.extra.get("strategy") == "cross_user"]
        assert len(cross) == 1 and cross[0].params == {"report_id": "7"} and cross[0].auth_mode == "override"
        assert all(tc.url == "https://api.example.com/reports" for tc in results)

    def test_ignores_non_id_query_params(self):
        ep = Endpoint(
            method="GET", path="/users",
            parameters=[Parameter(name="page", location=ParamLocation.QUERY)],
            base_url="https://api.example.com",
        )
        assert self.check.generate(ep, AuthConfig()) == []

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


class TestBOLACrossUserScheme:
    def _cross(self, auth):
        from fuzzowl.checks.bola import BOLACheck
        from fuzzowl.models.endpoint import Endpoint, Parameter, ParamLocation
        ep = Endpoint(method="GET", path="/users/{userId}", base_url="https://api.example.com",
                      parameters=[Parameter(name="userId", location=ParamLocation.PATH, required=True)])
        return next(c for c in BOLACheck().generate(ep, auth) if c.extra["strategy"] == "cross_user")

    def test_apikey_second_token_uses_same_header(self):
        from fuzzowl.models.endpoint import AuthConfig
        tc = self._cross(AuthConfig(type="apikey", token="a", header_name="X-API-Key", second_token="b"))
        assert tc.headers == {"X-API-Key": "b"} and tc.auth_mode == "override"

    def test_bearer_second_token(self):
        from fuzzowl.models.endpoint import AuthConfig
        tc = self._cross(AuthConfig(type="bearer", token="a", second_token="b"))
        assert tc.headers == {"Authorization": "Bearer b"}



def test_cross_user_keeps_example_zero():
    from fuzzowl.checks.bola import BOLACheck
    from fuzzowl.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation
    ep = Endpoint(method="GET", path="/items/{itemId}", base_url="http://x",
                  parameters=[Parameter(name="itemId", location=ParamLocation.PATH, example=0)])
    tc = next(c for c in BOLACheck().generate(ep, AuthConfig(type="bearer", token="a", second_token="b"))
              if c.extra["strategy"] == "cross_user")
    assert tc.url == "http://x/items/0"


def test_build_url_does_not_clobber_longer_param_names():
    from fuzzowl.checks.base import build_url
    from fuzzowl.models.endpoint import Endpoint, Parameter, ParamLocation
    ep = Endpoint(method="GET", path="/u/:user/items/:userId", base_url="http://x", parameters=[
        Parameter(name="user", location=ParamLocation.PATH, example="bob"),
        Parameter(name="userId", location=ParamLocation.PATH, example="7")])
    assert build_url(ep) == "http://x/u/bob/items/7"



def test_secured_endpoint_probes_non_id_path_params():
    from fuzzowl.checks.bola import BOLACheck
    from fuzzowl.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation
    ep = Endpoint(method="GET", path="/books/{book_title}", base_url="http://x", secured=True,
                  parameters=[Parameter(name="book_title", location=ParamLocation.PATH, example="bookTitle77")])
    cases = BOLACheck().generate(ep, AuthConfig(type="bearer", token="a", second_token="b"))
    assert any(c.extra["strategy"] == "cross_user" and c.url == "http://x/books/bookTitle77" for c in cases)


def test_public_endpoint_not_probed():
    from fuzzowl.checks.bola import BOLACheck
    from fuzzowl.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation
    ep = Endpoint(method="GET", path="/users/{userId}", base_url="http://x", secured=False,
                  parameters=[Parameter(name="userId", location=ParamLocation.PATH)])
    assert BOLACheck().generate(ep, AuthConfig(type="bearer", token="a", second_token="b")) == []


def test_listing_read_as_second_user():
    ep = Endpoint(method="GET", path="/posts/recent", base_url="https://api.example.com",
                  parameters=[Parameter(name="limit", location=ParamLocation.QUERY)])
    [tc] = BOLACheck().generate(ep, AuthConfig(type="bearer", token="a", second_token="b"))
    assert tc.check_id == "bola_listing" and tc.method == "GET" and tc.auth_mode == "override"
    assert tc.headers == {"Authorization": "Bearer b"} and tc.url == "https://api.example.com/posts/recent"
    assert BOLACheck().generate(ep, AuthConfig(type="bearer", token="a")) == []  # no second user, no listing read
    post = Endpoint(method="POST", path="/posts", base_url="https://api.example.com")
    assert BOLACheck().generate(post, AuthConfig(type="bearer", token="a", second_token="b")) == []
