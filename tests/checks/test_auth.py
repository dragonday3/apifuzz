import pytest
from apifuzz.checks.auth import AuthCheck, _make_alg_none_jwt
from apifuzz.models.endpoint import Endpoint, AuthConfig


def make_endpoint(method="GET", path="/users"):
    return Endpoint(method=method, path=path, base_url="https://api.example.com")


class TestAuthCheck:
    def setup_method(self):
        self.check = AuthCheck()

    def test_check_id(self):
        assert self.check.check_id == "auth"

    def test_generates_at_least_3_cases(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        assert len(results) >= 3

    def test_no_auth_case_present(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        no_auth = [r for r in results if r.extra.get("strategy") == "no_auth"]
        assert len(no_auth) == 1
        assert "Authorization" not in no_auth[0].headers

    def test_invalid_token_case_present(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        invalid = [r for r in results if r.extra.get("strategy") == "invalid_token"]
        assert len(invalid) == 1
        assert "INVALID_TOKEN" in invalid[0].headers["Authorization"]

    def test_all_cases_have_correct_check_id(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        assert all(r.check_id == "auth" for r in results)

    def test_jwt_alg_none_generated_for_bearer_jwt(self):
        ep = make_endpoint()
        # minimal valid JWT structure (3 dot-separated parts)
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
        auth = AuthConfig(type="bearer", token=fake_jwt)
        results = self.check.generate(ep, auth)
        alg_none = [r for r in results if r.extra.get("strategy") == "jwt_alg_none"]
        assert len(alg_none) == 1
        # tampered token should have empty signature (ends with ".")
        assert alg_none[0].headers["Authorization"].endswith(".")

    def test_jwt_alg_none_not_generated_for_non_jwt(self):
        ep = make_endpoint()
        auth = AuthConfig(type="bearer", token="not-a-jwt")
        results = self.check.generate(ep, auth)
        alg_none = [r for r in results if r.extra.get("strategy") == "jwt_alg_none"]
        assert len(alg_none) == 0

    def test_jwt_alg_none_not_generated_for_non_bearer(self):
        ep = make_endpoint()
        auth = AuthConfig(type="apikey", token="key123")
        results = self.check.generate(ep, auth)
        alg_none = [r for r in results if r.extra.get("strategy") == "jwt_alg_none"]
        assert len(alg_none) == 0

    def test_url_correct(self):
        ep = make_endpoint()
        results = self.check.generate(ep, AuthConfig())
        for r in results:
            assert r.url == "https://api.example.com/users"

    def test_method_preserved(self):
        ep = make_endpoint(method="POST", path="/login")
        results = self.check.generate(ep, AuthConfig())
        assert all(r.method == "POST" for r in results)


class TestMakeAlgNoneJWT:
    def test_replaces_alg_with_none(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = _make_alg_none_jwt(token)
        parts = result.split(".")
        import base64, json
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "none"

    def test_empty_signature(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = _make_alg_none_jwt(token)
        assert result.endswith(".")

    def test_invalid_token_returned_unchanged(self):
        token = "notajwt"
        result = _make_alg_none_jwt(token)
        assert result == token
