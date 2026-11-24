import base64
import hashlib
import hmac
import json

from fuzzowl.checks.auth import AuthCheck, _make_alg_none_jwt
from fuzzowl.models.endpoint import Endpoint, AuthConfig


def _hs256(secret: str, claims: dict | None = None) -> str:
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()  # noqa: E731
    h, p = b64({"alg": "HS256", "typ": "JWT"}), b64(claims or {"sub": "1"})
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig.rstrip(b'=').decode()}"


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
        import base64
        import json
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


class TestAuthCheckModes:
    def test_probes_use_apikey_header_name(self):
        auth = AuthConfig(type="apikey", token="k", header_name="X-API-Key")
        cases = AuthCheck().generate(make_endpoint(), auth)
        probes = [c for c in cases if c.extra["strategy"] != "no_auth"]
        assert probes and all(list(c.headers) == ["X-API-Key"] for c in probes)

    def test_probe_cases_bypass_configured_auth(self):
        cases = AuthCheck().generate(make_endpoint(), AuthConfig(type="bearer", token="a.b.c"))
        modes = {c.extra["strategy"]: c.auth_mode for c in cases}
        assert modes.pop("no_auth") == "none"
        assert set(modes.values()) == {"override"}

    def test_basic_invalid_probe_uses_basic_scheme(self):
        cases = AuthCheck().generate(make_endpoint(), AuthConfig(type="basic", token="u:p"))
        invalid = next(c for c in cases if c.extra["strategy"] == "invalid_token")
        assert invalid.headers["Authorization"].startswith("Basic ")


def test_public_endpoint_not_probed():
    ep = Endpoint(method="GET", path="/books", base_url="https://api.example.com", secured=False)
    assert AuthCheck().generate(ep, AuthConfig(type="bearer", token="t")) == []


class TestJWTProbes:
    def _strategies(self, token):
        ep = Endpoint(method="GET", path="/me", base_url="https://api.example.com")
        cases = AuthCheck().generate(ep, AuthConfig(type="bearer", token=token))
        return {c.extra["strategy"] for c in cases}

    def test_signature_bypass_probes_for_any_jwt(self):
        # alg:none, unverified signature and kid traversal need no key, so they fire for any JWT.
        strategies = self._strategies(_hs256("not-in-any-wordlist-xyz123"))
        assert {"jwt_alg_none", "jwt_unsigned", "jwt_kid_trav"} <= strategies

    def test_no_weak_key_probe_when_secret_uncrackable(self):
        strategies = self._strategies(_hs256("not-in-any-wordlist-xyz123"))
        assert "jwt_weak_key" not in strategies and "jwt_expired" not in strategies

    def test_weak_key_and_expired_probes_when_cracked(self):
        strategies = self._strategies(_hs256("random"))  # "random" is in the bundled wordlist
        assert {"jwt_weak_key", "jwt_expired"} <= strategies

    def test_cracked_secret_carried_on_probe(self):
        ep = Endpoint(method="GET", path="/me", base_url="https://api.example.com")
        cases = AuthCheck().generate(ep, AuthConfig(type="bearer", token=_hs256("random")))
        weak = next(c for c in cases if c.extra["strategy"] == "jwt_weak_key")
        assert weak.extra["cracked_secret"] == "random"

    def test_crack_runs_once_per_token(self, monkeypatch):
        import fuzzowl.jwt_forge as jf
        calls = []
        real = jf.crack_hs256
        monkeypatch.setattr(jf, "crack_hs256", lambda *a, **k: calls.append(1) or real(*a, **k))
        check = AuthCheck()
        auth = AuthConfig(type="bearer", token=_hs256("random"))
        for path in ("/a", "/b", "/c"):
            check.generate(Endpoint(method="GET", path=path, base_url="https://api.example.com"), auth)
        assert len(calls) == 1  # cached across endpoints

    def test_no_jwt_probes_for_non_jwt_bearer(self):
        strategies = self._strategies("opaque-token")
        assert not any(s.startswith("jwt_") for s in strategies)


def test_unknown_security_still_probed():
    ep = Endpoint(method="GET", path="/x", base_url="https://api.example.com", secured=None)
    assert AuthCheck().generate(ep, AuthConfig(type="bearer", token="t"))
