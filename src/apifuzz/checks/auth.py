import base64
import json

from apifuzz import jwt_forge
from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig


def _make_alg_none_jwt(original_token: str) -> str:
    """Take a JWT and return a version with alg:none and empty signature."""
    parts = original_token.split(".")
    if len(parts) != 3:
        return original_token
    try:
        header = json.dumps({"alg": "none", "typ": "JWT"})
        new_header = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
        return f"{new_header}.{parts[1]}."  # empty signature
    except Exception:
        return original_token


class AuthCheck(BaseCheck):
    check_id = "auth"
    name = "Broken Authentication (OWASP API2)"

    def __init__(self) -> None:
        # Offline HS256 crack is the same for every endpoint; do it once per scan per token.
        self._crack_cache: dict[str, str | None] = {}

    def _cracked_secret(self, token: str) -> str | None:
        if token not in self._crack_cache:
            self._crack_cache[token] = jwt_forge.crack_hs256(token, jwt_forge.load_default_wordlist())
        return self._crack_cache[token]

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if endpoint.secured is False:  # public by design in the spec: nothing to bypass
            return []
        url = self._build_url(endpoint)
        body = endpoint.body_example
        # Probe the header the API actually authenticates with (apikey may use a custom header).
        hdr = auth.header_name if auth.type == "apikey" else "Authorization"

        def case(desc: str, strategy: str, headers: dict[str, str], **extra: str) -> TestCase:
            return TestCase(
                method=endpoint.method,
                url=url,
                headers=headers,
                params={},
                body=body,
                label=f"Auth: {endpoint.method} {endpoint.path} [{desc}]",
                check_id=self.check_id,
                extra={"strategy": strategy, **extra},
                # These headers ARE the test: never let the executor replace them with the real token.
                auth_mode="none" if strategy == "no_auth" else "override",
            )

        test_cases = [case("no auth header", "no_auth", {})]

        if auth.type == "apikey":
            test_cases.append(case("invalid token", "invalid_token", {hdr: "INVALID_TOKEN_apifuzz"}))
            test_cases.append(case("empty api key", "empty_apikey", {hdr: ""}))
            return test_cases  # no auth scheme to tamper with

        if auth.type == "basic":
            bad = base64.b64encode(b"apifuzz:invalid").decode()
            test_cases.append(case("invalid token", "invalid_token", {hdr: f"Basic {bad}"}))
        else:
            test_cases.append(case("invalid token", "invalid_token", {hdr: "Bearer INVALID_TOKEN_apifuzz"}))
        # "Bearer" with no token: a trailing space ("Bearer ") is an illegal header value that httpx
        # refuses to send, so v0.1.0 never actually sent this probe.
        test_cases.append(case("empty bearer", "empty_bearer", {hdr: "Bearer"}))

        # JWT attacks (OWASP API2): only when the configured credential is a bearer JWT.
        if auth.type == "bearer" and jwt_forge.is_jwt(auth.token):
            token = auth.token
            bearer = lambda t: {hdr: f"Bearer {t}"}  # noqa: E731
            # Signature-bypass forgeries (no key needed): accepted => the server trusts an unverified token.
            test_cases.append(case("JWT alg:none", "jwt_alg_none", bearer(_make_alg_none_jwt(token))))
            test_cases.append(case("JWT unverified signature", "jwt_unsigned",
                                    bearer(jwt_forge.forge_unsigned(token))))
            test_cases.append(case("JWT kid path traversal", "jwt_kid_trav",
                                    bearer(jwt_forge.forge_kid_traversal(token))))
            # Weak HS256 secret cracked offline (zero requests). If found, prove it by minting tokens.
            secret = self._cracked_secret(token)
            if secret is not None:
                test_cases.append(case("JWT weak HS256 key", "jwt_weak_key",
                                        bearer(jwt_forge.resign_hs256(token, secret)),
                                        cracked_secret=secret))
                test_cases.append(case("JWT expired token", "jwt_expired",
                                        bearer(jwt_forge.resign_hs256(token, secret, expired=True)),
                                        cracked_secret=secret))

        test_cases.append(case("malformed auth scheme", "malformed_scheme", {hdr: "NotBearer token123"}))
        return test_cases
