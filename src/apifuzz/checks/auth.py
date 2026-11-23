import base64
import json
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

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
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
            test_cases.append(case("empty api key", "empty_bearer", {hdr: ""}))
            return test_cases  # no auth scheme to tamper with

        if auth.type == "basic":
            bad = base64.b64encode(b"apifuzz:invalid").decode()
            test_cases.append(case("invalid token", "invalid_token", {hdr: f"Basic {bad}"}))
        else:
            test_cases.append(case("invalid token", "invalid_token", {hdr: "Bearer INVALID_TOKEN_apifuzz"}))
        test_cases.append(case("empty bearer", "empty_bearer", {hdr: "Bearer "}))

        # JWT alg:none attack (only if current auth is bearer and looks like JWT)
        if auth.type == "bearer" and auth.token.count(".") == 2:
            tampered = _make_alg_none_jwt(auth.token)
            test_cases.append(case("JWT alg:none", "jwt_alg_none", {hdr: f"Bearer {tampered}"},
                                   tampered_token=tampered))

        test_cases.append(case("malformed auth scheme", "malformed_scheme", {hdr: "NotBearer token123"}))
        return test_cases
