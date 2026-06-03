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
        test_cases = []
        url = self._build_url(endpoint)
        body = endpoint.body_schema if endpoint.body_schema else None

        # Test 1: No auth header at all
        test_cases.append(TestCase(
            method=endpoint.method,
            url=url,
            headers={},
            params={},
            body=body,
            label=f"Auth: {endpoint.method} {endpoint.path} [no auth header]",
            check_id=self.check_id,
            extra={"strategy": "no_auth"},
        ))

        # Test 2: Invalid/garbage token
        test_cases.append(TestCase(
            method=endpoint.method,
            url=url,
            headers={"Authorization": "Bearer INVALID_TOKEN_apifuzz"},
            params={},
            body=body,
            label=f"Auth: {endpoint.method} {endpoint.path} [invalid token]",
            check_id=self.check_id,
            extra={"strategy": "invalid_token"},
        ))

        # Test 3: Empty bearer token
        test_cases.append(TestCase(
            method=endpoint.method,
            url=url,
            headers={"Authorization": "Bearer "},
            params={},
            body=body,
            label=f"Auth: {endpoint.method} {endpoint.path} [empty bearer]",
            check_id=self.check_id,
            extra={"strategy": "empty_bearer"},
        ))

        # Test 4: JWT alg:none attack (only if current auth is bearer and looks like JWT)
        if auth.type == "bearer" and auth.token.count(".") == 2:
            tampered = _make_alg_none_jwt(auth.token)
            test_cases.append(TestCase(
                method=endpoint.method,
                url=url,
                headers={"Authorization": f"Bearer {tampered}"},
                params={},
                body=body,
                label=f"Auth: {endpoint.method} {endpoint.path} [JWT alg:none]",
                check_id=self.check_id,
                extra={"strategy": "jwt_alg_none", "tampered_token": tampered},
            ))

        # Test 5: Malformed Authorization header format
        test_cases.append(TestCase(
            method=endpoint.method,
            url=url,
            headers={"Authorization": "NotBearer token123"},
            params={},
            body=body,
            label=f"Auth: {endpoint.method} {endpoint.path} [malformed auth scheme]",
            check_id=self.check_id,
            extra={"strategy": "malformed_scheme"},
        ))

        return test_cases
