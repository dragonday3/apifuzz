from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


class CORSCheck(BaseCheck):
    check_id = "cors"
    name = "Security Misconfiguration — CORS (OWASP API8)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        url = self._build_url(endpoint)
        body = endpoint.body_schema if endpoint.body_schema else None
        test_cases = []

        for origin in EVIL_ORIGINS:
            test_cases.append(TestCase(
                method=endpoint.method,
                url=url,
                headers={"Origin": origin},
                params={},
                body=body,
                label=f"CORS: {endpoint.method} {endpoint.path} [Origin: {origin}]",
                check_id=self.check_id,
                extra={"origin": origin, "strategy": "origin_reflection"},
            ))

        # Preflight OPTIONS request
        test_cases.append(TestCase(
            method="OPTIONS",
            url=url,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": endpoint.method,
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
            params={},
            body=None,
            label=f"CORS preflight: OPTIONS {endpoint.path} [Origin: https://evil.com]",
            check_id=self.check_id,
            extra={"origin": "https://evil.com", "strategy": "preflight_probe"},
        ))

        return test_cases
