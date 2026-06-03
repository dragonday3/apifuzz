from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig

BURST_COUNT = 50


class RateLimitCheck(BaseCheck):
    check_id = "rate_limit"
    name = "Unrestricted Resource Consumption (OWASP API4)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        url = self._build_url(endpoint)
        body = endpoint.body_schema if endpoint.body_schema else None

        return [
            TestCase(
                method=endpoint.method,
                url=url,
                headers={},
                params={},
                body=body,
                label=f"RateLimit burst #{i+1}: {endpoint.method} {endpoint.path}",
                check_id=self.check_id,
                extra={"burst_index": i, "burst_total": BURST_COUNT, "strategy": "burst"},
            )
            for i in range(BURST_COUNT)
        ]
