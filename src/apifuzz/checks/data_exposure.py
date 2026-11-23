from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import AuthConfig, Endpoint


class DataExposureCheck(BaseCheck):
    """Read each GET endpoint as the configured user; the analyzer looks for secrets in the response and for
    fields the spec doesn't document (OWASP API3:2023, the former "excessive data exposure")."""

    check_id = "data_exposure"
    name = "Excessive Data Exposure (OWASP API3)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if endpoint.method != "GET":
            return []
        return [TestCase(
            method="GET",
            url=self._build_url(endpoint),
            headers={},
            params={},
            body=None,
            label=f"DataExposure: GET {endpoint.path}",
            check_id=self.check_id,
            extra={"strategy": "exposure", "response_schema": endpoint.response_schema},
        )]
