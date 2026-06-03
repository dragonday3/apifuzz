from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig

PRIVILEGED_FIELDS = {
    "isAdmin": True,
    "role": "admin",
    "is_verified": True,
    "credits": 99999,
    "balance": 99999.99,
    "permissions": ["read", "write", "admin"],
}


class MassAssignmentCheck(BaseCheck):
    check_id = "mass_assignment"
    name = "Mass Assignment (OWASP API6)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if not endpoint.body_schema:
            return []

        url = self._build_url(endpoint)
        body = {**endpoint.body_schema, **PRIVILEGED_FIELDS}

        return [TestCase(
            method=endpoint.method,
            url=url,
            headers={},
            params={},
            body=body,
            label=f"MassAssignment: {endpoint.method} {endpoint.path}",
            check_id=self.check_id,
            extra={
                "injected_fields": list(PRIVILEGED_FIELDS.keys()),
                "strategy": "privileged_field_injection",
            },
        )]
