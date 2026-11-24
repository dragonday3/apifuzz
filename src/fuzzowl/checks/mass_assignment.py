import re
import secrets
from typing import Any

from fuzzowl.checks.base import BaseCheck
from fuzzowl.executor import TestCase
from fuzzowl.models.endpoint import Endpoint, AuthConfig

PRIVILEGED_FIELDS = {
    "admin": True,
    "is_admin": True,
    "isAdmin": True,
    "role": "admin",
    "is_verified": True,
    "credits": 99999,
    "balance": 99999.99,
    "permissions": ["read", "write", "admin"],
}

# Body fields an API typically keeps unique (one account per username/email).
_UNIQUE_FIELD = re.compile(r"(user_?name|login|e_?mail|nick_?name|handle|slug)$", re.IGNORECASE)


def unique_values(body: dict[str, Any]) -> dict[str, Any]:
    """The body with unique-looking top-level string fields made unique (a random suffix; an email keeps its
    domain). The POST baseline already created the spec's example record, and an API enforcing uniqueness
    rejects the same username twice, so the probe would never reach the code that binds the extra fields."""
    tag = secrets.token_hex(3)
    out = dict(body)
    for k, v in body.items():
        if isinstance(v, str) and _UNIQUE_FIELD.search(k):
            local, at, domain = v.partition("@")
            out[k] = f"{local}{tag}@{domain}" if at else f"{v}{tag}"
    return out


class MassAssignmentCheck(BaseCheck):
    check_id = "mass_assignment"
    name = "Mass Assignment / Broken Object Property Level Authorization (OWASP API3)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if not isinstance(endpoint.body_example, dict) or not endpoint.body_example:
            return []

        url = self._build_url(endpoint)
        example = unique_values(endpoint.body_example) if endpoint.method == "POST" else endpoint.body_example
        body = {**example, **PRIVILEGED_FIELDS}

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
                "injected_values": PRIVILEGED_FIELDS,
                "strategy": "privileged_field_injection",
            },
        )]
