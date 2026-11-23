import re

from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase, auth_headers
from apifuzz.models.endpoint import AuthConfig, Endpoint

# Words in the path, tags, operationId or summary that mark an operation as meant for privileged roles.
PRIVILEGED = re.compile(r"(admin|internal|manage(ment)?|staff|superuser|privileged|moderat|root\b)", re.IGNORECASE)


class BFLACheck(BaseCheck):
    """Broken function level authorization (OWASP API5): with --low-priv-token, call privileged-looking
    operations as the low-privilege user. The configured token is the privileged one (the baseline)."""

    check_id = "bfla"
    name = "Broken Function Level Authorization (OWASP API5)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if not auth.low_priv_token:
            return []
        hints = " ".join([endpoint.path, endpoint.operation_id, endpoint.summary, *endpoint.tags])
        match = PRIVILEGED.search(hints)
        if not match:
            return []
        return [TestCase(
            method=endpoint.method,
            url=self._build_url(endpoint),
            headers=auth_headers(auth.type if auth.type != "none" else "bearer", auth.low_priv_token,
                                 auth.header_name),
            params={},
            body=endpoint.body_example,
            label=f"BFLA: {endpoint.method} {endpoint.path} as low-privilege user",
            check_id=self.check_id,
            extra={"strategy": "low_priv", "hint": match.group(0)},
            auth_mode="override",
        )]
