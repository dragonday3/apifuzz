import re

from fuzzowl.checks.base import BaseCheck
from fuzzowl.executor import TestCase, auth_headers
from fuzzowl.models.endpoint import AuthConfig, Endpoint

_ROLE = r"(admin|administrator|internal|manage|management|staff|superuser|moderator|backoffice|root)"
# Anchored: a whole path segment (/admin/, /internal/...), a whole tag, an operationId word (adminDeleteUser,
# admin_delete) or an explicit phrase in the summary. "/users/{id}/manager" or "admins can also..." don't count.
_PATH = re.compile(rf"(^|/){_ROLE}(/|$)", re.IGNORECASE)
_TAG = re.compile(rf"^{_ROLE}$", re.IGNORECASE)
_OP_ID = re.compile(rf"(^|_|\b){_ROLE}([A-Z_]|$)")
_SUMMARY = re.compile(r"\b(only\s+admin(istrator)?s?|admin(istrator)?s?\s+only|requires?\s+(an?\s+)?admin"
                      r"|admin(istrator)?\s+(role|privileges?|access|rights))\b", re.IGNORECASE)


def privilege_hint(endpoint: Endpoint) -> str | None:
    """Why the spec says this operation is for privileged roles, or None."""
    if endpoint.privileged:
        return "x-admin/x-internal extension"
    for text, pattern in ((endpoint.path, _PATH), (endpoint.operation_id, _OP_ID)):
        m = pattern.search(text)
        if m:
            return m.group(2)  # the role word itself
    m = _SUMMARY.search(endpoint.summary)
    if m:
        return m.group(0)
    return next((t for t in endpoint.tags if _TAG.match(t)), None)


class BFLACheck(BaseCheck):
    """Broken function level authorization (OWASP API5): with --low-priv-token, call privileged-looking
    operations as the low-privilege user. The configured token is the privileged one (the baseline)."""

    check_id = "bfla"
    name = "Broken Function Level Authorization (OWASP API5)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if not auth.low_priv_token or endpoint.secured is False:  # public: any token may call it
            return []
        hint = privilege_hint(endpoint)
        if not hint:
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
            extra={"strategy": "low_priv", "hint": hint},
            auth_mode="override",
        )]
