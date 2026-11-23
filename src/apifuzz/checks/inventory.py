import re
import secrets

from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import AuthConfig, Endpoint

# (path, kind): kind decides what content the analyzer requires before calling it exposed.
WELL_KNOWN = [
    ("/openapi.json", "spec"), ("/openapi.yaml", "spec"), ("/swagger.json", "spec"), ("/swagger.yaml", "spec"),
    ("/v2/api-docs", "spec"), ("/v3/api-docs", "spec"), ("/api-docs", "spec"),
    ("/swagger-ui.html", "docs_ui"), ("/swagger-ui/", "docs_ui"), ("/docs", "docs_ui"), ("/redoc", "docs_ui"),
    ("/ui/", "docs_ui"),
    ("/actuator", "actuator"), ("/actuator/env", "actuator_env"), ("/actuator/configprops", "actuator_env"),
    ("/.env", "dotenv"), ("/debug/vars", "expvar"), ("/metrics", "metrics"), ("/server-status", "server_status"),
]
_VERSION = re.compile(r"/v(\d+)(?=/|$)")
MAX_VERSION_PROBES = 10


class InventoryCheck(BaseCheck):
    """Improper inventory management (OWASP API9): API docs, debug/management endpoints and API versions
    that are reachable but not in the spec. Runs once per scan."""

    check_id = "inventory"
    name = "Improper Inventory Management (OWASP API9)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        return []  # nothing per endpoint

    def generate_global(self, endpoints: list[Endpoint], auth: AuthConfig) -> list[TestCase]:
        if not endpoints:
            return []
        base = endpoints[0].base_url
        documented = {ep.path.rstrip("/") or "/" for ep in endpoints}

        def case(path: str, kind: str, strategy: str = "inventory_probe") -> TestCase:
            return TestCase(method="GET", url=f"{base}{path}", headers={}, params={}, body=None,
                            label=f"Inventory: GET {path} [{kind}]", check_id=self.check_id,
                            extra={"strategy": strategy, "kind": kind, "path": path})

        # A path that can't exist: what a catch-all/SPA server answers for anything.
        cases = [case(f"/apifuzz-nonexistent-{secrets.token_hex(4)}", "control", "inventory_control")]
        cases += [case(p, kind) for p, kind in WELL_KNOWN if p.rstrip("/") not in documented]
        versions: list[str] = []
        for ep in endpoints:
            m = _VERSION.search(ep.path)
            if ep.method != "GET" or "{" in ep.path or not m:
                continue
            n = int(m.group(1))
            for other in (n + 1, n - 1):
                path = ep.path[:m.start()] + f"/v{other}" + ep.path[m.end():]
                if other >= 0 and path not in documented and path not in versions:
                    versions.append(path)
        cases += [case(p, "version") for p in versions[:MAX_VERSION_PROBES]]
        return cases
