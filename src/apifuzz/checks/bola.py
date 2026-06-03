import re
from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig, ParamLocation

ID_PATTERNS = re.compile(r'(id|Id|ID|uuid|UUID|key|Key)$')


class BOLACheck(BaseCheck):
    check_id = "bola"
    name = "Broken Object Level Authorization (OWASP API1)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        test_cases = []
        id_params = [p for p in endpoint.parameters if p.location == ParamLocation.PATH and ID_PATTERNS.search(p.name)]

        if not id_params:
            return []

        for param in id_params:
            # Strategy 1: ID manipulation — try adjacent IDs (current±1, 0, 999999)
            probe_ids = ["0", "1", "2", "999999", "99999999"]
            for probe_id in probe_ids:
                url = self._build_url(endpoint, {param.name: probe_id})
                test_cases.append(TestCase(
                    method=endpoint.method,
                    url=url,
                    headers={},
                    params={},
                    body=endpoint.body_schema if endpoint.body_schema else None,
                    label=f"BOLA: {endpoint.method} {endpoint.path} [{param.name}={probe_id}]",
                    check_id=self.check_id,
                    extra={"param_name": param.name, "probe_id": probe_id, "strategy": "id_enumeration"},
                ))

            # Strategy 2: Cross-user test — if second_token provided, access as user-A using user-B's token
            if auth.second_token:
                # Use a known ID from example or default "1"
                example_id = str(param.example) if param.example else "1"
                url = self._build_url(endpoint, {param.name: example_id})
                test_cases.append(TestCase(
                    method=endpoint.method,
                    url=url,
                    headers={"Authorization": f"Bearer {auth.second_token}"},
                    params={},
                    body=endpoint.body_schema if endpoint.body_schema else None,
                    label=f"BOLA cross-user: {endpoint.method} {endpoint.path} [{param.name}={example_id}] via second token",
                    check_id=self.check_id,
                    extra={"param_name": param.name, "probe_id": example_id, "strategy": "cross_user", "uses_second_token": True},
                ))

        return test_cases
