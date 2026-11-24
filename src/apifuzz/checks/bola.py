import re
from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase, auth_headers
from apifuzz.models.endpoint import Endpoint, AuthConfig, ParamLocation

ID_PATTERNS = re.compile(r'(id|Id|ID|uuid|UUID|key|Key)$')
MISSING_ID = "99999999"  # an id that shouldn't exist: shows what the endpoint answers for "not found"


class BOLACheck(BaseCheck):
    check_id = "bola"
    name = "Broken Object Level Authorization (OWASP API1)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        test_cases = []
        if auth.second_token and endpoint.method == "GET" and not any(
                p.location == ParamLocation.PATH for p in endpoint.parameters):
            # A listing as user B: an object of user A's that B also sees here is public by design (forum
            # posts, products), so B reading it directly is a weaker signal (the analyzer downgrades it).
            return [TestCase(
                method="GET", url=self._build_url(endpoint), params={}, body=None,
                headers=auth_headers(auth.type if auth.type != "none" else "bearer",
                                     auth.second_token, auth.header_name),
                label=f"BOLA listing: GET {endpoint.path} via second token", check_id="bola_listing",
                extra={"strategy": "listing", "uses_second_token": True}, auth_mode="override",
            )]
        if endpoint.secured is False and not endpoint.auth_optional:  # public by design: anyone may read it
            return []
        path_params = [p for p in endpoint.parameters if p.location == ParamLocation.PATH]
        # On a secured endpoint every path param can be an object reference (book_title, username);
        # otherwise only id-looking names are worth probing.
        id_params = path_params if endpoint.secured else [p for p in path_params if ID_PATTERNS.search(p.name)]

        if not id_params:
            return []

        for param in id_params:
            # Strategy 1: ID manipulation — try adjacent IDs (current±1, 0, 999999)
            # DELETE probes would destroy objects and can't be confirmed (no baseline for DELETE).
            probe_ids = [] if endpoint.method == "DELETE" else ["0", "1", "2", "999999", MISSING_ID]
            for probe_id in probe_ids:
                url = self._build_url(endpoint, {param.name: probe_id})
                test_cases.append(TestCase(
                    method=endpoint.method,
                    url=url,
                    headers={},
                    params={},
                    body=endpoint.body_example,
                    label=f"BOLA: {endpoint.method} {endpoint.path} [{param.name}={probe_id}]",
                    check_id=self.check_id,
                    extra={"param_name": param.name, "probe_id": probe_id, "strategy": "id_enumeration"},
                ))

            # Strategy 2: Cross-user test — if second_token provided, access as user-A using user-B's token
            if auth.second_token:
                # Use a known ID from example or default "1"
                example_id = str(param.example) if param.example is not None else "1"
                url = self._build_url(endpoint, {param.name: example_id})
                test_cases.append(TestCase(
                    method=endpoint.method,
                    url=url,
                    # Same scheme as user A; with auth type "none", assume bearer for the second token.
                    headers=auth_headers(auth.type if auth.type != "none" else "bearer",
                                         auth.second_token, auth.header_name),
                    params={},
                    body=endpoint.body_example,
                    label=f"BOLA cross-user: {endpoint.method} {endpoint.path} [{param.name}={example_id}] via second token",
                    check_id=self.check_id,
                    extra={"param_name": param.name, "probe_id": example_id, "strategy": "cross_user",
                           "uses_second_token": True},
                    auth_mode="override",
                ))

        return test_cases
