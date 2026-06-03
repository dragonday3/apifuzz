from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig, ParamLocation

SSRF_PARAM_NAMES = {
    "url", "uri", "endpoint", "redirect", "callback", "src", "href",
    "path", "dest", "destination", "link", "target", "next",
    "returnUrl", "returnurl",
}

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080",
    "http://127.0.0.1",
    "http://0.0.0.0",
]


class SSRFCheck(BaseCheck):
    check_id = "ssrf"
    name = "Server Side Request Forgery (OWASP API7)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        test_cases = []

        ssrf_params = [
            p for p in endpoint.parameters
            if p.name.lower() in {n.lower() for n in SSRF_PARAM_NAMES}
        ]

        if not ssrf_params:
            return []

        for param in ssrf_params:
            for payload in SSRF_PAYLOADS:
                label = f"SSRF: {endpoint.method} {endpoint.path} [{param.name}={payload[:30]}...]"
                extra = {
                    "param_name": param.name,
                    "param_location": param.location.value,
                    "payload": payload,
                    "strategy": "ssrf_probe",
                }

                if param.location == ParamLocation.QUERY:
                    test_cases.append(TestCase(
                        method=endpoint.method,
                        url=self._build_url(endpoint),
                        headers={},
                        params={param.name: payload},
                        body=endpoint.body_schema if endpoint.body_schema else None,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))
                elif param.location == ParamLocation.PATH:
                    url = self._build_url(endpoint, {param.name: payload})
                    test_cases.append(TestCase(
                        method=endpoint.method,
                        url=url,
                        headers={},
                        params={},
                        body=endpoint.body_schema if endpoint.body_schema else None,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))
                elif param.location == ParamLocation.BODY:
                    body = {**endpoint.body_schema, param.name: payload}
                    test_cases.append(TestCase(
                        method=endpoint.method,
                        url=self._build_url(endpoint),
                        headers={},
                        params={},
                        body=body,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))
                else:
                    # HEADER, COOKIE, etc.
                    test_cases.append(TestCase(
                        method=endpoint.method,
                        url=self._build_url(endpoint),
                        headers={param.name: payload},
                        params={},
                        body=endpoint.body_schema if endpoint.body_schema else None,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))

        return test_cases
