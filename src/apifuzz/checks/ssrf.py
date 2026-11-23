import secrets

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
    oob_url = ""  # set by Scanner from --oob-url: a collector you control, for blind SSRF

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        test_cases = []

        ssrf_params = [
            p for p in endpoint.parameters
            if p.name.lower() in {n.lower() for n in SSRF_PARAM_NAMES}
        ]

        if not ssrf_params:
            return []

        for param in ssrf_params:
            payloads = [(p, "") for p in SSRF_PAYLOADS]
            if self.oob_url:
                # Unique id per probe: a callback to <collector>/apifuzz-<id> names the parameter that fired.
                oob_id = secrets.token_hex(4)
                payloads.append((f"{self.oob_url.rstrip('/')}/apifuzz-{oob_id}", oob_id))
            for payload, oob_id in payloads:
                label = f"SSRF: {endpoint.method} {endpoint.path} [{param.name}={payload[:30]}...]"
                extra = {
                    "param_name": param.name,
                    "param_location": param.location.value,
                    "payload": payload,
                    "strategy": "ssrf_oob" if oob_id else "ssrf_probe",
                    **({"oob_id": oob_id} if oob_id else {}),
                }

                if param.location == ParamLocation.QUERY:
                    test_cases.append(TestCase(
                        method=endpoint.method,
                        url=self._build_url(endpoint),
                        headers={},
                        params={param.name: payload},
                        body=endpoint.body_example,
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
                        body=endpoint.body_example,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))
                elif param.location == ParamLocation.BODY:
                    base = endpoint.body_example if isinstance(endpoint.body_example, dict) else {}
                    body = {**base, param.name: payload}
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
                        body=endpoint.body_example,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))

        return test_cases
