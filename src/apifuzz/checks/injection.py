from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import Endpoint, AuthConfig, ParamLocation

INJECTION_PAYLOADS = [
    {"payload": "' OR '1'='1", "type": "sqli"},
    {"payload": "{{7*7}}", "type": "ssti"},
    {"payload": '{"$gt": ""}', "type": "nosqli"},
    {"payload": "; id", "type": "cmd_injection"},
    {"payload": "<script>alert(1)</script>", "type": "xss"},
]


class InjectionCheck(BaseCheck):
    check_id = "injection"
    name = "Injection (OWASP API8)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        test_cases = []

        string_params = [
            p for p in endpoint.parameters
            if p.schema_type == "string" and p.location in (ParamLocation.QUERY, ParamLocation.PATH)
        ]

        for param in string_params:
            for p in INJECTION_PAYLOADS:
                label = f"Injection [{p['type']}]: {endpoint.method} {endpoint.path} [{param.name}]"
                extra = {
                    "param_name": param.name,
                    "payload": p["payload"],
                    "injection_type": p["type"],
                    "strategy": "injection_probe",
                }

                if param.location == ParamLocation.QUERY:
                    test_cases.append(TestCase(
                        method=endpoint.method,
                        url=self._build_url(endpoint),
                        headers={},
                        params={param.name: p["payload"]},
                        body=endpoint.body_example,
                        label=label,
                        check_id=self.check_id,
                        extra=extra,
                    ))
                elif param.location == ParamLocation.PATH:
                    url = self._build_url(endpoint, {param.name: p["payload"]})
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

        # Body injection: one string field at a time, the rest of the example stays valid
        example = endpoint.body_example if isinstance(endpoint.body_example, dict) else {}
        string_fields = [k for k, v in example.items() if isinstance(v, str)]
        for field_name in string_fields:
            for p in INJECTION_PAYLOADS:
                label = f"Injection [{p['type']}]: {endpoint.method} {endpoint.path} [body.{field_name}]"
                body = {**example, field_name: p["payload"]}
                test_cases.append(TestCase(
                    method=endpoint.method,
                    url=self._build_url(endpoint),
                    headers={},
                    params={},
                    body=body,
                    label=label,
                    check_id=self.check_id,
                    extra={
                        "target": "body",
                        "param_name": field_name,
                        "payload": p["payload"],
                        "injection_type": p["type"],
                        "strategy": "injection_probe",
                    },
                ))

        return test_cases
