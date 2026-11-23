from apifuzz.checks.base import BaseCheck
from apifuzz.executor import TestCase
from apifuzz.models.endpoint import AuthConfig, Endpoint, ParamLocation

# Canaries: the analyzer looks for the *computed* value, which never appears in the payload itself.
SSTI_PRODUCT = "9801547"            # 1337 * 7331
CMD_CANARY = "apifuzz9801547"       # output of: echo apifuzz$((1337*7331))

INJECTION_PAYLOADS = [
    {"payload": "'", "type": "sqli"},             # breaks quoting -> DB error even where a tautology is valid SQL
    {"payload": "' OR '1'='1", "type": "sqli"},
    {"payload": "{{1337*7331}}", "type": "ssti"},  # Jinja2 / Twig / Nunjucks
    {"payload": "${1337*7331}", "type": "ssti"},   # FreeMarker / JSP EL / Thymeleaf
    {"payload": "; id", "type": "cmd_injection"},
    {"payload": "; echo apifuzz$((1337*7331))", "type": "cmd_injection"},
    {"payload": "<script>apifuzz(1337)</script>", "type": "xss"},
]

# NoSQL operator injection is sent as a true/false pair; the analyzer flags a pair whose responses differ.
# Query params use the qs bracket syntax (Express); JSON bodies get real operator objects.
NOSQLI_NONEXISTENT = "apifuzz-nonexistent"


class InjectionCheck(BaseCheck):
    check_id = "injection"
    name = "Injection (OWASP Top 10 A03:2021)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        test_cases: list[TestCase] = []
        url = self._build_url(endpoint)

        def case(label: str, extra: dict, *, url: str = url, params: dict | None = None, body=None) -> TestCase:
            return TestCase(
                method=endpoint.method,
                url=url,
                headers={},
                params=params or {},
                body=body if body is not None else endpoint.body_example,
                label=label,
                check_id=self.check_id,
                extra={"strategy": "injection_probe", **extra},
            )

        string_params = [
            p for p in endpoint.parameters
            if p.schema_type == "string" and p.location in (ParamLocation.QUERY, ParamLocation.PATH)
        ]
        for param in string_params:
            for p in INJECTION_PAYLOADS:
                label = f"Injection [{p['type']}]: {endpoint.method} {endpoint.path} [{param.name}]"
                extra = {"param_name": param.name, "payload": p["payload"], "injection_type": p["type"]}
                if param.location == ParamLocation.QUERY:
                    test_cases.append(case(label, extra, params={param.name: p["payload"]}))
                else:
                    test_cases.append(case(label, extra, url=self._build_url(endpoint, {param.name: p["payload"]})))
            if param.location == ParamLocation.QUERY:
                pair = f"{endpoint.method} {endpoint.path} query.{param.name}"
                for polarity, op in (("true", "$ne"), ("false", "$eq")):
                    test_cases.append(case(
                        f"Injection [nosqli {polarity}]: {endpoint.method} {endpoint.path} [{param.name}]",
                        {"param_name": param.name, "injection_type": "nosqli", "strategy": "nosqli_pair",
                         "pair_id": pair, "polarity": polarity},
                        params={f"{param.name}[{op}]": NOSQLI_NONEXISTENT},
                    ))

        # Body injection: one string field at a time, the rest of the example stays valid
        example = endpoint.body_example if isinstance(endpoint.body_example, dict) else {}
        for field_name in [k for k, v in example.items() if isinstance(v, str)]:
            for p in INJECTION_PAYLOADS:
                test_cases.append(case(
                    f"Injection [{p['type']}]: {endpoint.method} {endpoint.path} [body.{field_name}]",
                    {"target": "body", "param_name": field_name, "payload": p["payload"],
                     "injection_type": p["type"]},
                    body={**example, field_name: p["payload"]},
                ))
            pair = f"{endpoint.method} {endpoint.path} body.{field_name}"
            for polarity, value in (("true", {"$ne": None}), ("false", {"$eq": NOSQLI_NONEXISTENT})):
                test_cases.append(case(
                    f"Injection [nosqli {polarity}]: {endpoint.method} {endpoint.path} [body.{field_name}]",
                    {"target": "body", "param_name": field_name, "injection_type": "nosqli",
                     "strategy": "nosqli_pair", "pair_id": pair, "polarity": polarity},
                    body={**example, field_name: value},
                ))

        return test_cases
