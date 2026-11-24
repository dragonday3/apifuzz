from fuzzowl.checks.base import BaseCheck
from fuzzowl.executor import TestCase
from fuzzowl.models.endpoint import AuthConfig, Endpoint, ParamLocation

# Canaries: the analyzer looks for the *computed* value, which never appears in the payload itself.
SSTI_PRODUCT = "9801547"            # 1337 * 7331
CMD_CANARY = "fuzzowl9801547"       # output of: echo fuzzowl$((1337*7331))

INJECTION_PAYLOADS = [
    {"payload": "'", "type": "sqli"},             # breaks quoting -> DB error even where a tautology is valid SQL
    {"payload": "' OR '1'='1", "type": "sqli"},
    {"payload": "{{1337*7331}}", "type": "ssti"},  # Jinja2 / Twig / Nunjucks
    {"payload": "${1337*7331}", "type": "ssti"},   # FreeMarker / JSP EL / Thymeleaf
    {"payload": "; id", "type": "cmd_injection"},
    {"payload": "; echo fuzzowl$((1337*7331))", "type": "cmd_injection"},
    {"payload": "<script>fuzzowl(1337)</script>", "type": "xss"},
]

# NoSQL operator injection is sent as a true/false pair; the analyzer flags a pair whose responses differ.
# Query params use the qs bracket syntax (Express); JSON bodies get real operator objects.
NOSQLI_NONEXISTENT = "fuzzowl-nonexistent"

# Boolean SQLi: original value + a true / false condition, between two control requests with the original
# value alone (sent one at a time, in this order). True must answer like the control and false must not, and
# both controls must answer alike: a response that grows with every request isn't a stable reference.
SQLI_BOOL = (("true", "' AND '1'='1"), ("false", "' AND '1'='2"))
# Time-based SQLi (opt-in, --time-based): each payload sent TIME_REPEATS times, compared with the control.
SQLI_SLEEP_SECONDS = 5
SQLI_TIME_PAYLOADS = (f"' AND SLEEP({SQLI_SLEEP_SECONDS})-- -", f"'||pg_sleep({SQLI_SLEEP_SECONDS})--",
                      f"'; WAITFOR DELAY '0:0:{SQLI_SLEEP_SECONDS}'--")
TIME_REPEATS = 3


class InjectionCheck(BaseCheck):
    check_id = "injection"
    name = "Injection (OWASP Top 10 A03:2021)"
    time_based = False  # set by Scanner from --time-based; each probe waits ~5 s on a vulnerable target

    def _value_probes(self, endpoint: Endpoint, case, target: str, value: str, place) -> list[TestCase]:
        """Probes that append to the original value: the boolean SQLi triple and optional time-based."""
        if endpoint.method == "DELETE":  # the control request carries the real value: it would delete it
            return []
        where = f"{endpoint.method} {endpoint.path} [{target}]"
        common = {"param_name": target, "injection_type": "sqli"}
        if target.startswith("body."):
            common["target"] = "body"
        out = [case(f"Injection [sqli bool {pol}]: {where}",
                    {**common, "strategy": "sqli_bool", "pair_id": where, "polarity": pol,
                     "payload": value + suffix}, **place(value + suffix))
               for pol, suffix in (("control", ""), *SQLI_BOOL, ("control_again", ""))]
        if self.time_based:
            for payload in SQLI_TIME_PAYLOADS:
                out += [case(f"Injection [sqli time #{i + 1}]: {where}",
                             {**common, "strategy": "sqli_time", "pair_id": f"{where} {payload}",
                              "polarity": "probe", "control_id": where, "payload": value + payload}, **place(value + payload))
                        for i in range(TIME_REPEATS)]
        return out

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
            original = str(param.example) if param.example is not None else "1"
            if param.location == ParamLocation.QUERY:
                test_cases += self._value_probes(endpoint, case, param.name, original,
                                                 lambda v, n=param.name: {"params": {n: v}})
            else:
                test_cases += self._value_probes(endpoint, case, param.name, original,
                                                 lambda v, n=param.name: {"url": self._build_url(endpoint, {n: v})})
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
            test_cases += self._value_probes(endpoint, case, f"body.{field_name}", example[field_name],
                                             lambda v, f=field_name: {"body": {**example, f: v}})
            pair = f"{endpoint.method} {endpoint.path} body.{field_name}"
            for polarity, value in (("true", {"$ne": None}), ("false", {"$eq": NOSQLI_NONEXISTENT})):
                test_cases.append(case(
                    f"Injection [nosqli {polarity}]: {endpoint.method} {endpoint.path} [body.{field_name}]",
                    {"target": "body", "param_name": field_name, "injection_type": "nosqli",
                     "strategy": "nosqli_pair", "pair_id": pair, "polarity": polarity},
                    body={**example, field_name: value},
                ))

        return test_cases
