"""ReDoS (OWASP API4): opt-in with --time-based, since a vulnerable target really burns CPU on every probe.

Targets string fields the server probably validates with a regex: top-level body fields and query params whose
schema has a `pattern`, a format in REGEX_FORMATS, or a name matching REGEX_NAME (email, url, domain...).

Each target gets REPEATS (control, evil) pairs, interleaved and sent one at a time in the time-based pass:
- evil    = "a" * N + "!": a long run a nested quantifier (`^(a+)+$`, VAmPI-style email regexes) splits every
            possible way before the final "!" fails the match;
- control = "!" + "a" * N: same length and characters, but it fails at the first character, so no backtracking.
Both are invalid for the field, so a server takes the same code path for both; only the regex cost differs.
"""
import re

from fuzzowl.checks.base import BaseCheck
from fuzzowl.executor import TestCase
from fuzzowl.models.endpoint import AuthConfig, Endpoint, ParamLocation

# Exponential backtracking doubles per character: in CPython, N=27 takes ~6 s for VAmPI's email regex and
# ~12 s for `^(\w+\s?)*$` (under the 15 s default --timeout), ~1 ms for a safe regex. Faster engines (V8, JVM)
# need longer runs and may be missed; linear engines (RE2, Go, Rust) are immune. Polynomial ReDoS is not tested.
REDOS_N = 27
REDOS_EVIL = "a" * REDOS_N + "!"
REDOS_CONTROL = "!" + "a" * REDOS_N
REPEATS = 3
REGEX_FORMATS = {"email", "idn-email", "uri", "url", "iri", "uri-reference", "hostname", "idn-hostname"}
REGEX_NAME = re.compile(r"e-?mail|url|uri|link|domain|host|website", re.IGNORECASE)


def _regex_validated(name: str, schema_format: str, pattern: str) -> bool:
    return bool(pattern) or schema_format in REGEX_FORMATS or bool(REGEX_NAME.search(name))


class RedosCheck(BaseCheck):
    check_id = "redos"
    name = "ReDoS (OWASP API4:2023)"
    time_based = False  # set by Scanner from --time-based; nothing is generated without it

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        if not self.time_based or endpoint.method == "DELETE":
            return []
        url = self._build_url(endpoint)
        example = endpoint.body_example if isinstance(endpoint.body_example, dict) else {}
        props = endpoint.body_schema.get("properties") or {}
        targets: list[tuple[str, bool]] = []  # (name, in_body)
        for p in endpoint.parameters:
            if (p.location == ParamLocation.QUERY and p.schema_type == "string"
                    and _regex_validated(p.name, p.schema_format, p.pattern)):
                targets.append((p.name, False))
        for field, value in example.items():
            sub = props.get(field)
            schema = sub if isinstance(sub, dict) else {}
            if isinstance(value, str) and _regex_validated(field, str(schema.get("format", "")),
                                                           str(schema.get("pattern", ""))):
                targets.append((field, True))

        cases = []
        for name, in_body in targets:
            pair = f"{endpoint.method} {endpoint.path} [{name}]"
            for i in range(REPEATS):
                for polarity, value in (("control", REDOS_CONTROL), ("evil", REDOS_EVIL)):
                    cases.append(TestCase(
                        method=endpoint.method, url=url, headers={},
                        params={} if in_body else {name: value},
                        body={**example, name: value} if in_body else endpoint.body_example,
                        label=f"ReDoS [{polarity} #{i + 1}]: {pair}", check_id=self.check_id,
                        extra={"strategy": "redos", "pair_id": pair, "polarity": polarity, "param_name": name,
                               "payload": value, **({"target": "body"} if in_body else {})}))
        return cases
