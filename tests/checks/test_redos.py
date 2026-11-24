"""Phase 6.3: ReDoS probes (opt-in with --time-based): targeting, payload shape, scan pass placement."""
import textwrap

from apifuzz.checks.redos import REDOS_CONTROL, REDOS_EVIL, REDOS_N, REPEATS, RedosCheck
from apifuzz.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation
from apifuzz.parsers.openapi import OpenAPIParser
from apifuzz.scanner import Scanner


def check(time_based=True) -> RedosCheck:
    c = RedosCheck()
    c.time_based = time_based
    return c


def ep(method="POST", params=None, body=None, props=None):
    return Endpoint(method=method, path="/users", base_url="http://api", parameters=params or [],
                    body_example=body, body_schema={"type": "object", "properties": props or {}})


def targets(cases):
    return {c.extra["param_name"] for c in cases}


def test_nothing_without_time_based():
    assert check(False).generate(ep(body={"email": "a@b.co"}), AuthConfig()) == []


def test_targets_pattern_format_and_name():
    body = {"email": "a@b.co", "site": "x", "code": "AB12", "bio": "hi", "zip": "1", "age": 3}
    props = {"site": {"type": "string", "format": "uri"}, "code": {"type": "string", "pattern": "^[A-Z]+[0-9]+$"},
             "zip": {"type": "string", "format": "date"}, "age": {"type": "integer", "pattern": "x"}}
    params = [Parameter(name="callback_url", location=ParamLocation.QUERY),
              Parameter(name="q", location=ParamLocation.QUERY, pattern="^(a+)+$"),
              Parameter(name="host", location=ParamLocation.QUERY, schema_format="hostname"),
              Parameter(name="page", location=ParamLocation.QUERY),
              Parameter(name="limit", location=ParamLocation.QUERY, schema_type="integer", pattern="^[0-9]+$"),
              Parameter(name="email", location=ParamLocation.PATH)]  # path params aren't targeted
    cases = check().generate(ep(params=params, body=body, props=props), AuthConfig())
    # bio/zip: no regex hint; age/limit: not strings
    assert targets(cases) == {"email", "site", "code", "callback_url", "q", "host"}


def test_payload_shape_interleaved_same_length():
    cases = check().generate(ep(body={"email": "a@b.co", "name": "bob"}), AuthConfig())
    assert len(cases) == 2 * REPEATS
    assert [c.extra["polarity"] for c in cases] == ["control", "evil"] * REPEATS
    assert REDOS_EVIL == "a" * REDOS_N + "!" and REDOS_CONTROL == "!" + "a" * REDOS_N
    for c in cases:
        assert c.body == {"email": c.extra["payload"], "name": "bob"}  # rest of the example stays valid
        assert c.extra["strategy"] == "redos" and c.extra["pair_id"] == "POST /users [email]"
        assert c.auth_mode == "default" and c.throttle


def test_query_param_payload():
    cases = check().generate(ep("GET", params=[Parameter(name="email", location=ParamLocation.QUERY)]), AuthConfig())
    assert {c.params["email"] for c in cases} == {REDOS_EVIL, REDOS_CONTROL} and all(c.body is None for c in cases)


def test_delete_skipped():
    assert check().generate(ep("DELETE", params=[Parameter(name="email", location=ParamLocation.QUERY)]),
                            AuthConfig()) == []


def test_parser_keeps_format_and_pattern(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(textwrap.dedent("""
        swagger: "2.0"
        info: {title: t, version: "1"}
        paths:
          /a:
            get:
              parameters:
                - {name: e, in: query, type: string, format: email}
                - {name: c, in: query, type: string, pattern: "^[a-z]+$"}
              responses: {"200": {description: ok}}
    """))
    [e] = OpenAPIParser().parse(str(spec))
    assert {p.name: (p.schema_format, p.pattern) for p in e.parameters} == {"e": ("email", ""), "c": ("", "^[a-z]+$")}


def _scanner(tmp_path, monkeypatch, time_based):
    scanner = Scanner(str(tmp_path / "unused.yaml"), "http://api", checks=["injection", "redos"],
                      time_based=time_based)
    endpoint = Endpoint(method="POST", path="/users", base_url="http://api", body_example={"email": "a@b.co"})
    monkeypatch.setattr(scanner, "_parse", lambda path: [endpoint])
    return scanner


async def test_scan_sends_redos_serially_in_time_pass(tmp_path, monkeypatch):
    calls: list[tuple[int, list[str]]] = []

    async def fake_run(self, cases):
        calls.append((self._sem._value, [tc.extra.get("strategy") or tc.check_id for tc in cases]))
        return []
    monkeypatch.setattr("apifuzz.executor.Executor.run", fake_run)
    await _scanner(tmp_path, monkeypatch, True).run()
    [(concurrency, strategies)] = [c for c in calls if "redos" in c[1]]
    assert concurrency == 1 and set(strategies) == {"redos", "sqli_time", "sqli_bool"}  # shares the serial pass
    assert strategies.count("redos") == 2 * REPEATS


def test_no_redos_without_time_based(tmp_path, monkeypatch):
    plan = _scanner(tmp_path, monkeypatch, False).plan()
    assert plan and not [tc for tc in plan if tc.check_id == "redos"]
