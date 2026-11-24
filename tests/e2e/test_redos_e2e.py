"""Phase 6.3: ReDoS end to end. The mocked API "backtracks" on the evil input by advancing a fake clock the
executor reads, so no test sleeps."""
import json
import re
import textwrap
import types

import httpx
import respx

import apifuzz.executor
from apifuzz.checks.redos import REPEATS
from apifuzz.scanner import Scanner

BASE = "http://testserver"
SPEC = textwrap.dedent("""
    openapi: "3.0.3"
    info: {title: users, version: "1"}
    paths:
      /users:
        post:
          requestBody:
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    email: {type: string, example: mail1@mail.com}
                    username: {type: string, example: name1}
          responses: {"200": {description: ok}}
""")
# A long run of word characters followed by a character the regex can't end on: what backtracks.
EVIL = re.compile(r"^\w{20,}[^\w@.]$")


async def scan(tmp_path, monkeypatch, vulnerable: bool, time_based=True):
    clock = [0.0]
    monkeypatch.setattr(apifuzz.executor, "time", types.SimpleNamespace(monotonic=lambda: clock[0], time=lambda: 0))
    seen: list[str] = []

    def api(request: httpx.Request) -> httpx.Response:
        email = json.loads(request.content or b"{}").get("email", "")
        seen.append(email)
        clock[0] += 6.0 if vulnerable and EVIL.match(email) else 0.05
        return httpx.Response(400 if "@" not in email else 200, json={"email": email})

    spec = tmp_path / "users.yaml"
    spec.write_text(SPEC)
    with respx.mock(assert_all_called=False) as router:
        router.route(host="testserver").mock(side_effect=api)
        findings = await Scanner(str(spec), BASE, checks=["redos"], rate_limit_rps=0, time_based=time_based).run()
    return findings, seen


async def test_vulnerable_regex_detected(tmp_path, monkeypatch):
    findings, seen = await scan(tmp_path, monkeypatch, vulnerable=True)
    [f] = findings
    assert (f.rule_id, f.confidence, f.endpoint, f.parameter) == ("APIFUZZ-REDOS-001", "firm", "POST /users", "email")
    assert len(seen) == 2 * REPEATS  # no baseline needed: the controls are the comparison


async def test_linear_regex_not_flagged(tmp_path, monkeypatch):
    findings, _ = await scan(tmp_path, monkeypatch, vulnerable=False)
    assert findings == []


async def test_default_scan_sends_nothing(tmp_path, monkeypatch):
    findings, seen = await scan(tmp_path, monkeypatch, vulnerable=True, time_based=False)
    assert findings == [] and seen == []
