import textwrap

import httpx
import respx
from typer.testing import CliRunner

from apifuzz.checks.ssrf import SSRFCheck
from apifuzz.cli import app
from apifuzz.models.endpoint import AuthConfig, Endpoint, Parameter, ParamLocation

EP = Endpoint(method="GET", path="/fetch", base_url="http://api",
              parameters=[Parameter(name="url", location=ParamLocation.QUERY)])


def test_no_oob_payload_without_collector():
    assert not [c for c in SSRFCheck().generate(EP, AuthConfig()) if c.extra.get("oob_id")]


def test_oob_payload_points_at_collector_with_unique_id():
    check = SSRFCheck()
    check.oob_url = "https://oob.example.net/"
    [oob] = [c for c in check.generate(EP, AuthConfig()) if c.extra.get("oob_id")]
    assert oob.params["url"] == f"https://oob.example.net/apifuzz-{oob.extra['oob_id']}"
    [again] = [c for c in check.generate(EP, AuthConfig()) if c.extra.get("oob_id")]
    assert again.extra["oob_id"] != oob.extra["oob_id"]


def test_cli_prints_probe_ids_even_when_quiet(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(textwrap.dedent("""
        openapi: "3.0.3"
        info: {title: t, version: "1"}
        paths:
          /fetch:
            get:
              parameters: [{name: url, in: query, schema: {type: string}}]
              responses: {"200": {description: ok}}
    """))
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(return_value=httpx.Response(200, json={}))
        result = CliRunner().invoke(app, [str(spec), "--target", "http://api", "--checks", "ssrf", "--quiet",
                                          "--rate-limit", "0", "--oob-url", "https://oob.example.net"])
    assert result.exit_code == 0
    assert "blind-SSRF probe" in result.output and "apifuzz-" in result.output and "GET /fetch [url]" in result.output
