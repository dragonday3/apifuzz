"""--token without --auth-type must authenticate (it used to scan with no credentials at all)."""
import httpx
import respx
from typer.testing import CliRunner

from apifuzz.cli import app

SPEC = """openapi: "3.0.3"
info: {title: t, version: "1"}
paths:
  /me: {get: {responses: {"200": {description: ok}}}}
"""


def run(tmp_path, *args):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    seen: list[str | None] = []

    def handler(request):
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"me": "alice"})

    with respx.mock(assert_all_called=False) as router:
        router.route(host="api").mock(side_effect=handler)
        result = CliRunner().invoke(app, [str(spec), "--target", "http://api", "--checks", "auth", "--quiet",
                                          "--rate-limit", "0", "--fail-on", "never", *args])
    return result, seen


def test_token_alone_defaults_to_bearer(tmp_path):
    result, seen = run(tmp_path, "--token", "tok-a")
    assert result.exit_code == 0
    assert "Bearer tok-a" in seen  # the baseline request carries the token


def test_explicit_none_with_token_is_rejected(tmp_path):
    result, _ = run(tmp_path, "--auth-type", "none", "--token", "tok-a")
    assert result.exit_code == 2
