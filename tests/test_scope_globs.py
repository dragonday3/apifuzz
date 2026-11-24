"""A glob that matches nothing is warned about: "* /createdb" once silently excluded nothing and the scan reset
VAmPI's data."""
from typer.testing import CliRunner

from fuzzowl.cli import app
from fuzzowl.scanner import Scanner

SPEC = """openapi: "3.0.3"
info: {title: t, version: "1"}
paths:
  /createdb: {get: {responses: {"200": {description: ok}}}}
  /users/{u}: {get: {parameters: [{name: u, in: path, required: true, schema: {type: string}}],
                     responses: {"200": {description: ok}}}}
"""


def test_unmatched_globs(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    s = Scanner(str(spec), "http://api", include=["/users/*"], exclude=["* /createdb", "/createdb"])
    assert s.unmatched_globs() == ["--exclude * /createdb"]


def test_cli_warns_even_when_quiet(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    result = CliRunner().invoke(app, [str(spec), "--target", "http://api", "--exclude", "GET /createdb",
                                      "--dry-run", "--quiet"])
    assert result.exit_code == 0
    assert "--exclude GET /createdb matches no path" in result.output
