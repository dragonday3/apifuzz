import json
import respx
import httpx
from pathlib import Path
from typer.testing import CliRunner

from apifuzz.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
PETSTORE = str(FIXTURES / "petstore.yaml")

runner = CliRunner()


class TestCLIScan:
    def test_scan_no_target_fails(self):
        result = runner.invoke(app, [PETSTORE])
        assert result.exit_code != 0

    def test_scan_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "target" in result.output.lower()

    @respx.mock
    def test_scan_json_output(self):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.delete(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.patch(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.put(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))

        result = runner.invoke(app, [
            PETSTORE,
            "--target", "http://testserver",
            "--output", "json",
            "--checks", "auth",
            "--quiet",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)

    @respx.mock
    def test_scan_sarif_output(self):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))

        result = runner.invoke(app, [
            PETSTORE,
            "--target", "http://testserver",
            "--output", "sarif",
            "--checks", "cors",
            "--quiet",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "runs" in data

    @respx.mock
    def test_scan_html_output(self):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))

        result = runner.invoke(app, [
            PETSTORE,
            "--target", "http://testserver",
            "--output", "html",
            "--checks", "cors",
            "--quiet",
        ])
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

    @respx.mock
    def test_scan_exit_1_on_critical_finding(self):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={"data": "ok"}))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={}))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200))

        result = runner.invoke(app, [
            PETSTORE,
            "--target", "http://testserver",
            "--output", "json",
            "--checks", "auth",
            "--quiet",
        ])
        assert result.exit_code == 1

    @respx.mock
    def test_scan_write_json_to_file(self, tmp_path):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))

        out = tmp_path / "findings.json"
        result = runner.invoke(app, [
            PETSTORE,
            "--target", "http://testserver",
            "--output", "json",
            "--out-file", str(out),
            "--checks", "auth",
            "--quiet",
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)

    def test_app_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "owasp" in result.output.lower()
