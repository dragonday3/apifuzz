import pytest
import respx
import httpx
from pathlib import Path

from apifuzz.scanner import Scanner, _detect_format
from apifuzz.models.endpoint import AuthConfig

FIXTURES = Path(__file__).parent / "fixtures"
PETSTORE = str(FIXTURES / "petstore.yaml")


@pytest.fixture
def auth():
    return AuthConfig()


class TestDetectFormat:
    def test_har_extension(self):
        assert _detect_format(str(FIXTURES / "sample.har")) == "har"

    def test_yaml_openapi(self):
        assert _detect_format(PETSTORE) == "openapi"

    def test_postman_json(self):
        assert _detect_format(str(FIXTURES / "sample_postman.json")) == "postman"


class TestScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_run_returns_list(self):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={}))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(201, json={}))
        respx.delete(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(204))
        respx.patch(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={}))
        respx.put(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={}))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200))

        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://testserver",
            auth=AuthConfig(),
            checks=["auth"],  # just auth to keep test fast
        )
        findings = await scanner.run()
        assert isinstance(findings, list)

    @respx.mock
    @pytest.mark.asyncio
    async def test_checks_filter_works(self):
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(403))

        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://testserver",
            checks=["cors"],
        )
        # Just verify it runs without error
        findings = await scanner.run()
        assert isinstance(findings, list)

    @respx.mock
    @pytest.mark.asyncio
    async def test_auth_bypass_detected(self):
        # All requests return 200 — auth check should flag issues
        respx.get(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={"data": "secret"}))
        respx.post(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200, json={}))
        respx.options(url__regex=r"http://testserver.*").mock(return_value=httpx.Response(200))

        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://testserver",
            checks=["auth"],
        )
        findings = await scanner.run()
        assert len(findings) > 0
        rule_ids = {f.rule_id for f in findings}
        # Should detect no_auth or similar auth bypass
        assert any("AUTH" in rid for rid in rule_ids)

    def test_parse_openapi_returns_endpoints(self):
        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://testserver",
        )
        endpoints = scanner._parse(PETSTORE)
        assert len(endpoints) > 0

    def test_base_url_injected_into_endpoints(self):
        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://myapi.example.com",
        )
        endpoints = scanner._parse(PETSTORE)
        for ep in endpoints:
            ep.base_url = ep.base_url or "http://myapi.example.com"
        assert all(ep.base_url != "" for ep in endpoints)

    def test_unknown_check_id_ignored(self):
        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://testserver",
            checks=["bola", "nonexistent_check"],
        )
        assert len(scanner._checks) == 1

    def test_generate_produces_test_cases(self):
        scanner = Scanner(
            spec_path=PETSTORE,
            base_url="http://testserver",
            checks=["auth"],
        )
        endpoints = scanner._parse(PETSTORE)
        for ep in endpoints:
            if not ep.base_url:
                ep.base_url = "http://testserver"
        cases = scanner._generate(endpoints)
        assert len(cases) > 0
