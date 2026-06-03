import asyncio
import base64
import pytest
import respx
import httpx
from apifuzz.executor import Executor, TestCase, TestResult
from apifuzz.models.endpoint import AuthConfig


def make_tc(method="GET", url="https://api.example.com/users", check_id="test", label="test", body=None, params=None, headers=None):
    return TestCase(
        method=method,
        url=url,
        headers=headers or {},
        params=params or {},
        body=body,
        label=label,
        check_id=check_id,
    )


class TestExecutorAuthInjection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_no_auth(self):
        route = respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200, json={"users": []}))
        executor = Executor(auth=AuthConfig(type="none"))
        results = await executor.run([make_tc()])
        assert results[0].status_code == 200
        assert "Authorization" not in route.calls[0].request.headers

    @respx.mock
    @pytest.mark.asyncio
    async def test_bearer_auth_injected(self):
        route = respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200))
        executor = Executor(auth=AuthConfig(type="bearer", token="mytoken"))
        await executor.run([make_tc()])
        assert route.calls[0].request.headers["authorization"] == "Bearer mytoken"

    @respx.mock
    @pytest.mark.asyncio
    async def test_apikey_auth_injected(self):
        route = respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200))
        executor = Executor(auth=AuthConfig(type="apikey", token="secret", header_name="X-API-Key"))
        await executor.run([make_tc()])
        assert route.calls[0].request.headers["x-api-key"] == "secret"

    @respx.mock
    @pytest.mark.asyncio
    async def test_basic_auth_injected(self):
        route = respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200))
        executor = Executor(auth=AuthConfig(type="basic", token="user:pass"))
        await executor.run([make_tc()])
        expected = "Basic " + base64.b64encode(b"user:pass").decode()
        assert route.calls[0].request.headers["authorization"] == expected


class TestExecutorResponseMapping:
    @respx.mock
    @pytest.mark.asyncio
    async def test_status_code_captured(self):
        respx.get("https://api.example.com/users").mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
        executor = Executor(auth=AuthConfig())
        results = await executor.run([make_tc()])
        assert results[0].status_code == 403

    @respx.mock
    @pytest.mark.asyncio
    async def test_response_body_captured(self):
        respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200, json={"name": "Alice"}))
        executor = Executor(auth=AuthConfig())
        results = await executor.run([make_tc()])
        assert "Alice" in results[0].response_body

    @respx.mock
    @pytest.mark.asyncio
    async def test_elapsed_ms_positive(self):
        respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200))
        executor = Executor(auth=AuthConfig())
        results = await executor.run([make_tc()])
        assert results[0].elapsed_ms >= 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_is_success_true_on_2xx(self):
        respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200))
        executor = Executor(auth=AuthConfig())
        results = await executor.run([make_tc()])
        assert results[0].is_success is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_is_success_false_on_4xx(self):
        respx.get("https://api.example.com/users").mock(return_value=httpx.Response(401))
        executor = Executor(auth=AuthConfig())
        results = await executor.run([make_tc()])
        assert results[0].is_success is False


class TestExecutorErrorHandling:
    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_captured(self):
        respx.get("https://api.example.com/users").mock(side_effect=httpx.ConnectError("refused"))
        executor = Executor(auth=AuthConfig())
        results = await executor.run([make_tc()])
        assert results[0].is_error is True
        assert results[0].error is not None
        assert results[0].status_code == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_multiple_test_cases(self):
        respx.get("https://api.example.com/users").mock(return_value=httpx.Response(200))
        respx.post("https://api.example.com/users").mock(return_value=httpx.Response(201))
        executor = Executor(auth=AuthConfig())
        tcs = [make_tc(method="GET"), make_tc(method="POST")]
        results = await executor.run(tcs)
        assert len(results) == 2
        codes = {r.status_code for r in results}
        assert codes == {200, 201}


class TestTestCaseDataclass:
    def test_extra_field_default_empty(self):
        tc = make_tc()
        assert tc.extra == {}

    def test_extra_field_set(self):
        tc = TestCase(method="GET", url="https://x.com/a", headers={}, params={},
                      body=None, label="test", check_id="bola", extra={"user_id": 42})
        assert tc.extra["user_id"] == 42

    def test_is_error_false_when_no_error(self):
        tc = make_tc()
        r = TestResult(tc, 200, '{}', {}, 100.0, None)
        assert r.is_error is False

    def test_is_error_true_when_error(self):
        tc = make_tc()
        r = TestResult(tc, 0, '', {}, 0.0, "Connection refused")
        assert r.is_error is True
