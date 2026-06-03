import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from apifuzz.models.endpoint import AuthConfig


@dataclass
class TestCase:
    method: str
    url: str
    headers: dict[str, str]
    params: dict[str, str]          # query params
    body: dict[str, Any] | None
    label: str                      # human-readable: "BOLA: GET /users/2 as user-A"
    check_id: str                   # "bola" | "auth" | "mass_assignment" | "ssrf" | "injection" | "rate_limit" | "cors"
    extra: dict[str, Any] = field(default_factory=dict)  # check-specific metadata


@dataclass
class TestResult:
    test_case: TestCase
    status_code: int
    response_body: str
    response_headers: dict[str, str]
    elapsed_ms: float
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @property
    def is_success(self) -> bool:
        return not self.is_error and 200 <= self.status_code < 300


class Executor:
    def __init__(
        self,
        auth: AuthConfig,
        concurrency: int = 10,
        rate_limit_rps: float = 10.0,
        timeout: float = 15.0,
    ):
        self.auth = auth
        self._sem = asyncio.Semaphore(concurrency)
        self._min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self._timeout = timeout
        self._last_request_time: float = 0.0

    async def run(self, test_cases: list[TestCase]) -> list[TestResult]:
        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            verify=False,  # target APIs may use self-signed certs
        ) as client:
            tasks = [self._run_one(client, tc) for tc in test_cases]
            return await asyncio.gather(*tasks)

    async def _run_one(self, client: httpx.AsyncClient, tc: TestCase) -> TestResult:
        async with self._sem:
            await self._rate_limit()
            headers = self._inject_auth(dict(tc.headers))
            try:
                start = time.monotonic()
                resp = await client.request(
                    method=tc.method,
                    url=tc.url,
                    headers=headers,
                    params=tc.params or None,
                    json=tc.body if tc.body else None,
                )
                elapsed = (time.monotonic() - start) * 1000
                return TestResult(
                    test_case=tc,
                    status_code=resp.status_code,
                    response_body=resp.text[:8192],
                    response_headers=dict(resp.headers),
                    elapsed_ms=elapsed,
                )
            except Exception as e:
                return TestResult(
                    test_case=tc,
                    status_code=0,
                    response_body="",
                    response_headers={},
                    elapsed_ms=0.0,
                    error=str(e),
                )

    async def _rate_limit(self) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        wait = self._min_interval - (now - self._last_request_time)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_time = time.monotonic()

    def _inject_auth(self, headers: dict[str, str]) -> dict[str, str]:
        match self.auth.type:
            case "bearer":
                headers["Authorization"] = f"Bearer {self.auth.token}"
            case "apikey":
                headers[self.auth.header_name] = self.auth.token
            case "basic":
                creds = base64.b64encode(self.auth.token.encode()).decode()
                headers["Authorization"] = f"Basic {creds}"
            case _:
                pass  # none — no auth header
        return headers
