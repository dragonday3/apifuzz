import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any, Literal

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
    # default: inject configured auth | none: strip all auth headers | override: send tc.headers as-is
    auth_mode: Literal["default", "none", "override"] = "default"
    throttle: bool = True  # False: skip the global rps limiter (rate-limit bursts); semaphore still applies


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
        self._rate_lock = asyncio.Lock()

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
            if tc.throttle:
                await self._rate_limit()
            headers = self._apply_auth(dict(tc.headers), tc.auth_mode)
            start = time.monotonic()
            try:
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
                    elapsed_ms=(time.monotonic() - start) * 1000,  # time-based SQLi counts timeouts
                    error=f"{type(e).__name__}: {e}",
                )

    async def _rate_limit(self) -> None:
        if self._min_interval <= 0:
            return
        # Lock held across the sleep: serialises slots so concurrent coroutines can't share one timestamp.
        async with self._rate_lock:
            wait = self._min_interval - (time.monotonic() - self._last_request_time)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.monotonic()

    def _apply_auth(self, headers: dict[str, str], mode: str) -> dict[str, str]:
        if mode == "override":
            return headers
        if mode == "none":
            strip = {"authorization", self.auth.header_name.lower()}
            return {k: v for k, v in headers.items() if k.lower() not in strip}
        headers.update(auth_headers(self.auth.type, self.auth.token, self.auth.header_name))
        return headers


def auth_headers(auth_type: str, token: str, header_name: str = "Authorization") -> dict[str, str]:
    """Credential header for one auth scheme. Shared by the executor and checks that need a
    second user's credential in the same scheme (BOLA cross-user)."""
    match auth_type:
        case "bearer":
            return {"Authorization": f"Bearer {token}"}
        case "apikey":
            return {header_name: token}
        case "basic":
            return {"Authorization": f"Basic {base64.b64encode(token.encode()).decode()}"}
        case _:
            return {}
