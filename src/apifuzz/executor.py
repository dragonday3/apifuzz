import asyncio
import base64
import random
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
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
    request_headers: dict[str, str] = field(default_factory=dict)  # as sent (auth applied); redact before output
    truncated: bool = False  # body longer than MAX_BODY; detectors only saw the first MAX_BODY characters

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @property
    def is_success(self) -> bool:
        return not self.is_error and 200 <= self.status_code < 300


MAX_BODY = 8192
MAX_RETRY_WAIT = 30.0  # seconds; a Retry-After longer than this is capped


class OutOfScope(httpx.RequestError):
    """Raised by the request hook for any URL (including a redirect target) outside the target origin."""


class RequestBudget:
    """--max-requests: shared by every executor of one scan; retries count too."""

    def __init__(self, limit: int | None = None):
        self.limit, self.used, self.denied = limit, 0, 0

    def take(self) -> bool:
        if self.limit is not None and self.used >= self.limit:
            self.denied += 1
            return False
        self.used += 1
        return True


_DEFAULT_PORTS = {"http": 80, "https": 443}


def origin(url: str) -> tuple[str, str, int | None]:
    """(scheme, ASCII host, port) the way httpx sends it: default ports filled in, IDN hosts punycoded."""
    u = httpx.URL(url)
    return u.scheme, u.raw_host.decode("ascii").lower(), u.port or _DEFAULT_PORTS.get(u.scheme)


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("retry-after", "").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError, OverflowError):
        return None


class Executor:
    def __init__(
        self,
        auth: AuthConfig,
        concurrency: int = 10,
        rate_limit_rps: float = 10.0,
        timeout: float = 15.0,
        *,
        verify: bool = True,
        proxy: str | None = None,
        scope: str | None = None,
        budget: RequestBudget | None = None,
        retries: int = 2,
    ):
        self.auth = auth
        self._sem = asyncio.Semaphore(concurrency)
        self._min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self._timeout = timeout
        self._last_request_time: float = 0.0
        self._rate_lock = asyncio.Lock()
        self._verify, self._proxy = verify, proxy
        self._scope = origin(scope) if scope else None
        self._budget = budget or RequestBudget()
        self._retries = max(0, retries)

    async def run(self, test_cases: list[TestCase]) -> list[TestResult]:
        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,  # each hop passes the scope hook, so off-host redirects fail
            verify=self._verify,
            proxy=self._proxy,
            event_hooks={"request": [self._check_scope]},
        ) as client:
            tasks = [self._run_one(client, tc) for tc in test_cases]
            return await asyncio.gather(*tasks)

    async def _check_scope(self, request: httpx.Request) -> None:
        if self._scope and origin(str(request.url)) != self._scope:
            scheme, host, port = self._scope
            raise OutOfScope(f"{request.url} is outside the target {scheme}://{host}:{port}", request=request)

    async def _run_one(self, client: httpx.AsyncClient, tc: TestCase) -> TestResult:
        async with self._sem:
            headers = self._apply_auth(dict(tc.headers), tc.auth_mode)
            # Bursts measure the target's limiter: never retried, and 429s are the signal.
            attempts = 1 + (self._retries if tc.throttle else 0)
            result = None
            for attempt in range(attempts):
                if tc.throttle:
                    await self._rate_limit()
                result, resp = await self._send(client, tc, headers)
                # A 503'd POST may still have been processed: only 429 ("not processed") is retried for it.
                retry_on = (429, 503) if tc.method in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE") else (429,)
                if resp is None or resp.status_code not in retry_on or attempt == attempts - 1:
                    break
                wait = _retry_after(resp)
                if wait is None:
                    wait = 0.5 * 2 ** attempt + random.uniform(0, 0.5)  # exponential backoff with jitter
                await asyncio.sleep(min(wait, MAX_RETRY_WAIT))
            assert result is not None
            return result

    async def _send(self, client: httpx.AsyncClient, tc: TestCase,
                    headers: dict[str, str]) -> tuple[TestResult, httpx.Response | None]:
        if not self._budget.take():
            return TestResult(test_case=tc, status_code=0, response_body="", response_headers={}, elapsed_ms=0.0,
                              error="BudgetExhausted: --max-requests reached", request_headers=headers), None
        start = time.monotonic()
        try:
            resp = await client.request(
                method=tc.method,
                url=tc.url,
                headers=headers,
                params=tc.params or None,
                json=tc.body if tc.body else None,
            )
        except Exception as e:
            return TestResult(
                test_case=tc,
                status_code=0,
                response_body="",
                response_headers={},
                elapsed_ms=(time.monotonic() - start) * 1000,  # time-based SQLi counts timeouts
                error=f"{type(e).__name__}: {e}",
                request_headers=headers,
            ), None
        text = resp.text
        return TestResult(
            test_case=tc,
            status_code=resp.status_code,
            response_body=text[:MAX_BODY],
            response_headers=dict(resp.headers),
            elapsed_ms=(time.monotonic() - start) * 1000,
            request_headers=headers,
            truncated=len(text) > MAX_BODY,
        ), resp

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
