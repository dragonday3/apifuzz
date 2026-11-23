"""End-to-end harness: run the real Scanner against a respx-mocked API whose security
behaviour is configurable, so tests can assert on false positives as well as detections."""
import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
import respx

FIXTURES = Path(__file__).parent.parent / "fixtures"
PETSTORE = str(FIXTURES / "petstore.yaml")
BASE = "http://testserver"

TOKENS = {"token-alice": "alice", "token-bob": "bob"}


@dataclass
class MockAPI:
    """Petstore-shaped API. Pets 1 (alice) and 2 (bob) exist.

    accept_any_token: any non-empty bearer value authenticates as alice (signature never verified).
    enforce_ownership: /pets/{id} returns 403 unless the caller owns the pet (no BOLA).
    rate_limit: per-(method, path) request budget before 429s; None disables it.
    rate_limited_paths: restrict rate_limit to these paths; None means every path.
    rate_limit_global: one budget for all requests (per-client limiter) instead of per (method, path).
    """
    accept_any_token: bool = False
    enforce_ownership: bool = True
    rate_limit: int | None = None
    rate_limited_paths: set[str] | None = None
    rate_limit_global: bool = False
    pets: dict[str, dict] = field(default_factory=lambda: {
        "1": {"id": 1, "name": "rex", "owner": "alice"},
        "2": {"id": 2, "name": "tom", "owner": "bob"},
    })
    hits: dict[tuple[str, str], int] = field(default_factory=dict)
    auth_seen: list[str | None] = field(default_factory=list)  # Authorization header of every request
    statuses: dict[tuple[str, str], list[int]] = field(default_factory=dict)  # responses per (method, path)

    def _user(self, request: httpx.Request) -> str | None:
        value = request.headers.get("authorization", "")
        if not value.startswith("Bearer ") or not value[7:].strip():
            return None
        token = value[7:].strip()
        if token in TOKENS:
            return TOKENS[token]
        return "alice" if self.accept_any_token else None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        response = self._handle(request)
        self.statuses.setdefault((request.method, request.url.path), []).append(response.status_code)
        return response

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = (request.method, path)
        self.hits[key] = self.hits.get(key, 0) + 1
        self.auth_seen.append(request.headers.get("authorization"))
        limited = self.rate_limited_paths is None or path in self.rate_limited_paths
        used = sum(self.hits.values()) if self.rate_limit_global else self.hits[key]
        if self.rate_limit is not None and limited and used > self.rate_limit:
            return httpx.Response(429, headers={"Retry-After": "1"})

        if request.method == "OPTIONS":
            return httpx.Response(204)

        user = self._user(request)
        if user is None:
            return httpx.Response(401, json={"error": "unauthorized"})

        if path == "/pets" and request.method == "GET":
            return httpx.Response(200, json=[p for p in self.pets.values() if p["owner"] == user])
        if path == "/pets" and request.method == "POST":
            try:
                body = json.loads(request.content or b"{}")
            except ValueError:
                return httpx.Response(400, json={"error": "bad json"})
            if not isinstance(body, dict) or not isinstance(body.get("name"), str):
                return httpx.Response(422, json={"error": "name required"})
            return httpx.Response(201, json={"id": 3, "name": body["name"], "owner": user})
        if path.startswith("/pets/"):
            pet = self.pets.get(path.removeprefix("/pets/"))
            if pet is None:
                return httpx.Response(404, json={"error": "not found"})
            if self.enforce_ownership and pet["owner"] != user:
                return httpx.Response(403, json={"error": "forbidden"})
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json=pet)
        return httpx.Response(404)


@pytest.fixture
def mock_api():
    """Yield a factory: mock_api(**MockAPI kwargs) installs that API on BASE for the test."""
    with respx.mock(assert_all_called=False) as router:
        def install(**kwargs) -> MockAPI:
            api = MockAPI(**kwargs)
            router.route(host="testserver").mock(side_effect=api)
            return api
        yield install
