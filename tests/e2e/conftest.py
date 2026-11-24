"""End-to-end harness: run the real Scanner against a respx-mocked API whose security
behaviour is configurable, so tests can assert on false positives as well as detections."""
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
import respx

FIXTURES = Path(__file__).parent.parent / "fixtures"
PETSTORE = str(FIXTURES / "petstore.yaml")
REGISTER = str(FIXTURES / "register.yaml")  # POST /users/register (no id/Location) + GET /users/{username}
BASE = "http://testserver"

TOKENS = {"token-alice": "alice", "token-bob": "bob"}
API_KEYS = {"key-alice": "alice", "key-bob": "bob"}
BASIC = {"alice:pw-alice": "alice", "bob:pw-bob": "bob"}

# A weak HS256 secret that IS in the bundled wordlist (rank 2836), so the offline crack finds it.
JWT_SECRET = "random"
# A secret the wordlist does not contain, so the offline crack fails against it.
STRONG_SECRET = "Xq7#9fL2_pR4vN8tZ1bK6mW3yH5sJ0cDgEa"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(sub: str = "alice", secret: str = JWT_SECRET, exp_in: int = 3600) -> str:
    """A real HS256 JWT for `sub`, signed with `secret`. Used as the configured credential."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": sub, "iat": now, "exp": now + exp_in}).encode())
    signing = f"{header}.{payload}".encode()
    sig = _b64url(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@dataclass
class MockAPI:
    """Petstore-shaped API. Pets 1 (alice) and 2 (bob) exist.

    accept_any_token: any non-empty bearer value authenticates as alice (signature never verified).
    enforce_ownership: /pets/{id} returns 403 unless the caller owns the pet (no BOLA).
    rate_limit: per-(method, path) request budget before 429s; None disables it.
    rate_limited_paths: restrict rate_limit to these paths; None means every path.
    rate_limit_global: one budget for all requests (per-client limiter) instead of per (method, path).
    mass_assignment: "none" (allowlisted fields), "reflect" (echoes the body, stores nothing) or
        "persist" (binds the whole body to the new pet, returns 201 + Location without echoing).
        Also applies to POST /users/register, which answers {"message": ...} with no id or Location
        ("persist" stores the whole body, otherwise only username/email); GET /users/{username} reads it back.
    """
    accept_any_token: bool = False
    # JWT bearer handling: None = plain token map (default); "verify" = check HS256 sig + exp against
    # JWT_SECRET (secure); "accept_unverified" = decode claims, skip signature/alg/exp checks (vulnerable).
    jwt_mode: str | None = None
    jwt_secret: str = JWT_SECRET  # the HS256 key the API verifies against when jwt_mode == "verify"
    enforce_ownership: bool = True
    rate_limit: int | None = None
    rate_limited_paths: set[str] | None = None
    rate_limit_global: bool = False
    scheme: str | None = None  # "bearer" | "apikey" | "basic": honour only that one (catches wrong-scheme sends)
    mass_assignment: str = "none"
    store_created: bool = False  # "none" mode: keep the pet POST /pets creates (readable at /pets/3)
    pets: dict[str, dict] = field(default_factory=lambda: {
        "1": {"id": 1, "name": "rex", "owner": "alice"},
        "2": {"id": 2, "name": "tom", "owner": "bob"},
    })
    users: dict[str, dict] = field(default_factory=dict)
    hits: dict[tuple[str, str], int] = field(default_factory=dict)
    auth_seen: list[str | None] = field(default_factory=list)  # Authorization header of every request
    statuses: dict[tuple[str, str], list[int]] = field(default_factory=dict)  # responses per (method, path)

    def _user(self, request: httpx.Request) -> str | None:
        """Bearer token-<user>, X-API-Key key-<user>, or Basic <user>:pw-<user>."""
        value = request.headers.get("authorization", "")
        api_key = request.headers.get("x-api-key", "")
        allowed = lambda s: self.scheme in (None, s)  # noqa: E731
        if allowed("bearer") and self.jwt_mode and value.startswith("Bearer "):
            return self._jwt_user(value[7:].strip())
        if allowed("bearer") and value.startswith("Bearer ") and value[7:].strip():
            presented, user = value[7:].strip(), TOKENS.get(value[7:].strip())
        elif allowed("apikey") and api_key:
            presented, user = api_key, API_KEYS.get(api_key)
        elif allowed("basic") and value.startswith("Basic ") and value[6:].strip():
            try:
                presented = base64.b64decode(value[6:]).decode()
            except ValueError:
                return None
            user = BASIC.get(presented)
        else:
            return None
        if user:
            return user
        return "alice" if self.accept_any_token and presented else None

    def _jwt_user(self, token: str) -> str | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        except Exception:
            return None
        if self.jwt_mode == "verify":
            if header.get("alg") != "HS256":
                return None
            signing = f"{parts[0]}.{parts[1]}".encode()
            try:
                sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            except Exception:
                return None
            expected = hmac.new(self.jwt_secret.encode(), signing, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                return None
            if payload.get("exp", 0) < time.time():
                return None
        # "accept_unverified": decode the claims, trust them — no signature/alg/exp enforcement.
        sub = payload.get("sub")
        return sub if sub in ("alice", "bob") else None

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
            if self.mass_assignment == "reflect":
                return httpx.Response(201, json={**body, "id": 3, "owner": user})
            if self.mass_assignment == "persist":
                self.pets["3"] = {**body, "id": 3, "owner": user}
                return httpx.Response(201, json={"status": "created"}, headers={"Location": "/pets/3"})
            created = {"id": 3, "name": body["name"], "owner": user}
            if self.store_created:
                self.pets["3"] = created
            return httpx.Response(201, json=created)
        if path == "/users/register" and request.method == "POST":
            body = json.loads(request.content or b"{}")
            stored = body if self.mass_assignment == "persist" else {k: body.get(k) for k in ("username", "email")}
            self.users[str(body.get("username"))] = {"role": "user", **stored}
            return httpx.Response(200, json={"message": "registered", "status": "success"})
        if path.startswith("/users/") and request.method == "GET":
            found = self.users.get(path.removeprefix("/users/"))
            if found is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={k: v for k, v in found.items() if k != "password"})
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
