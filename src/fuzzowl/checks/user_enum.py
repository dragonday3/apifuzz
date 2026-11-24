import random
import re
import secrets
import string

from fuzzowl.checks.base import BaseCheck
from fuzzowl.executor import TestCase
from fuzzowl.models.endpoint import AuthConfig, Endpoint

_USER_KEY = re.compile(r"^(user(name)?|login|email|e-?mail|account)$", re.IGNORECASE)
_PASS_KEY = re.compile(r"^(pass(word)?|passwd|pwd)$", re.IGNORECASE)
# Login-like operations only: a signup form says "user already exists" by design, and probing it creates
# accounts (which then made the "unknown" usernames real).
_LOGIN_HINT = re.compile(r"(log-?in|sign-?in|auth|session|token)", re.IGNORECASE)
WRONG_PASSWORD = "fuzzowl-Wr0ng-passw0rd"


def lookalike(value: str, rng: random.Random) -> str:
    """Same length, case and character classes as `value`, different letters/digits: an unknown user that
    passes the same format validation as the real one (emails keep their domain)."""
    local, at, domain = value.partition("@")
    while True:
        out = "".join(rng.choice(string.ascii_lowercase) if c.islower() else
                      rng.choice(string.ascii_uppercase) if c.isupper() else
                      rng.choice(string.digits) if c.isdigit() else c for c in local)
        if out.lower() != local.lower() or not any(c.isalnum() for c in local):
            return out + at + domain


class UserEnumCheck(BaseCheck):
    """Login user enumeration (OWASP API2): a real username and an unknown one, both with a wrong password,
    must get the same answer. Two unknown usernames are sent as a control for per-request noise."""

    check_id = "user_enum"
    name = "User Enumeration on Login (OWASP API2)"

    def generate(self, endpoint: Endpoint, auth: AuthConfig) -> list[TestCase]:
        body = endpoint.body_example
        where = f"{endpoint.path} {endpoint.operation_id} {endpoint.summary}"
        if endpoint.method != "POST" or not isinstance(body, dict) or not _LOGIN_HINT.search(where):
            return []
        user_key = next((k for k in body if _USER_KEY.match(k)), None)
        pass_key = next((k for k in body if _PASS_KEY.match(k)), None)
        if not user_key or not pass_key or not isinstance(body[user_key], str):
            return []
        known = body[user_key]
        if not any(c.isalnum() for c in known):
            return []
        # Fresh lookalikes each scan: same format as the known user (so input validation answers alike),
        # random letters (a fixed name could have been registered by an earlier run).
        rng = random.Random(secrets.randbits(64))
        unknown: list[str] = []
        while len(unknown) < 2:
            candidate = lookalike(known, rng)
            if candidate not in unknown:
                unknown.append(candidate)
        users = [("known", known)] + [(f"unknown{i}", u) for i, u in enumerate(unknown, 1)]
        pair_id = f"{endpoint.method} {endpoint.path}"
        return [TestCase(
            method="POST",
            url=self._build_url(endpoint),
            headers={},
            params={},
            body={**body, user_key: user, pass_key: WRONG_PASSWORD},
            label=f"UserEnum: POST {endpoint.path} [{role} {user_key}, wrong password]",
            check_id=self.check_id,
            extra={"strategy": "enum_pair", "pair_id": pair_id, "polarity": role, "user": user},
            auth_mode="none",  # a login form is used anonymously
        ) for role, user in users]
