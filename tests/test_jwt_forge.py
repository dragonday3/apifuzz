"""Phase 6.1: stdlib JWT forging + offline HS256 cracking."""
import base64
import hashlib
import hmac
import json
import time

from fuzzowl import jwt_forge


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_token(secret="s3cr3t", alg="HS256", claims=None) -> str:
    claims = claims or {"sub": "1"}
    header = _b64({"alg": alg, "typ": "JWT"})
    payload = _b64(claims)
    signing = f"{header}.{payload}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


class TestStructure:
    def test_is_jwt_true(self):
        assert jwt_forge.is_jwt(make_token())

    def test_is_jwt_false(self):
        assert not jwt_forge.is_jwt("not.a.jwt")  # header is not valid base64 JSON
        assert not jwt_forge.is_jwt("only.two")
        assert not jwt_forge.is_jwt("token-alice")

    def test_decode_payload(self):
        assert jwt_forge.decode_payload(make_token(claims={"sub": "alice"}))["sub"] == "alice"


class TestForgeries:
    def test_unsigned_keeps_claims_changes_signature(self):
        tok = make_token(claims={"sub": "alice"})
        forged = jwt_forge.forge_unsigned(tok)
        assert jwt_forge.decode_payload(forged)["sub"] == "alice"
        assert forged.rsplit(".", 1)[1] != tok.rsplit(".", 1)[1]
        # header + payload untouched
        assert forged.rsplit(".", 1)[0] == tok.rsplit(".", 1)[0]

    def test_kid_traversal_header_and_null_key(self):
        forged = jwt_forge.forge_kid_traversal(make_token(claims={"sub": "alice"}))
        header = jwt_forge.decode_header(forged)
        assert header["kid"] == "../../../../../../dev/null"
        assert header["alg"] == "HS256"
        # verifiably signed HMAC-SHA256 with the null key b"\x00" (== base64 "AA==")
        assert base64.b64encode(b"\x00").decode() == "AA=="
        assert jwt_forge.crack_hs256(forged, ["\x00"]) == "\x00"
        assert jwt_forge.decode_payload(forged)["sub"] == "alice"


class TestCracking:
    def test_hit(self):
        assert jwt_forge.crack_hs256(make_token("letmein"), ["x", "letmein", "y"]) == "letmein"

    def test_miss(self):
        assert jwt_forge.crack_hs256(make_token("letmein"), ["x", "y"]) is None

    def test_non_hs256_not_cracked(self):
        assert jwt_forge.crack_hs256(make_token(alg="RS256"), ["anything"]) is None

    def test_bundled_wordlist_contains_vampi_secret(self):
        # Honesty: VAmPI signs with "random"; it is in the bundled list (crAPI's "crapi" is not).
        wl = jwt_forge.load_default_wordlist()
        assert "random" in wl
        assert "crapi" not in wl
        assert jwt_forge.crack_hs256(make_token("random"), wl) == "random"

    def test_wordlist_cached(self):
        assert jwt_forge.load_default_wordlist() is jwt_forge.load_default_wordlist()


class TestResign:
    def test_resign_valid_is_signed_with_key_and_not_expired(self):
        tok = make_token("weak", claims={"sub": "alice", "iat": 1, "exp": 1})
        rs = jwt_forge.resign_hs256(tok, "weak")
        assert jwt_forge.crack_hs256(rs, ["weak"]) == "weak"
        assert jwt_forge.decode_payload(rs)["sub"] == "alice"
        assert jwt_forge.decode_payload(rs)["exp"] > time.time()

    def test_resign_expired_has_past_exp(self):
        tok = make_token("weak", claims={"sub": "alice", "exp": 9999999999})
        ex = jwt_forge.resign_hs256(tok, "weak", expired=True)
        assert jwt_forge.decode_payload(ex)["exp"] < time.time()
        assert jwt_forge.crack_hs256(ex, ["weak"]) == "weak"
