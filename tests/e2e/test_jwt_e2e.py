"""Phase 6.1 e2e: JWT attacks against a mock API.

Three servers:
- accept_unverified: trusts JWT claims without checking the signature -> every attack lands.
- verify + strong secret: checks HS256 signature and expiry, secret not in the wordlist -> nothing lands.
- verify + weak secret: checks signatures properly but the key is guessable -> the weak-key forgery
  still lands (that is the whole point), while signature-bypass forgeries are rejected.
"""
from apifuzz.models.endpoint import AuthConfig
from apifuzz.scanner import Scanner

from .conftest import BASE, PETSTORE, STRONG_SECRET, make_jwt

JWT_RULES = {
    "APIFUZZ-AUTH-JWT_ALG_NO",   # alg:none
    "APIFUZZ-AUTH-JWT_UNSIGN",   # garbage signature
    "APIFUZZ-AUTH-JWT_KID_TR",   # kid path traversal
    "APIFUZZ-AUTH-JWT_WEAK_K",   # weak HS256 secret cracked offline
    "APIFUZZ-AUTH-JWT_EXPIRE",   # expired token
}
BYPASS_RULES = {"APIFUZZ-AUTH-JWT_ALG_NO", "APIFUZZ-AUTH-JWT_UNSIGN", "APIFUZZ-AUTH-JWT_KID_TR"}


async def scan(mock_api, token, **api_kwargs):
    mock_api(**api_kwargs)
    auth = AuthConfig(type="bearer", token=token)
    return await Scanner(PETSTORE, BASE, auth=auth, checks=["auth"], rate_limit_rps=0).run()


async def test_vulnerable_api_flags_every_jwt_attack(mock_api):
    findings = await scan(mock_api, make_jwt("alice"), jwt_mode="accept_unverified")
    rules = {f.rule_id for f in findings}
    assert JWT_RULES <= rules
    jwt_findings = [f for f in findings if f.rule_id in JWT_RULES]
    assert jwt_findings and all(f.confidence == "firm" for f in jwt_findings)


async def test_strong_secret_verifying_api_has_no_jwt_findings(mock_api):
    # Token and server share a strong secret: forgeries fail verification, crack fails -> nothing.
    token = make_jwt("alice", STRONG_SECRET)
    findings = await scan(mock_api, token, jwt_mode="verify", jwt_secret=STRONG_SECRET)
    assert [f for f in findings if f.rule_id in JWT_RULES] == []


async def test_weak_secret_verifying_api_flagged_by_weak_key_only(mock_api):
    # Signatures ARE verified, but the key "random" is guessable: the re-signed token is valid and
    # accepted (weak-key finding), while alg:none/garbage-sig/kid are rejected, and the expired
    # re-signed token is rejected because expiry is enforced.
    findings = await scan(mock_api, make_jwt("alice"), jwt_mode="verify")
    rules = {f.rule_id for f in findings}
    assert "APIFUZZ-AUTH-JWT_WEAK_K" in rules
    assert not (BYPASS_RULES & rules)
    assert "APIFUZZ-AUTH-JWT_EXPIRE" not in rules


async def test_cracked_secret_never_printed_in_full(mock_api):
    findings = await scan(mock_api, make_jwt("alice"), jwt_mode="accept_unverified")
    weak = [f for f in findings if f.rule_id == "APIFUZZ-AUTH-JWT_WEAK_K"]
    assert weak
    for f in weak:
        assert "random" not in f.evidence          # the guessed key is masked
        assert "signing key guessed" in f.evidence
