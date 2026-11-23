"""Mask credentials before anything leaves the scanner (reports, SARIF, console)."""
import base64
from collections.abc import Iterable

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


def mask(value: str) -> str:
    """First 4 characters + ****; short values are masked entirely."""
    return value[:4] + "****" if len(value) > 8 else "****"


def redact_headers(headers: dict[str, str], extra_names: Iterable[str] = ()) -> dict[str, str]:
    names = SENSITIVE_HEADERS | {n.lower() for n in extra_names}
    return {k: mask(v) if k.lower() in names else v for k, v in headers.items()}


def secrets_for(*tokens: str) -> list[str]:
    """Every form a configured credential can take on the wire: raw, and base64 for basic auth."""
    out: list[str] = []
    for t in tokens:
        if t and len(t) >= 4:
            out += [t, base64.b64encode(t.encode()).decode()]
    return sorted(set(out), key=len, reverse=True)  # longest first, so a substring can't pre-empt it


def scrub(text: str, secrets: Iterable[str]) -> str:
    for s in secrets:
        if s in text:
            text = text.replace(s, mask(s))
    return text
