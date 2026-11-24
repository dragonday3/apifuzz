import json
import re
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit

from fuzzowl.checks.base import build_url
from fuzzowl.checks.bola import MISSING_ID
from fuzzowl.checks.injection import CMD_CANARY, SQLI_SLEEP_SECONDS, SSTI_PRODUCT
from fuzzowl.checks.redos import REDOS_N
from fuzzowl.executor import TestCase, TestResult, auth_headers
from fuzzowl.models.endpoint import AuthConfig, Endpoint
from fuzzowl.redact import mask, redact_headers
from fuzzowl.models.finding import Confidence, Finding, OWASPCategory, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]

_SQLI_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|syntax error|pg_exec|sqlite3\.OperationalError|unrecognized token"
    r"|SQLSTATE\[|Microsoft OLE DB|ODBC SQL|Unclosed quotation mark|Incorrect syntax near)",
    re.IGNORECASE,
)
# Markers only a real metadata/file read returns; none of them occurs in the SSRF payloads themselves.
_SSRF_METADATA = re.compile(r"(ami-id|instance-id|root:x:0:0|computeMetadata|\"AccessKeyId\")", re.IGNORECASE)
_CMD_UID = re.compile(r"uid=\d+\([\w-]+\) gid=\d+")
# Operator reached the query engine. Not E11000 (duplicate key) or CastError (type validation
# rejecting the object): both are normal on a secure Mongo API.
_NOSQL_ERRORS = re.compile(r"(MongoError|MongoServerError|unknown operator|\$where)")

_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}

# ReDoS verdict: every evil probe must be this much slower than the slowest control (both conditions).
REDOS_MIN_DELAY_MS = 2000
REDOS_FACTOR = 5


_IDENTIFYING_KEY = re.compile(r"^(id|uuid|username|email|.+_id|.+Id)$")
# Per-request values that change on every call and say nothing about which object it is.
_VOLATILE_KEY = re.compile(r"(request|trace|correlation|session|span|transaction|nonce)", re.IGNORECASE)
_WRAPPERS = ("data", "user", "result")


def _json(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return None


def _unwrap(doc: Any) -> Any:
    """{"data": {...}, "meta": {...}} -> the inner object."""
    if isinstance(doc, dict):
        for key in _WRAPPERS:
            if isinstance(doc.get(key), dict):
                return doc[key]
    return doc


def _identity(doc: dict, extra_keys: tuple[str, ...] = ()) -> dict[str, Any]:
    return {k: v for k, v in doc.items()
            if (_IDENTIFYING_KEY.match(k) or k in extra_keys) and not _VOLATILE_KEY.search(k)
            and v not in (None, "")}


def _same_object(a: str, b: str, extra_keys: tuple[str, ...] = ()) -> bool:
    """Do two response bodies describe the same object? Same identifying fields (id, username, the probed
    path param...) when both have some, else an identical body. Empty bodies (204s) prove nothing."""
    if not a.strip() or not b.strip():
        return False
    ja, jb = _unwrap(_json(a)), _unwrap(_json(b))
    if isinstance(ja, dict) and isinstance(jb, dict):
        ia, ib = _identity(ja, extra_keys), _identity(jb, extra_keys)
        common = ia.keys() & ib.keys()
        if common:
            return all(ia[k] == ib[k] for k in common)
    return a == b


def _listed_in(body: str, listings: list[TestResult], extra_keys: tuple[str, ...] = ()) -> TestResult | None:
    """The first listing response containing the object `body` describes: an object anywhere in it (items,
    nested ones) carrying every identifying field of `body` with the same value. None without identifying
    fields: a bare body can't be found in a list."""
    obj = _unwrap(_json(body))
    ident = _identity(obj, extra_keys) if isinstance(obj, dict) else {}
    if not ident:
        return None
    for listing in listings:
        doc = _json(listing.response_body)
        if doc is None and listing.truncated:
            # A listing longer than --max-body is cut mid-JSON and won't parse: look for every identifying
            # field as a `"key": value` pair in the text that did arrive (crAPI's 30 recent posts are ~12 KB).
            # Key and value together: a bare value (an id like 6, a vehicle id quoted under another key) is
            # found almost anywhere. ponytail: the pairs may come from different objects in the cut text; that can
            # only downgrade firm -> tentative, never drop a finding. Same-object matching needs a lenient parser.
            if all(re.search(rf'"{re.escape(str(k))}"\s*:\s*{re.escape(json.dumps(v))}', listing.response_body)
                   for k, v in ident.items()):
                return listing
            continue
        stack, seen = [doc], 0
        while stack and seen < _MAX_WALK:
            node, seen = stack.pop(), seen + 1
            if isinstance(node, dict):
                if all(node.get(k) == v for k, v in ident.items()):
                    return listing
                stack += node.values()
            elif isinstance(node, list):
                stack += node
    return None


def _content_type(result: TestResult) -> str:
    value = next((v for k, v in result.response_headers.items() if k.lower() == "content-type"), "")
    return value.split(";")[0].strip().lower()


def _fields_with_values(body: str, injected: dict[str, Any]) -> list[str]:
    """Injected fields present with the injected value, top level or under a data/user/result wrapper."""
    doc = _json(body)
    candidates = [doc] + [doc.get(k) for k in ("data", "user", "result")] if isinstance(doc, dict) else []
    found: list[str] = []
    for obj in candidates:
        if isinstance(obj, dict):
            found += [k for k, v in injected.items() if k in obj and obj[k] == v and k not in found]
    return found


def _resource_url(result: TestResult) -> str | None:
    tc = result.test_case
    location = next((v for k, v in result.response_headers.items() if k.lower() == "location"), None)
    if location:
        # The follow-up carries the configured credentials: never follow a Location to another origin.
        url = urljoin(tc.url, location)
        a, b = urlsplit(url), urlsplit(tc.url)
        return url if (a.scheme, a.netloc) == (b.scheme, b.netloc) else None
    if tc.method in ("PUT", "PATCH"):
        return tc.url
    doc = _json(result.response_body)
    if tc.method == "POST" and isinstance(doc, dict) and doc.get("id") not in (None, ""):
        return f"{tc.url.rstrip('/')}/{quote(str(doc['id']), safe='')}"
    return None


_PARAM_SEGMENT = re.compile(r"^(?:\{([^{}/]+)\}|:(\w+))$")
_REF_PARAM = re.compile(r"^.+(_id|Id|ID)$")


def _segments(path: str) -> list[str]:
    return [s for s in path.strip("/").split("/") if s]


def _usable(value: Any) -> bool:
    return isinstance(value, (str, int)) and not isinstance(value, bool) and str(value) != ""


def _link(candidates: list[Endpoint], created_path: str, request_body: Any,
          response_body: str) -> tuple[Endpoint, str] | None:
    """Resource linking: the documented URL of the object a POST to `created_path` just created.

    A candidate is an item path `<parent>/{param}` whose parent is a non-empty prefix of the creating path
    (POST /orders -> /orders/{id}, POST /users/v1/register -> /users/v1/{username}). `{param}` is filled
    from the response object, then the request body, by exact field name; a `<x>_id`/`<x>Id` param also
    takes the response's `id`. Params inside the parent are the creating path's own and keep their example
    values. Best match: longest parent, then the shorter path, then alphabetical, so ties are deterministic.
    A wrong link costs one request, never a finding: confirmation still needs the injected values (or A's
    object) in what comes back."""
    created = _segments(created_path)
    response = _unwrap(_json(response_body))
    sources = [d for d in (response, request_body) if isinstance(d, dict)]
    best: tuple[tuple[int, int, str], Endpoint, str] | None = None
    for ep in candidates:
        segs = _segments(ep.path)
        m = _PARAM_SEGMENT.match(segs[-1]) if segs else None
        parent = segs[:-1]
        if not m or not parent or created[:len(parent)] != parent:
            continue
        name = m.group(1) or m.group(2)
        value = next((d[name] for d in sources if _usable(d.get(name))), None)
        if value is None and _REF_PARAM.match(name) and isinstance(response, dict) and _usable(response.get("id")):
            value = response["id"]
        if value is None:
            continue
        rank = (-len(parent), len(segs), ep.path)
        if best is None or rank < best[0]:
            best = (rank, ep, build_url(ep, {name: str(value)}))
    return (best[1], best[2]) if best else None


# Field names whose values must never reach an API client. A bare "secret" is left out: it is often the
# resource's own content shown to its owner (VAmPI's book "secret"), which is a BOLA question, not exposure.
_SENSITIVE_FIELD = re.compile(
    r"^(password|passwd|pwd|password_?hash|hashed_?password|client_?secret|secret_?key|api_?secret|api_?key"
    r"|private_?key"
    r"|access_?token|refresh_?token|ssn|social_?security_?number|card_?number|cvv|cvc)$", re.IGNORECASE)
_CREDENTIAL_FIELD = re.compile(r"(api_?key|access_?token|refresh_?token|secret)", re.IGNORECASE)
# A masked value: runs of mask characters, optionally the first 6 / last 4 digits visible (PCI style):
# XXXXXXXXXXXX9999, ************1234, xxxx-xxxx-xxxx-1234, •••• 1234, 411111******1234, ***-**-6789.
_MASKED = r"\d{0,6}[\s-]*(?:[x*•●#]{2,}[\s-]*)+\d{0,4}"
_PLACEHOLDER = re.compile(
    rf"^\s*(\[?(filtered|redacted|hidden|masked|removed)\]?|<[^>]*>|null|none|n/?a|-+|\**|x+|•+|{_MASKED})\s*$",
    re.IGNORECASE)
# The caller's own account/settings: a key or token shown there may be the caller's own (still worth a look).
_CALLER_SCOPED = re.compile(r"/(me|self|account|profile|settings|current|whoami)(/|$)", re.IGNORECASE)
_MAX_WALK = 2000


def _sensitive_fields(doc: Any) -> list[str]:
    """Dotted paths of sensitive fields holding a real (non-empty, unmasked) value."""
    found: list[str] = []
    stack: list[tuple[str, Any]] = [("", doc)]
    seen = 0
    while stack and seen < _MAX_WALK:
        path, node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            for k, v in node.items():
                child = f"{path}.{k}" if path else str(k)
                if (_SENSITIVE_FIELD.match(str(k)) and isinstance(v, (str, int)) and not isinstance(v, bool)
                        and not _PLACEHOLDER.match(str(v))):
                    found.append(child)
                else:
                    stack.append((child, v))
        elif isinstance(node, list):
            stack += [(f"{path}[]", v) for v in node[:50]]
    # One entry per field path (a list of 50 users -> "users[].password" once).
    return sorted(set(found))


# Pagination envelope fields (compared without "_"/"-", lower case): spec drift, not data.
_PAGINATION = {"count", "total", "totalcount", "totalitems", "totalpages", "pages", "page", "pagesize", "perpage",
               "limit", "offset", "next", "previous", "prev", "nextoffset", "previousoffset", "prevoffset",
               "nextpage", "previouspage", "prevpage", "cursor", "nextcursor", "previouscursor", "prevcursor",
               "hasmore", "hasnext", "hasprevious"}


def _undocumented_fields(doc: Any, schema: Any, path: str = "", depth: int = 0) -> list[str]:
    """Response fields the documented 2xx schema doesn't declare (objects with declared properties only).
    Not reported: empty values (null, "", [], {} expose nothing) and pagination fields of the top-level envelope."""
    if depth > 4 or not isinstance(schema, dict):
        return []
    if isinstance(doc, list):
        items = schema.get("items")
        return sorted({f for d in doc[:3] for f in _undocumented_fields(d, items, f"{path}[]", depth + 1)})
    props = schema.get("properties")
    if (not isinstance(doc, dict) or not isinstance(props, dict) or schema.get("additionalProperties")
            or any(k in schema for k in ("allOf", "oneOf", "anyOf"))):
        return []  # open or composed schema: can't tell what is undocumented
    out = [f"{path}.{k}" if path else str(k) for k, v in doc.items()
           if k not in props and v is not None and v not in ("", [], {})
           and not (depth == 0 and str(k).replace("_", "").replace("-", "").lower() in _PAGINATION)]
    for k, v in doc.items():
        if k in props:
            out += _undocumented_fields(v, props[k], f"{path}.{k}" if path else str(k), depth + 1)
    return out


# kind -> (content that proves it, severity, rule, title, confidence)
_INVENTORY_SIGNATURES: dict[str, tuple[re.Pattern[str], Severity, str, str, Confidence]] = {
    "spec": (re.compile(r'("openapi"|"swagger"|^openapi:|^swagger:)', re.M), Severity.MEDIUM,
             "FUZZOWL-INVENTORY-001", "Spec for operations missing from the scanned spec exposed", "firm"),
    "actuator": (re.compile(r'"_links"\s*:'), Severity.MEDIUM,
                 "FUZZOWL-INVENTORY-002", "Spring Boot actuator exposed", "firm"),
    "actuator_env": (re.compile(r'"(propertySources|activeProfiles|contexts)"\s*:'), Severity.HIGH,
                     "FUZZOWL-INVENTORY-002", "Actuator configuration endpoint exposed", "firm"),
    "dotenv": (re.compile(r"(^[A-Z][A-Z0-9_]{2,}=.*\n){2,}", re.M), Severity.HIGH,
               "FUZZOWL-INVENTORY-002", ".env file exposed", "firm"),
    "expvar": (re.compile(r'"memstats"\s*:'), Severity.MEDIUM,
               "FUZZOWL-INVENTORY-002", "Go expvar debug endpoint exposed", "firm"),
    "metrics": (re.compile(r"^# (HELP|TYPE) ", re.M), Severity.MEDIUM,
                "FUZZOWL-INVENTORY-002", "Prometheus metrics exposed", "firm"),
    "server_status": (re.compile(r"Server Status for", re.I), Severity.MEDIUM,
                      "FUZZOWL-INVENTORY-002", "Apache server-status exposed", "firm"),
    "version": (re.compile(r"^\s*[\[{]"), Severity.MEDIUM,
                "FUZZOWL-INVENTORY-003", "Undocumented API version reachable", "tentative"),
}


def _spec_paths(body: str) -> set[str]:
    """Path templates of a served OpenAPI/Swagger document (JSON or YAML), or empty."""
    import yaml
    try:
        doc = json.loads(body)
    except ValueError:
        try:
            doc = yaml.safe_load(body)
        except yaml.YAMLError:
            return set()
    paths = doc.get("paths") if isinstance(doc, dict) else None
    return {str(p).rstrip("/") or "/" for p in paths} if isinstance(paths, dict) else set()


def _label_endpoints(findings: list[Finding], results: list[TestResult]) -> None:
    """Every finding's endpoint_path is the URL of the probe that produced it: map it back to its operation."""
    keys: dict[tuple[str, str], str] = {}
    for r in results:
        # Confirmation GETs carry the POST probe's key: never let them relabel a real GET probe's URL.
        if r.test_case.check_id != "mass_assignment_verify":
            keys.setdefault((r.test_case.method, r.test_case.url), r.test_case.extra.get("endpoint_key", ""))
    for f in findings:
        f.endpoint = f.endpoint or keys.get((f.endpoint_method, f.endpoint_path), "")


# Operations where an attacker guesses (passwords, one-time codes, reset tokens): every wrong guess is
# answered with an error, so "the burst wasn't accepted" doesn't apply. What matters is that nothing slowed down.
_AUTH_SENSITIVE = re.compile(r"(log-?in|sign-?in|otp|verif|reset|passw|2fa|mfa|/token|check-?code)",
                             re.IGNORECASE)


def _limited(result: TestResult) -> bool:
    headers = {k.lower() for k in result.response_headers}
    return (result.status_code == 429 or "retry-after" in headers
            or any(h.startswith(("x-ratelimit-", "ratelimit-")) for h in headers))


_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|credential)", re.IGNORECASE)


def _mask_body(body: Any) -> Any:
    """Mask values of password/secret/token-like keys (recorded HAR/Postman login bodies)."""
    if isinstance(body, dict):
        return {k: (mask(str(v)) if _SECRET_KEY.search(k) and isinstance(v, (str, int)) else _mask_body(v))
                for k, v in body.items()}
    if isinstance(body, list):
        return [_mask_body(v) for v in body]
    return body


def _mask_fields(doc: Any) -> Any:
    """Mask values of _SENSITIVE_FIELD keys anywhere in a JSON document."""
    if isinstance(doc, dict):
        return {k: (mask(str(v)) if _SENSITIVE_FIELD.match(str(k)) and isinstance(v, (str, int)) else _mask_fields(v))
                for k, v in doc.items()}
    if isinstance(doc, list):
        return [_mask_fields(v) for v in doc]
    return doc


def _request_text(result: TestResult, sensitive_headers: tuple[str, ...] = ()) -> str:
    """The request as sent (sensitive headers masked here; Scanner scrubs configured tokens everywhere)."""
    tc = result.test_case
    query = ("?" + urlencode(tc.params)) if tc.params else ""
    lines = [f"# {tc.label}", f"{tc.method} {tc.url}{query}"]
    lines += [f"{k}: {v}" for k, v in redact_headers(result.request_headers, sensitive_headers).items()]
    if tc.body is not None:
        lines += ["", json.dumps(_mask_body(tc.body))[:1000]]
    return "\n".join(lines)


def _response_text(result: TestResult) -> str:
    excerpt = result.response_body[:500]
    if result.truncated:
        n = len(result.response_body)  # the executor cut it at --max-body
        excerpt += f"\n[response truncated at {n} characters (--max-body); detection only saw the first {n}]"
    return excerpt


def _resembles(a: TestResult, b: TestResult) -> bool:
    """Same status, same content type, same JSON shape (top-level keys), and a body within 10% (min 20
    bytes) in length. An {"error": ...} body never resembles a user object of similar length."""
    if a.status_code != b.status_code or _content_type(a) != _content_type(b):
        return False
    if a.response_body == b.response_body:
        return True
    ja, jb = _unwrap(_json(a.response_body)), _unwrap(_json(b.response_body))
    if type(ja) is not type(jb) or (isinstance(ja, dict) and isinstance(jb, dict) and ja.keys() != jb.keys()):
        return False
    la, lb = len(a.response_body), len(b.response_body)
    return abs(la - lb) <= max(20, 0.1 * max(la, lb))


class Analyzer:
    def __init__(self, sensitive_headers: tuple[str, ...] = (), documented_paths: set[str] | None = None):
        # Extra header names to mask in request samples (the configured --header-name for apikey auth).
        self.sensitive_headers = sensitive_headers
        # Path templates of the scanned spec: a served spec describing these is the API's own.
        self.documented_paths = documented_paths or set()
        # The scan's in-scope operations (Scanner sets them): sibling endpoints for resource linking.
        self.endpoints: list[Endpoint] = []
        # Set when bola runs with a second token: cross-user reads of objects user A creates during the scan.
        self.bola_auth: AuthConfig | None = None

    def analyze(self, results: list[TestResult]) -> list[Finding]:
        # Baseline = one normal request per endpoint with the configured auth (Scanner adds it).
        # Detectors compare against it: status, body, length, latency.
        self._baselines: dict[str | None, TestResult] = {
            r.test_case.extra.get("endpoint_key"): r
            for r in results if r.test_case.check_id == "baseline" and not r.is_error
        }
        self._inventory_control = next((r for r in results if not r.is_error
                                        and r.test_case.extra.get("strategy") == "inventory_control"), None)
        # What the endpoint answers for an object that can't exist: a 200 {"message": "not found"} must
        # not count as "user B got user A's object".
        self._missing: dict[str | None, TestResult] = {
            r.test_case.extra.get("endpoint_key"): r
            for r in results if r.test_case.check_id == "bola" and not r.is_error
            and r.test_case.extra.get("probe_id") == MISSING_ID
        }
        # User A's own read of an object A created this scan: what a cross-user read is compared to.
        self._owner_reads: dict[str | None, TestResult] = {
            r.test_case.extra.get("pair_id"): r
            for r in results if r.test_case.check_id == "bola_owner" and not r.is_error
        }
        # User B's reads of the listing endpoints (no path params): what B can see without asking for an id.
        self._listings = [r for r in results if r.test_case.check_id == "bola_listing" and r.is_success]
        raw: list[Finding] = []

        for result in results:
            if result.is_error:
                continue
            findings = self._dispatch(result)
            raw.extend(findings)

        raw.extend(self._analyze_nosqli_pairs(results))
        raw.extend(self._analyze_sqli_blind(results))
        raw.extend(self._analyze_user_enum(results))
        raw.extend(self._analyze_redos(results))
        self._confirm_mass_assignment(results, raw)
        _label_endpoints(raw, results)
        return self._dedup(raw)

    def _baseline(self, result: TestResult) -> TestResult | None:
        return getattr(self, "_baselines", {}).get(result.test_case.extra.get("endpoint_key"))

    def _baseline_body(self, result: TestResult) -> str:
        base = self._baseline(result)
        return base.response_body if base else ""

    def _dispatch(self, result: TestResult) -> list[Finding]:
        check_id = result.test_case.check_id
        dispatch = {
            "bola": self._check_bola,
            "auth": self._check_auth,
            "mass_assignment": self._check_mass_assignment,
            "ssrf": self._check_ssrf,
            "injection": self._check_injection,
            "rate_limit": self._check_rate_limit,
            "cors": self._check_cors,
            "data_exposure": self._check_data_exposure,
            "inventory": self._check_inventory,
            "bfla": self._check_bfla,
        }
        handler = dispatch.get(check_id)
        if handler:
            return handler(result)
        return []

    def _check_bola(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        strategy = tc.extra.get("strategy", "")
        if not result.is_success:
            return []
        base = self._baseline(result)  # user A (configured token) reading the example object
        missing = getattr(self, "_missing", {}).get(tc.extra.get("endpoint_key"))
        if missing is not None and missing.is_success and _resembles(missing, result):
            return []  # same answer as for an object that doesn't exist
        keys = (tc.extra["param_name"],) if tc.extra.get("param_name") else ()

        if strategy in ("cross_user", "created_cross_user"):
            created = strategy == "created_cross_user"
            if created:
                # The object A created this scan: A's own read of it is the comparison, and without one
                # (A can't read it: the link was wrong) there is nothing to show.
                base = getattr(self, "_owner_reads", {}).get(tc.extra.get("pair_id"))
                if base is None or not base.is_success:
                    return []
            # User B reading user A's object. Firm only if B got A's object back; a 2xx with B's own
            # data or a soft-fail body is not BOLA. No baseline (DELETE) -> tentative.
            confirmed = base is not None and base.is_success and _same_object(base.response_body,
                                                                               result.response_body, keys)
            if base is not None and not confirmed and base.response_body.strip():
                return []  # A's object has a body and B didn't get it back
            if created and not confirmed:
                return []
            # Firm only when B's response is A's object. Empty write responses (204) can't show whose
            # object changed, and without a baseline (DELETE) there is nothing to compare: tentative.
            # An object B also gets in a listing is public by design (a forum post): reading it, or adding to
            # it (POST: a comment, a like), is what every user may do -> tentative. Changing it (PUT/PATCH)
            # stays firm: a public object is still owned.
            listed = (_listed_in(base.response_body, getattr(self, "_listings", []), keys)
                      if confirmed and base is not None and tc.method in ("GET", "POST") else None)
            confidence: Confidence = "firm" if confirmed and listed is None else "tentative"
            public_note = (f" User B also gets this object from {listed.test_case.method} {listed.test_case.url}, so "
                           f"it may be public by design; verify it is meant to be private." if listed else "")
            return [Finding(
                title="BOLA: Cross-user object access succeeded",
                description=(
                    f"Using the second user's token, {tc.method} {tc.url} returned the first user's object. "
                    f"Object-level authorization is not enforced.{public_note}"
                    if confirmed else
                    f"Using the second user's token, {tc.method} {tc.url} returned HTTP {result.status_code}. "
                    f"Nothing in the response shows whose object it was; verify manually."
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API1_BOLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(result, self.sensitive_headers),
                response_sample=_response_text(result),
                evidence=(f"HTTP {result.status_code} with cross-user token; response matches user A's object"
                          + (" (created by user A during the scan)" if created else "")
                          + (f"; also listed for user B in {listed.test_case.method} {listed.test_case.url}"
                             if listed else "")
                          if confirmed else f"HTTP {result.status_code} with cross-user token"),
                remediation="Enforce object-level authorization: verify the requesting user owns the resource.",
                rule_id="FUZZOWL-BOLA-001",
                confidence=confidence,
            )]

        if strategy == "id_enumeration":
            # A 200 alone isn't a finding: most APIs have an object 1. Tentative only when the probed ID
            # returns an object shaped like the caller's own (same keys) but a different one.
            if base is None or not base.is_success or _same_object(base.response_body, result.response_body, keys):
                return []
            mine, theirs = _unwrap(_json(base.response_body)), _unwrap(_json(result.response_body))
            if not (isinstance(mine, dict) and isinstance(theirs, dict) and mine.keys() == theirs.keys()):
                return []
            return [Finding(
                title="BOLA: Enumerated object ID returned another object",
                description=(
                    f"Probe ID {tc.extra.get('probe_id')} on {tc.method} {tc.url} returned an object with the "
                    f"same fields as the caller's own but different values. It may belong to another user."
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.API1_BOLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(result, self.sensitive_headers),
                response_sample=_response_text(result),
                evidence=f"HTTP {result.status_code} for probe ID {tc.extra.get('probe_id')}; same schema, "
                         f"different object than the baseline",
                remediation="Validate that returned object belongs to the authenticated user.",
                rule_id="FUZZOWL-BOLA-002",
                confidence="tentative",
            )]
        return []

    def _check_auth(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if not result.is_success:  # any 2xx: 201/204 bypasses count too
            return []
        # A 2xx alone isn't a bypass (public data, {"error": ...} bodies, login pages). Firm when the
        # response matches what the authenticated baseline got; no baseline (DELETE) -> tentative.
        base = self._baseline(result)
        if base is not None and not _resembles(result, base):
            return []
        confidence: Confidence = "firm" if base is not None else "tentative"
        matched = (f"; matches the authenticated baseline (HTTP {base.status_code}, "
                   f"{len(base.response_body)} bytes)" if base is not None else "; no baseline to compare")
        strategy = tc.extra.get("strategy", "unknown")
        descriptions = {
            "no_auth": "Endpoint returned 2xx with no Authorization header.",
            "invalid_token": "Endpoint returned 2xx with a known-invalid token.",
            "empty_bearer": "Endpoint returned 2xx with an empty Bearer token.",
            "empty_apikey": "Endpoint returned 2xx with an empty API key.",
            "jwt_alg_none": "Endpoint accepted JWT with alg:none (signature bypass).",
            "jwt_unsigned": "Endpoint accepted a JWT whose signature was replaced with garbage "
                            "(the signature is not verified).",
            "jwt_kid_trav": "Endpoint accepted a JWT with a path-traversal `kid` signed with an "
                            "empty/null key (kid file-read signature bypass).",
            "jwt_weak_key": "Endpoint accepted a JWT re-signed with a HMAC secret guessed offline from a "
                            "public wordlist (the signing key is guessable).",
            "jwt_expired": "Endpoint accepted an expired JWT (exp in the past), re-signed with the "
                           "guessed HMAC secret (expiry is not enforced).",
            "malformed_scheme": "Endpoint returned 2xx with a malformed auth scheme.",
        }
        # Signature-bypass / guessable-key forgeries are critical; weaker signals stay high.
        critical = {"no_auth", "jwt_alg_none", "jwt_unsigned", "jwt_kid_trav", "jwt_weak_key"}
        cracked = tc.extra.get("cracked_secret")
        key_note = f"; signing key guessed: {mask(cracked)}" if cracked else ""
        return [Finding(
            title=f"Broken Auth: {strategy.replace('_', ' ').title()} accepted",
            description=descriptions.get(strategy, f"Auth bypass via {strategy}"),
            severity=Severity.CRITICAL if strategy in critical else Severity.HIGH,
            owasp_category=OWASPCategory.API2_AUTH,
            endpoint_method=tc.method,
            endpoint_path=tc.url,
            request_sample=_request_text(result, self.sensitive_headers),
            response_sample=_response_text(result),
            evidence=f"HTTP {result.status_code} returned with strategy: {strategy}{matched}{key_note}",
            remediation="Require valid authentication on all protected endpoints.",
            rule_id=f"FUZZOWL-AUTH-{strategy.upper()[:10]}",
            confidence=confidence,
        )]

    def _check_mass_assignment(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if not result.is_success:
            return []
        injected = tc.extra.get("injected_values", {})
        already = _fields_with_values(self._baseline_body(result), injected)  # e.g. scanning as an admin
        reflected = [f for f in _fields_with_values(result.response_body, injected) if f not in already]
        if not reflected:
            return []
        # Reflection alone may be an echo of the request; persistence (follow-up GET) makes it firm.
        return [self._mass_finding(result, reflected, "tentative",
                                   f"Injected values echoed in the response: {reflected}")]

    def _mass_finding(self, result: TestResult, fields: list[str], confidence: Confidence,
                      evidence: str) -> Finding:
        tc = result.test_case
        persisted = confidence == "firm"
        return Finding(
            title="Mass Assignment: Privileged fields " + ("persisted" if persisted else "reflected in response"),
            description=(
                f"Injected privileged fields {fields} were "
                + ("stored: a follow-up GET returns the injected values." if persisted else
                   "returned with the injected values. Verify they were stored (no follow-up URL was found or "
                   "it did not confirm).")
            ),
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API3_BOPLA,
            endpoint_method=tc.method,
            endpoint_path=tc.url,
            request_sample=_request_text(result, self.sensitive_headers),
            response_sample=_response_text(result),
            evidence=evidence,
            remediation="Use an allowlist for accepted fields; never bind request body directly to model.",
            rule_id="FUZZOWL-MASS-001",
            confidence=confidence,
        )

    def followups(self, results: list[TestResult]) -> list[TestCase]:
        """Second-pass requests that confirm first-pass signals.
        Mass assignment: GET the resource the probe created or updated (Location header, the same URL for
        PUT/PATCH, <url>/<id> for POST, else a sibling GET linked by `_link`).
        BOLA (with a second token): for each object a POST baseline created as user A, A's own read of it
        and user B's read of it through a sibling GET (`_link`). GET only: a read decides the verdict."""
        out = []
        gets = [e for e in self.endpoints if e.method == "GET"]
        # BOLA skips public-by-design reads, as the bola check does.
        private_gets = [e for e in gets if e.secured is not False or e.auth_optional]
        ops = {f"{e.method} {e.path}": e for e in self.endpoints}
        for r in results:
            tc = r.test_case
            if not r.is_success:
                continue
            key = tc.extra.get("endpoint_key", "")
            if tc.check_id == "mass_assignment":
                url, extra = _resource_url(r), {}
                if url is None and tc.method == "POST":
                    link = _link(gets, key.partition(" ")[2], tc.body, r.response_body)
                    if link:
                        url, extra = link[1], {"baseline_key": f"GET {link[0].path}"}
                if url:
                    out.append(TestCase(
                        method="GET", url=url, headers={}, params={}, body=None,
                        label=f"MassAssignment verify: GET {url}", check_id="mass_assignment_verify",
                        extra={"verifies": f"{tc.method} {tc.url}", "endpoint_key": key, **extra},
                    ))
            elif tc.check_id == "baseline" and tc.method == "POST" and self.bola_auth is not None:
                creator = ops.get(key)
                if creator is None or creator.secured is False:
                    continue  # created through a public endpoint: the object isn't tied to user A
                link = _link(private_gets, creator.path, tc.body, r.response_body)
                if not link:
                    continue
                ep, url = link
                a = self.bola_auth
                pair = {"pair_id": f"created {url}", "endpoint_key": f"GET {ep.path}"}
                out.append(TestCase(method="GET", url=url, headers={}, params={}, body=None,
                                    label=f"BOLA owner read (created object): GET {url}",
                                    check_id="bola_owner", extra=dict(pair)))
                out.append(TestCase(
                    method="GET", url=url, params={}, body=None,
                    # Same scheme as user A; with auth type "none", assume bearer (as the bola check does).
                    headers=auth_headers(a.type if a.type != "none" else "bearer", a.second_token, a.header_name),
                    label=f"BOLA cross-user (created object): GET {url} via second token", check_id="bola",
                    extra={**pair, "strategy": "created_cross_user", "uses_second_token": True},
                    auth_mode="override",
                ))
        return out

    def _confirm_mass_assignment(self, results: list[TestResult], raw: list[Finding]) -> None:
        probes = {f"{r.test_case.method} {r.test_case.url}": r for r in results
                  if r.test_case.check_id == "mass_assignment" and r.is_success}
        for v in results:
            if v.test_case.check_id != "mass_assignment_verify" or not v.is_success:
                continue
            probe = probes.get(v.test_case.extra.get("verifies", ""))
            if probe is None:
                continue
            injected = probe.test_case.extra.get("injected_values", {})
            already = _fields_with_values(self._baseline_body(probe), injected)
            # A sibling GET: values its normal read already has (every user is_verified) prove nothing.
            sibling = self._baselines.get(v.test_case.extra.get("baseline_key", ""))
            if sibling is not None:
                already += _fields_with_values(sibling.response_body, injected)
            stored = [f for f in _fields_with_values(v.response_body, injected) if f not in already]
            if not stored:
                continue
            raw[:] = [f for f in raw if not (f.rule_id == "FUZZOWL-MASS-001" and f.endpoint_path == probe.test_case.url
                                             and f.endpoint_method == probe.test_case.method)]
            raw.append(self._mass_finding(probe, stored, "firm",
                                          f"{v.test_case.label} returned the injected values: {stored}"))

    def _check_bfla(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if not result.is_success:
            return []
        base = self._baseline(result)  # the privileged (configured) token
        if base is not None and not (base.is_success and _resembles(result, base)):
            return []  # the privileged call itself failed, or the low-privilege user got something else
        confirmed = base is not None
        return [Finding(
            title="BFLA: Privileged operation allowed for a low-privilege user",
            description=(f"{tc.method} {tc.url} looks privileged ('{tc.extra.get('hint')}') and the low-privilege "
                         f"token got " + ("the same response as the privileged token." if confirmed else
                                          f"HTTP {result.status_code}; nothing to compare it with, verify manually.")),
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API5_BFLA,
            endpoint_method=tc.method,
            endpoint_path=tc.url,
            request_sample=_request_text(result, self.sensitive_headers),
            response_sample=_response_text(result),
            evidence=(f"Low-privilege HTTP {result.status_code}"
                      + (f"; privileged baseline HTTP {base.status_code}, same shape" if base else "")),
            remediation="Enforce role checks on every privileged function, server-side, deny by default.",
            rule_id="FUZZOWL-BFLA-001",
            confidence="firm" if confirmed else "tentative",
        )]

    def _check_inventory(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if tc.extra.get("strategy") != "inventory_probe" or not result.is_success:
            return []
        control = getattr(self, "_inventory_control", None)
        if control is not None and control.is_success and _resembles(result, control):
            return []  # catch-all server: answers this way for any path
        kind, path = tc.extra.get("kind", ""), tc.extra.get("path", "")
        if kind == "spec":
            served = _spec_paths(result.response_body)
            if not served or served & self.documented_paths:
                return []  # the API's own published spec (or unparseable): not an inventory gap
        signature = _INVENTORY_SIGNATURES.get(kind)
        if signature is None or not signature[0].search(result.response_body):
            return []  # reachable, but not the thing we probed for
        _, severity, rule_id, title, confidence = signature
        return [Finding(
            title=f"Inventory: {title} ({path})",
            description=(f"GET {tc.url} is reachable and is not in the spec. Unlisted docs, management endpoints "
                         f"and API versions escape review, patching and monitoring."),
            severity=severity,
            owasp_category=OWASPCategory.API9_INVENTORY,
            endpoint_method="GET",
            endpoint_path=tc.url,
            request_sample=_request_text(result, self.sensitive_headers),
            response_sample=_response_text(result),
            evidence=(f"HTTP {result.status_code}, content matches {kind}"
                      + ("; a random path answers differently" if control is not None
                         else "; no catch-all control response to compare with")),
            remediation="Remove or restrict the endpoint (network, auth), or document and own it in the inventory.",
            rule_id=rule_id,
            confidence=confidence,
        )]

    def _check_data_exposure(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        doc = _json(result.response_body) if result.is_success else None
        if doc is None:
            return []
        masked_sample = json.dumps(_mask_body(_mask_fields(doc)))[:500]
        findings = []
        secrets = _sensitive_fields(doc)
        if secrets:
            # Passwords never belong in a response. A key or token on the caller's own account page may be
            # theirs by design: tentative there.
            own_page = bool(_CALLER_SCOPED.search(tc.extra.get("endpoint_key", "") or tc.url))
            tentative = own_page and all(_CREDENTIAL_FIELD.search(f.rsplit(".", 1)[-1]) for f in secrets)
            findings.append(Finding(
                title="Data Exposure: Sensitive fields returned to the client",
                description=(f"{tc.method} {tc.url} returns sensitive fields with real values: {secrets}. "
                             f"Clients should never receive these."),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.API3_BOPLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(result, self.sensitive_headers),
                response_sample=masked_sample,  # values masked: the report must not repeat the leak
                evidence=f"Sensitive fields with values: {secrets}",
                remediation="Return an explicit allowlist of fields per role; never serialize whole model objects.",
                rule_id="FUZZOWL-EXPOSURE-001",
                confidence="tentative" if tentative else "firm",
            ))
        extra = _undocumented_fields(doc, tc.extra.get("response_schema") or {})
        if extra:
            findings.append(Finding(
                title="Data Exposure: Response fields missing from the spec",
                description=(f"{tc.method} {tc.url} returns fields its documented response schema doesn't declare: "
                             f"{extra[:20]}. Undocumented fields are often internal data leaking by accident."),
                severity=Severity.LOW,
                owasp_category=OWASPCategory.API3_BOPLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(result, self.sensitive_headers),
                response_sample=masked_sample,
                evidence=f"Undocumented fields: {extra[:20]}",
                remediation="Document every response field, or stop returning fields clients don't need.",
                rule_id="FUZZOWL-EXPOSURE-002",
                confidence="tentative",  # may just be an outdated spec
            ))
        return findings

    def _check_ssrf(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        match = _SSRF_METADATA.search(result.response_body)
        if match and not _SSRF_METADATA.search(self._baseline_body(result)):
            return [Finding(
                title="SSRF: Internal metadata content in response",
                description=(
                    f"Response to {tc.label} contains content indicative of internal resource access "
                    f"(cloud metadata or /etc/passwd) that the baseline response does not."
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API7_SSRF,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(result, self.sensitive_headers),
                response_sample=_response_text(result),
                evidence=f"Metadata marker '{match.group(0)}' in response, absent from baseline",
                remediation="Validate and allowlist URL parameters; block requests to internal networks.",
                rule_id="FUZZOWL-SSRF-001",
                parameter=str(tc.extra.get("param_name") or ""),
            )]
        return []

    def _injection_finding(self, result: TestResult, title: str, description: str, evidence: str,
                           remediation: str, rule_id: str, severity: Severity = Severity.CRITICAL) -> Finding:
        tc = result.test_case
        return Finding(
            title=title,
            description=description,
            severity=severity,
            owasp_category=OWASPCategory.INJECTION,
            endpoint_method=tc.method,
            endpoint_path=tc.url,
            request_sample=_request_text(result, self.sensitive_headers),
            response_sample=_response_text(result),
            evidence=evidence,
            remediation=remediation,
            rule_id=rule_id,
            parameter=str(tc.extra.get("param_name") or ""),
        )

    def _check_injection(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        body = result.response_body
        baseline = self._baseline_body(result)
        injection_type = tc.extra.get("injection_type", "")

        if injection_type == "sqli" and _SQLI_ERRORS.search(body) and not _SQLI_ERRORS.search(baseline):
            return [self._injection_finding(
                result, "SQL Injection: Database error in response",
                "Response to SQL injection probe contains a database error string the baseline does not.",
                "Database error pattern in response",
                "Use parameterized queries. Never concatenate user input into SQL.", "FUZZOWL-INJECT-SQLI")]
        if (injection_type == "ssti" and SSTI_PRODUCT in body and "1337*7331" not in body
                and SSTI_PRODUCT not in baseline):
            return [self._injection_finding(
                result, "SSTI: Template expression evaluated in response",
                f"1337*7331 was evaluated to {SSTI_PRODUCT}, indicating server-side template injection.",
                f"'{SSTI_PRODUCT}' in response, payload not reflected literally, absent from baseline",
                "Never render user input through template engines without sanitization.", "FUZZOWL-INJECT-SSTI")]
        if injection_type == "cmd_injection":
            uid = _CMD_UID.search(body)
            shown = uid.group(0) if uid else (CMD_CANARY if CMD_CANARY in body else "")
            if shown and not (_CMD_UID.search(baseline) or CMD_CANARY in baseline):
                return [self._injection_finding(
                    result, "Command Injection: Shell output in response",
                    "Response contains output of an injected shell command.",
                    f"Shell output '{shown}' in response",
                    "Never pass user input to shell commands. Use safe APIs.", "FUZZOWL-INJECT-CMD")]
        if injection_type == "xss":
            payload = tc.extra.get("payload", "")
            ctype = result.response_headers.get("content-type", "")
            if payload and payload in body and "text/html" in ctype:
                return [self._injection_finding(
                    result, "XSS: Payload reflected unescaped in HTML response",
                    "The script payload is reflected verbatim in a text/html response.",
                    f"Unescaped '{payload}' in {ctype} response",
                    "HTML-encode output and return JSON with application/json.", "FUZZOWL-INJECT-XSS",
                    severity=Severity.MEDIUM)]
        if injection_type == "nosqli" and _NOSQL_ERRORS.search(body) and not _NOSQL_ERRORS.search(baseline):
            return [self._injection_finding(
                result, "NoSQL Injection: Database error in response",
                "Response to a NoSQL operator probe contains a MongoDB error signature.",
                "MongoDB error pattern in response",
                "Reject objects/operators where scalars are expected; validate input types.",
                "FUZZOWL-INJECT-NOSQLI", severity=Severity.HIGH)]
        return []

    def _analyze_sqli_blind(self, results: list[TestResult]) -> list[Finding]:
        """Boolean: true answers like the control, false answers like neither control, and the control repeated
        after the pair still answers like the first (a stable endpoint). Time: every repeat of a sleep payload
        is at least ~SLEEP seconds slower than the control."""
        groups: dict[str, dict[str, list[TestResult]]] = {}
        controls: dict[str, TestResult] = {}
        for r in results:
            extra = r.test_case.extra
            if r.is_error and extra.get("strategy") != "sqli_time":
                continue
            if extra.get("strategy") == "sqli_bool":
                groups.setdefault(extra["pair_id"], {}).setdefault(extra["polarity"], []).append(r)
                if extra["polarity"] == "control":
                    controls[extra["pair_id"]] = r
            elif extra.get("strategy") == "sqli_time":
                groups.setdefault(extra["pair_id"], {}).setdefault("time", []).append(r)

        findings = []
        for pair_id, g in groups.items():
            if "time" in g:
                times = g["time"]
                control = controls.get(times[0].test_case.extra.get("control_id", ""))
                if control is None:
                    continue
                threshold = control.elapsed_ms + (SQLI_SLEEP_SECONDS - 0.5) * 1000
                if times and all(t.elapsed_ms >= threshold or "Timeout" in (t.error or "") for t in times):
                    findings.append(self._injection_finding(
                        times[0], "SQL Injection: Time-based (response delayed by injected sleep)",
                        f"All {len(times)} repeats of a {SQLI_SLEEP_SECONDS}s sleep payload were delayed "
                        f"compared with the control request.",
                        "Elapsed ms: " + ", ".join(f"{t.elapsed_ms:.0f}" for t in times)
                        + f"; control {control.elapsed_ms:.0f} ms",
                        "Use parameterized queries. Never concatenate user input into SQL.",
                        "FUZZOWL-INJECT-SQLI-TIME"))
                continue
            control, true, false, again = (g.get(k, [None])[0] for k in ("control", "true", "false", "control_again"))
            if not (control and true and false and again) or not (control.is_success and again.is_success):
                continue
            if any(r.status_code == 429 or r.status_code >= 500 for r in (true, false, again)):
                continue
            # The original value, sent before and after the pair, must get the same answer: a response that
            # changes with every request (each POST appends a comment to the object it returns) is no
            # reference, and the false probe differing from it proves nothing.
            if not _resembles(again, control):
                continue
            if _resembles(true, control) and not _resembles(false, control) and not _resembles(false, again):
                findings.append(self._injection_finding(
                    true, "SQL Injection: Boolean-based (true/false conditions change the response)",
                    "Appending a true condition returned the same response as the original value, a false "
                    "condition changed it, so the input is evaluated as SQL.",
                    f"control: HTTP {control.status_code}, {len(control.response_body)} bytes; "
                    f"AND '1'='1: HTTP {true.status_code}, {len(true.response_body)} bytes; "
                    f"AND '1'='2: HTTP {false.status_code}, {len(false.response_body)} bytes; "
                    f"control again: HTTP {again.status_code}, {len(again.response_body)} bytes",
                    "Use parameterized queries. Never concatenate user input into SQL.",
                    "FUZZOWL-INJECT-SQLI-BOOL"))
        return findings

    def _analyze_redos(self, results: list[TestResult]) -> list[Finding]:
        """Firm only if every evil probe is at least REDOS_MIN_DELAY_MS and REDOS_FACTOR x slower than the
        slowest control (a timed-out evil probe counts as slow, like time-based SQLi). No tentative verdict:
        one slow request is network noise. A 429, a failed control or any other error means no verdict."""
        groups: dict[str, dict[str, list[TestResult]]] = {}
        for r in results:
            if r.test_case.extra.get("strategy") == "redos":
                groups.setdefault(r.test_case.extra["pair_id"], {}).setdefault(
                    r.test_case.extra["polarity"], []).append(r)
        findings = []
        for pair_id, g in groups.items():
            controls, evil = g.get("control", []), g.get("evil", [])
            if not controls or not evil or any(r.is_error or r.status_code == 429 for r in controls) or any(
                    r.status_code == 429 or (r.is_error and "Timeout" not in (r.error or "")) for r in evil):
                continue
            slowest = max(r.elapsed_ms for r in controls)
            threshold = max(slowest + REDOS_MIN_DELAY_MS, slowest * REDOS_FACTOR)
            if not all(r.elapsed_ms >= threshold or r.is_error for r in evil):
                continue
            tc = evil[0].test_case
            findings.append(Finding(
                title="ReDoS: Regex backtracking delays the response",
                description=(f"{tc.extra.get('param_name')} accepts input that makes server-side validation "
                             f"backtrack: all {len(evil)} requests with {REDOS_N} 'a' characters followed by '!' "
                             f"were slower than every same-length control ('!' first). Each such request burns "
                             f"server CPU, so a few concurrent ones can exhaust the workers."),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.API4_RATE,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(evil[0], self.sensitive_headers),
                response_sample=_response_text(evil[0]),
                evidence=("Evil ms: " + ", ".join(f"{r.elapsed_ms:.0f}" + (" (timeout)" if r.is_error else "")
                                                  for r in evil)
                          + "; control ms: " + ", ".join(f"{r.elapsed_ms:.0f}" for r in controls)),
                remediation=("Rewrite the regex without nested or overlapping quantifiers (e.g. (a+)+, (\\w+\\s?)*), "
                             "cap the input length before matching, or use a linear-time engine (RE2)."),
                rule_id="FUZZOWL-REDOS-001",
                parameter=str(tc.extra.get("param_name") or ""),
            ))
        return findings

    def _analyze_user_enum(self, results: list[TestResult]) -> list[Finding]:
        """Known user vs two unknown users, all with a wrong password. The unknowns must answer alike (so
        the difference isn't per-request noise) and the known user differently."""
        groups: dict[str, dict[str, TestResult]] = {}
        for r in results:
            if r.test_case.extra.get("strategy") == "enum_pair" and not r.is_error:
                groups.setdefault(r.test_case.extra["pair_id"], {})[r.test_case.extra["polarity"]] = r
        findings = []
        for g in groups.values():
            known, u1, u2 = g.get("known"), g.get("unknown1"), g.get("unknown2")
            if not (known and u1 and u2):
                continue
            if any(r.status_code == 429 or r.status_code >= 500 for r in (known, u1, u2)):
                continue

            def norm(r: TestResult) -> tuple[int, str]:
                # An echoed username isn't a difference: replace whole-word echoes (any case) only, so a
                # username like "user" doesn't rewrite "Invalid username or password".
                user = re.escape(r.test_case.extra["user"])
                return r.status_code, re.sub(rf"(?<![\w-]){user}(?![\w-])", "<user>", r.response_body,
                                             flags=re.IGNORECASE).strip()

            if (known.status_code, known.response_body) == (u1.status_code, u1.response_body):
                continue
            if norm(u1) != norm(u2) or norm(known) == norm(u1):
                continue
            findings.append(Finding(
                title="User Enumeration: Login answers differently for existing users",
                description=(f"With a wrong password, {known.test_case.method} {known.test_case.url} answers "
                             f"differently for an existing username than for unknown ones, so attackers can "
                             f"list valid accounts before guessing passwords."),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.API2_AUTH,
                endpoint_method=known.test_case.method,
                endpoint_path=known.test_case.url,
                request_sample=_request_text(known, self.sensitive_headers),
                response_sample=_response_text(known),
                evidence=(f"existing user: HTTP {known.status_code} {known.response_body[:120]!r}; "
                          f"unknown user: HTTP {u1.status_code} {u1.response_body[:120]!r}"),
                remediation="Return the same status and message for a wrong username and a wrong password.",
                rule_id="FUZZOWL-ENUM-001",
            ))
        return findings

    def _analyze_nosqli_pairs(self, results: list[TestResult]) -> list[Finding]:
        """A $ne/$eq pair whose responses differ means the operator reached the query."""
        pairs: dict[str, dict[str, TestResult]] = {}
        for r in results:
            if r.test_case.extra.get("strategy") == "nosqli_pair" and not r.is_error:
                pairs.setdefault(r.test_case.extra["pair_id"], {})[r.test_case.extra["polarity"]] = r
        findings = []
        for pair in pairs.values():
            true, false = pair.get("true"), pair.get("false")
            if not true or not false or not true.is_success:
                continue
            # A limiter or server error on one side splits the pair for reasons unrelated to the query.
            if any(r.status_code == 429 or r.status_code >= 500 for r in (true, false)):
                continue
            len_t, len_f = len(true.response_body), len(false.response_body)
            if true.status_code == false.status_code and abs(len_t - len_f) <= max(20, 0.1 * max(len_t, len_f)):
                continue
            findings.append(self._injection_finding(
                true, "NoSQL Injection: Operator changes the result",
                "A $ne probe and an $eq-nonexistent probe on the same field returned different responses, "
                "so query operators reach the database.",
                f"$ne: HTTP {true.status_code}, {len_t} bytes; $eq: HTTP {false.status_code}, {len_f} bytes",
                "Reject objects/operators where scalars are expected; validate input types.",
                "FUZZOWL-INJECT-NOSQLI-BOOL", severity=Severity.HIGH))
        return findings

    def _check_rate_limit(self, result: TestResult) -> list[Finding]:  # noqa: ARG002
        return []

    def analyze_rate_limit(self, results: list[TestResult]) -> list[Finding]:
        """Aggregate burst results per endpoint to detect missing rate limiting."""
        bursts: dict[tuple[str, str], list[TestResult]] = {}
        for r in results:
            if r.test_case.check_id == "rate_limit" and not r.is_error:
                bursts.setdefault((r.test_case.method, r.test_case.url), []).append(r)

        findings = []
        for burst in bursts.values():
            total = len(burst)
            if total < burst[0].test_case.extra.get("burst_total", total):
                continue  # part of the burst failed or was cut off by --max-requests: no verdict
            success_count = sum(1 for r in burst if 200 <= r.status_code < 300)
            # Any 429, Retry-After or X-RateLimit-* header means a limiter exists (it may just allow more
            # than 50 requests).
            if any(_limited(r) for r in burst):
                continue
            tc = burst[0].test_case
            if success_count < total * 0.9:
                # Errors usually mean the burst wasn't accepted, except where errors ARE the answer to a guess.
                unthrottled = self._unthrottled_guessing(burst)
                if unthrottled:
                    findings.append(unthrottled)
                continue
            findings.append(Finding(
                title="Rate Limiting: Burst requests all succeeded",
                description=(
                    f"{success_count}/{total} burst requests returned 2xx. "
                    f"Endpoint appears to lack rate limiting."
                ),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.API4_RATE,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(burst[0], self.sensitive_headers),
                response_sample="",
                evidence=f"{success_count}/{total} burst requests succeeded",
                remediation="Implement rate limiting (token bucket, sliding window) per IP or user.",
                rule_id="FUZZOWL-RATE-001",
            ))
        _label_endpoints(findings, results)
        return findings

    def _unthrottled_guessing(self, burst: list[TestResult]) -> Finding | None:
        """A login/OTP/reset operation whose every attempt got the same error, first to last, with no throttling
        signal: wrong guesses can be repeated at full speed. Tentative: the error may also mean the request
        never reached the check (a malformed body), which only a person can tell."""
        tc = burst[0].test_case
        path = (tc.extra.get("endpoint_key") or tc.url).split(" ", 1)[-1]
        statuses = {r.status_code for r in burst}
        if (not _AUTH_SENSITIVE.search(path) or len(statuses) != 1 or 503 in statuses
                or not _resembles(burst[0], burst[-1])):
            return None
        status = burst[0].status_code
        return Finding(
            title="Rate Limiting: unthrottled attempts on an authentication operation",
            description=(f"All {len(burst)} burst requests to this authentication operation were answered "
                         f"HTTP {status} without any throttling: no 429, no Retry-After or rate-limit headers, "
                         f"and the last answer looks like the first (no lockout). Wrong passwords or codes can "
                         f"be guessed at full speed."),
            severity=Severity.MEDIUM,
            owasp_category=OWASPCategory.API4_RATE,
            endpoint_method=tc.method,
            endpoint_path=tc.url,
            request_sample=_request_text(burst[0], self.sensitive_headers),
            response_sample=_response_text(burst[-1]),
            evidence=f"{len(burst)}/{len(burst)} attempts answered HTTP {status}, none throttled",
            remediation="Limit attempts per account and per client (lockout or exponential delay after a few "
                        "failures) on login, one-time-code and reset operations.",
            rule_id="FUZZOWL-RATE-001",
            confidence="tentative",
        )

    def _check_cors(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        headers = result.response_headers
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        origin = tc.extra.get("origin", "")

        if acao and acao != "*" and origin in acao and acac == "true":
            return [Finding(
                title="CORS: Origin reflection with credentials allowed",
                description=(
                    f"Server reflects request Origin ({origin}) in Access-Control-Allow-Origin "
                    f"and sets Access-Control-Allow-Credentials: true. "
                    f"Cross-origin requests with credentials are permitted."
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.API8_MISCONFIG,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=_request_text(result, self.sensitive_headers),
                response_sample=str(redact_headers(headers))[:500],
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation=(
                    "Use a strict CORS allowlist. Never reflect Origin dynamically "
                    "when Access-Control-Allow-Credentials is true."
                ),
                rule_id="FUZZOWL-CORS-001",
            )]
        return []

    def _dedup(self, findings: list[Finding]) -> list[Finding]:
        """Keep highest severity finding per (rule_id, endpoint_method, endpoint_path)."""
        best: dict[tuple, Finding] = {}
        for f in findings:
            key = (f.rule_id, f.endpoint_method, f.endpoint_path)
            if key not in best:
                best[key] = f
            else:
                current = best[key]
                if _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[current.severity]:
                    best[key] = f
        return list(best.values())
