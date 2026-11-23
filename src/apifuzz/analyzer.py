import json
import re
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit

from apifuzz.checks.bola import MISSING_ID
from apifuzz.checks.injection import CMD_CANARY, SQLI_SLEEP_SECONDS, SSTI_PRODUCT
from apifuzz.executor import MAX_BODY, TestCase, TestResult
from apifuzz.redact import mask, redact_headers
from apifuzz.models.finding import Confidence, Finding, OWASPCategory, Severity

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


def _label_endpoints(findings: list[Finding], results: list[TestResult]) -> None:
    """Every finding's endpoint_path is the URL of the probe that produced it: map it back to its operation."""
    keys = {(r.test_case.method, r.test_case.url): r.test_case.extra.get("endpoint_key", "") for r in results}
    for f in findings:
        f.endpoint = f.endpoint or keys.get((f.endpoint_method, f.endpoint_path), "")


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
        excerpt += f"\n[response truncated at {MAX_BODY} bytes; detection only saw the first {MAX_BODY}]"
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
    def __init__(self, sensitive_headers: tuple[str, ...] = ()):
        # Extra header names to mask in request samples (the configured --header-name for apikey auth).
        self.sensitive_headers = sensitive_headers

    def analyze(self, results: list[TestResult]) -> list[Finding]:
        # Baseline = one normal request per endpoint with the configured auth (Scanner adds it).
        # Detectors compare against it: status, body, length, latency.
        self._baselines: dict[str | None, TestResult] = {
            r.test_case.extra.get("endpoint_key"): r
            for r in results if r.test_case.check_id == "baseline" and not r.is_error
        }
        # What the endpoint answers for an object that can't exist: a 200 {"message": "not found"} must
        # not count as "user B got user A's object".
        self._missing: dict[str | None, TestResult] = {
            r.test_case.extra.get("endpoint_key"): r
            for r in results if r.test_case.check_id == "bola" and not r.is_error
            and r.test_case.extra.get("probe_id") == MISSING_ID
        }
        raw: list[Finding] = []

        for result in results:
            if result.is_error:
                continue
            findings = self._dispatch(result)
            raw.extend(findings)

        raw.extend(self._analyze_nosqli_pairs(results))
        raw.extend(self._analyze_sqli_blind(results))
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

        if strategy == "cross_user":
            # User B reading user A's object. Firm only if B got A's object back; a 2xx with B's own
            # data or a soft-fail body is not BOLA. No baseline (DELETE) -> tentative.
            confirmed = base is not None and base.is_success and _same_object(base.response_body,
                                                                               result.response_body, keys)
            if base is not None and not confirmed and base.response_body.strip():
                return []  # A's object has a body and B didn't get it back
            # Firm only when B's response is A's object. Empty write responses (204) can't show whose
            # object changed, and without a baseline (DELETE) there is nothing to compare: tentative.
            confidence: Confidence = "firm" if confirmed else "tentative"
            return [Finding(
                title="BOLA: Cross-user object access succeeded",
                description=(
                    f"Using the second user's token, {tc.method} {tc.url} returned the first user's object. "
                    f"Object-level authorization is not enforced."
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
                          if confirmed else f"HTTP {result.status_code} with cross-user token"),
                remediation="Enforce object-level authorization: verify the requesting user owns the resource.",
                rule_id="APIFUZZ-BOLA-001",
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
                rule_id="APIFUZZ-BOLA-002",
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
            "malformed_scheme": "Endpoint returned 2xx with a malformed auth scheme.",
        }
        return [Finding(
            title=f"Broken Auth: {strategy.replace('_', ' ').title()} accepted",
            description=descriptions.get(strategy, f"Auth bypass via {strategy}"),
            severity=Severity.CRITICAL if strategy in ("no_auth", "jwt_alg_none") else Severity.HIGH,
            owasp_category=OWASPCategory.API2_AUTH,
            endpoint_method=tc.method,
            endpoint_path=tc.url,
            request_sample=_request_text(result, self.sensitive_headers),
            response_sample=_response_text(result),
            evidence=f"HTTP {result.status_code} returned with strategy: {strategy}{matched}",
            remediation="Require valid authentication on all protected endpoints.",
            rule_id=f"APIFUZZ-AUTH-{strategy.upper()[:10]}",
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
            rule_id="APIFUZZ-MASS-001",
            confidence=confidence,
        )

    def followups(self, results: list[TestResult]) -> list[TestCase]:
        """Second-pass requests that confirm first-pass signals. Mass assignment: GET the resource the
        probe created or updated (Location header, the same URL for PUT/PATCH, or <url>/<id> for POST)."""
        out = []
        for r in results:
            tc = r.test_case
            if tc.check_id != "mass_assignment" or not r.is_success:
                continue
            url = _resource_url(r)
            if url:
                out.append(TestCase(
                    method="GET", url=url, headers={}, params={}, body=None,
                    label=f"MassAssignment verify: GET {url}", check_id="mass_assignment_verify",
                    extra={"verifies": f"{tc.method} {tc.url}", "endpoint_key": tc.extra.get("endpoint_key")},
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
            stored = [f for f in _fields_with_values(v.response_body, injected) if f not in already]
            if not stored:
                continue
            raw[:] = [f for f in raw if not (f.rule_id == "APIFUZZ-MASS-001" and f.endpoint_path == probe.test_case.url
                                             and f.endpoint_method == probe.test_case.method)]
            raw.append(self._mass_finding(probe, stored, "firm",
                                          f"{v.test_case.label} returned the injected values: {stored}"))

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
                rule_id="APIFUZZ-SSRF-001",
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
                "Use parameterized queries. Never concatenate user input into SQL.", "APIFUZZ-INJECT-SQLI")]
        if (injection_type == "ssti" and SSTI_PRODUCT in body and "1337*7331" not in body
                and SSTI_PRODUCT not in baseline):
            return [self._injection_finding(
                result, "SSTI: Template expression evaluated in response",
                f"1337*7331 was evaluated to {SSTI_PRODUCT}, indicating server-side template injection.",
                f"'{SSTI_PRODUCT}' in response, payload not reflected literally, absent from baseline",
                "Never render user input through template engines without sanitization.", "APIFUZZ-INJECT-SSTI")]
        if injection_type == "cmd_injection":
            uid = _CMD_UID.search(body)
            shown = uid.group(0) if uid else (CMD_CANARY if CMD_CANARY in body else "")
            if shown and not (_CMD_UID.search(baseline) or CMD_CANARY in baseline):
                return [self._injection_finding(
                    result, "Command Injection: Shell output in response",
                    "Response contains output of an injected shell command.",
                    f"Shell output '{shown}' in response",
                    "Never pass user input to shell commands. Use safe APIs.", "APIFUZZ-INJECT-CMD")]
        if injection_type == "xss":
            payload = tc.extra.get("payload", "")
            ctype = result.response_headers.get("content-type", "")
            if payload and payload in body and "text/html" in ctype:
                return [self._injection_finding(
                    result, "XSS: Payload reflected unescaped in HTML response",
                    "The script payload is reflected verbatim in a text/html response.",
                    f"Unescaped '{payload}' in {ctype} response",
                    "HTML-encode output and return JSON with application/json.", "APIFUZZ-INJECT-XSS",
                    severity=Severity.MEDIUM)]
        if injection_type == "nosqli" and _NOSQL_ERRORS.search(body) and not _NOSQL_ERRORS.search(baseline):
            return [self._injection_finding(
                result, "NoSQL Injection: Database error in response",
                "Response to a NoSQL operator probe contains a MongoDB error signature.",
                "MongoDB error pattern in response",
                "Reject objects/operators where scalars are expected; validate input types.",
                "APIFUZZ-INJECT-NOSQLI", severity=Severity.HIGH)]
        return []

    def _analyze_sqli_blind(self, results: list[TestResult]) -> list[Finding]:
        """Boolean: true answers like the control, false doesn't. Time: every repeat of a sleep payload
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
                        "APIFUZZ-INJECT-SQLI-TIME"))
                continue
            control, true, false = (g.get(k, [None])[0] for k in ("control", "true", "false"))
            if not (control and true and false) or not control.is_success:
                continue
            if any(r.status_code == 429 or r.status_code >= 500 for r in (true, false)):
                continue
            if _resembles(true, control) and not _resembles(false, control):
                findings.append(self._injection_finding(
                    true, "SQL Injection: Boolean-based (true/false conditions change the response)",
                    "Appending a true condition returned the same response as the original value, a false "
                    "condition changed it, so the input is evaluated as SQL.",
                    f"control: HTTP {control.status_code}, {len(control.response_body)} bytes; "
                    f"AND '1'='1: HTTP {true.status_code}, {len(true.response_body)} bytes; "
                    f"AND '1'='2: HTTP {false.status_code}, {len(false.response_body)} bytes",
                    "Use parameterized queries. Never concatenate user input into SQL.",
                    "APIFUZZ-INJECT-SQLI-BOOL"))
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
                "APIFUZZ-INJECT-NOSQLI-BOOL", severity=Severity.HIGH))
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
            # 4xx answers mean the burst wasn't accepted anyway; any 429, Retry-After or X-RateLimit-*
            # header means a limiter exists (it may just allow more than 50 requests).
            if success_count < total * 0.9 or any(_limited(r) for r in burst):
                continue
            tc = burst[0].test_case
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
                rule_id="APIFUZZ-RATE-001",
            ))
        _label_endpoints(findings, results)
        return findings

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
                rule_id="APIFUZZ-CORS-001",
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
