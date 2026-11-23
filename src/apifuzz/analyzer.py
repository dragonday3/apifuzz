import json
import re
from typing import Any

from apifuzz.checks.injection import CMD_CANARY, SSTI_PRODUCT
from apifuzz.executor import TestResult
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


def _json(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return None


def _same_object(a: str, b: str) -> bool:
    """Do two response bodies describe the same object? Identical, or the same identifying fields."""
    if a == b:
        return True
    ja, jb = _json(a), _json(b)
    if not (isinstance(ja, dict) and isinstance(jb, dict)):
        return False
    keys = [k for k in ja if _IDENTIFYING_KEY.match(k) and k in jb and ja[k] not in (None, "")]
    return bool(keys) and all(ja[k] == jb[k] for k in keys)


def _resembles(a: TestResult, b: TestResult) -> bool:
    """Same status and essentially the same body: identical, or within 10% (min 20 bytes) in length."""
    if a.status_code != b.status_code:
        return False
    if a.response_body == b.response_body:
        return True
    la, lb = len(a.response_body), len(b.response_body)
    return abs(la - lb) <= max(20, 0.1 * max(la, lb))


class Analyzer:
    def analyze(self, results: list[TestResult]) -> list[Finding]:
        # Baseline = one normal request per endpoint with the configured auth (Scanner adds it).
        # Detectors compare against it: status, body, length, latency.
        self._baselines: dict[str | None, TestResult] = {
            r.test_case.extra.get("endpoint_key"): r
            for r in results if r.test_case.check_id == "baseline" and not r.is_error
        }
        raw: list[Finding] = []

        for result in results:
            if result.is_error:
                continue
            findings = self._dispatch(result)
            raw.extend(findings)

        raw.extend(self._analyze_nosqli_pairs(results))
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

        if strategy == "cross_user":
            # User B reading user A's object. Firm only if B got A's object back; a 2xx with B's own
            # data or a soft-fail body is not BOLA. No baseline (DELETE) -> tentative.
            if base is not None and not (base.is_success and _same_object(base.response_body,
                                                                           result.response_body)):
                return []
            confidence: Confidence = "firm" if base is not None else "tentative"
            return [Finding(
                title="BOLA: Cross-user object access succeeded",
                description=(
                    f"Using the second user's token, {tc.method} {tc.url} returned the first user's object. "
                    f"Object-level authorization is not enforced."
                    if base is not None else
                    f"Using the second user's token, {tc.method} {tc.url} returned HTTP {result.status_code}. "
                    f"No baseline to confirm whose object it was; verify manually."
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API1_BOLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=result.response_body[:500],
                evidence=(f"HTTP {result.status_code} with cross-user token; response matches user A's object"
                          if base is not None else f"HTTP {result.status_code} with cross-user token"),
                remediation="Enforce object-level authorization: verify the requesting user owns the resource.",
                rule_id="APIFUZZ-BOLA-001",
                confidence=confidence,
            )]

        if strategy == "id_enumeration":
            # A 200 alone isn't a finding: most APIs have an object 1. Tentative only when the probed ID
            # returns an object shaped like the caller's own (same keys) but a different one.
            if base is None or not base.is_success or _same_object(base.response_body, result.response_body):
                return []
            mine, theirs = _json(base.response_body), _json(result.response_body)
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
                request_sample=tc.label,
                response_sample=result.response_body[:500],
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
            request_sample=tc.label,
            response_sample=result.response_body[:500],
            evidence=f"HTTP {result.status_code} returned with strategy: {strategy}{matched}",
            remediation="Require valid authentication on all protected endpoints.",
            rule_id=f"APIFUZZ-AUTH-{strategy.upper()[:10]}",
            confidence=confidence,
        )]

    def _check_mass_assignment(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if not result.is_success:
            return []
        body = result.response_body.lower()
        injected = tc.extra.get("injected_fields", [])
        reflected = [f for f in injected if f.lower() in body]
        if reflected:
            return [Finding(
                title="Mass Assignment: Privileged fields reflected in response",
                description=(
                    f"Server reflected injected privileged fields in response: {reflected}. "
                    f"Endpoint may allow mass assignment of protected attributes."
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.API3_BOPLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=result.response_body[:500],
                evidence=f"Reflected fields: {reflected}",
                remediation="Use an allowlist for accepted fields; never bind request body directly to model.",
                rule_id="APIFUZZ-MASS-001",
            )]
        return []

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
                request_sample=tc.label,
                response_sample=result.response_body[:500],
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
            request_sample=tc.label,
            response_sample=result.response_body[:500],
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
            success_count = sum(1 for r in burst if 200 <= r.status_code < 300)
            total = len(burst)
            if success_count < total * 0.9:
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
                request_sample=tc.label,
                response_sample="",
                evidence=f"{success_count}/{total} burst requests succeeded",
                remediation="Implement rate limiting (token bucket, sliding window) per IP or user.",
                rule_id="APIFUZZ-RATE-001",
            ))
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
                request_sample=tc.label,
                response_sample=str(dict(headers))[:500],
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
