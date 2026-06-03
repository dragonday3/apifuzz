import re
from apifuzz.executor import TestResult
from apifuzz.models.finding import Finding, Severity, OWASPCategory

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]

_SQLI_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|syntax error|pg_exec|sqlite3\.OperationalError"
    r"|Microsoft OLE DB|ODBC SQL|Unclosed quotation mark|Incorrect syntax near)",
    re.IGNORECASE,
)
_SSTI_REFLECTED = re.compile(r"\b49\b")  # {{7*7}} = 49
_SSRF_METADATA = re.compile(
    r"(ami-id|instance-id|169\.254\.169\.254|localhost|127\.0\.0\.1|root:x:|/etc/passwd)",
    re.IGNORECASE,
)
_CMD_PATTERNS = re.compile(r"(uid=\d+|gid=\d+|\$ |# )", re.IGNORECASE)

_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


class Analyzer:
    def analyze(self, results: list[TestResult]) -> list[Finding]:
        raw: list[Finding] = []

        for result in results:
            if result.is_error:
                continue
            findings = self._dispatch(result)
            raw.extend(findings)

        return self._dedup(raw)

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

        if strategy == "cross_user" and result.status_code == 200:
            return [Finding(
                title="BOLA: Cross-user object access succeeded",
                description=(
                    f"Request using second token returned HTTP 200 on "
                    f"{tc.method} {tc.url}. Resource may be accessible across user boundaries."
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API1_BOLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=result.response_body[:500],
                evidence=f"HTTP {result.status_code} with cross-user token",
                remediation="Enforce object-level authorization: verify the requesting user owns the resource.",
                rule_id="APIFUZZ-BOLA-001",
            )]

        if strategy == "id_enumeration" and result.status_code == 200:
            return [Finding(
                title="BOLA: Enumerated object ID returned data",
                description=(
                    f"Probe ID {tc.extra.get('probe_id')} on {tc.method} {tc.url} "
                    f"returned HTTP 200. Possible IDOR vulnerability."
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.API1_BOLA,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=result.response_body[:500],
                evidence=f"HTTP {result.status_code} for probe ID {tc.extra.get('probe_id')}",
                remediation="Validate that returned object belongs to the authenticated user.",
                rule_id="APIFUZZ-BOLA-002",
            )]
        return []

    def _check_auth(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if result.status_code == 200:
            strategy = tc.extra.get("strategy", "unknown")
            descriptions = {
                "no_auth": "Endpoint returned 200 with no Authorization header.",
                "invalid_token": "Endpoint returned 200 with a known-invalid token.",
                "empty_bearer": "Endpoint returned 200 with an empty Bearer token.",
                "jwt_alg_none": "Endpoint accepted JWT with alg:none (signature bypass).",
                "malformed_scheme": "Endpoint returned 200 with a malformed auth scheme.",
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
                evidence=f"HTTP {result.status_code} returned with strategy: {strategy}",
                remediation="Require valid authentication on all protected endpoints.",
                rule_id=f"APIFUZZ-AUTH-{strategy.upper()[:10]}",
            )]
        return []

    def _check_mass_assignment(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        if result.status_code not in (200, 201):
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
                owasp_category=OWASPCategory.API6_MASS,
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
        if _SSRF_METADATA.search(result.response_body):
            return [Finding(
                title="SSRF: Internal metadata content in response",
                description=(
                    f"Response to {tc.label} contains content indicative of internal resource access "
                    f"(cloud metadata, localhost, /etc/passwd)."
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API7_SSRF,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=result.response_body[:500],
                evidence="Metadata pattern found in response body",
                remediation="Validate and allowlist URL parameters; block requests to internal networks.",
                rule_id="APIFUZZ-SSRF-001",
            )]
        return []

    def _check_injection(self, result: TestResult) -> list[Finding]:
        tc = result.test_case
        body = result.response_body
        injection_type = tc.extra.get("injection_type", "")
        findings = []

        if injection_type == "sqli" and _SQLI_ERRORS.search(body):
            findings.append(Finding(
                title="SQL Injection: Database error in response",
                description="Response to SQL injection probe contains a database error string.",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API8_INJECT,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=body[:500],
                evidence="Database error pattern in response",
                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                rule_id="APIFUZZ-INJECT-SQLI",
            ))
        elif injection_type == "ssti" and _SSTI_REFLECTED.search(body):
            findings.append(Finding(
                title="SSTI: Template expression evaluated in response",
                description="{{7*7}} was reflected as 49, indicating server-side template injection.",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API8_INJECT,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=body[:500],
                evidence="Template result '49' reflected in response",
                remediation="Never render user input through template engines without sanitization.",
                rule_id="APIFUZZ-INJECT-SSTI",
            ))
        elif injection_type == "cmd_injection" and _CMD_PATTERNS.search(body):
            findings.append(Finding(
                title="Command Injection: Shell output in response",
                description="Response contains patterns consistent with shell command execution (uid=, gid=).",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.API8_INJECT,
                endpoint_method=tc.method,
                endpoint_path=tc.url,
                request_sample=tc.label,
                response_sample=body[:500],
                evidence="Shell output pattern in response",
                remediation="Never pass user input to shell commands. Use safe APIs.",
                rule_id="APIFUZZ-INJECT-CMD",
            ))
        return findings

    def _check_rate_limit(self, result: TestResult) -> list[Finding]:  # noqa: ARG002
        return []

    def analyze_rate_limit(self, results: list[TestResult]) -> list[Finding]:
        """Aggregate burst results to detect missing rate limiting."""
        burst = [r for r in results if r.test_case.check_id == "rate_limit" and not r.is_error]
        if not burst:
            return []

        success_count = sum(1 for r in burst if 200 <= r.status_code < 300)
        total = len(burst)
        if total == 0:
            return []

        if success_count >= total * 0.9:
            tc = burst[0].test_case
            return [Finding(
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
            )]
        return []

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
                owasp_category=OWASPCategory.API8_INJECT,
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
