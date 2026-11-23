from enum import Enum
from typing import Literal

from pydantic import BaseModel

Confidence = Literal["firm", "tentative"]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    API1_BOLA  = "API1:2023 - Broken Object Level Authorization"
    API2_AUTH  = "API2:2023 - Broken Authentication"
    API3_BOPLA = "API3:2023 - Broken Object Property Level Authorization"
    API4_RATE  = "API4:2023 - Unrestricted Resource Consumption"
    API5_BFLA  = "API5:2023 - Broken Function Level Authorization"
    API6_BUSINESS_FLOWS = "API6:2023 - Unrestricted Access to Sensitive Business Flows"
    API7_SSRF  = "API7:2023 - Server Side Request Forgery"
    API8_MISCONFIG = "API8:2023 - Security Misconfiguration"
    API9_INVENTORY = "API9:2023 - Improper Inventory Management"
    API10_UNSAFE   = "API10:2023 - Unsafe Consumption of APIs"
    # Injection has no OWASP API 2023 category; map to the general OWASP Top 10.
    INJECTION = "A03:2021 Injection (OWASP Top 10)"


class Finding(BaseModel):
    title: str
    description: str
    severity: Severity
    owasp_category: OWASPCategory
    endpoint_method: str
    endpoint_path: str
    request_sample: str = ""
    response_sample: str = ""
    evidence: str = ""
    remediation: str = ""
    rule_id: str = ""            # for SARIF output
    # firm: confirmed by comparison (baseline, second request, persistence check);
    # tentative: plausible signal that needs manual verification.
    confidence: Confidence = "firm"
    # The spec operation ("GET /users/{id}"); endpoint_path is the concrete probe URL. Benchmarks score by this.
    endpoint: str = ""
