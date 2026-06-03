from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    API1_BOLA = "API1:2023 - Broken Object Level Authorization"
    API2_AUTH = "API2:2023 - Broken Authentication"
    API3_BOPLA = "API3:2023 - Broken Object Property Level Authorization"
    API4_RATE = "API4:2023 - Unrestricted Resource Consumption"
    API6_MASS = "API6:2023 - Unrestricted Access to Sensitive Business Flows"
    API7_SSRF = "API7:2023 - Server Side Request Forgery"
    API8_INJECT = "API8:2023 - Security Misconfiguration"


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
