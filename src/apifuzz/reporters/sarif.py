import json
from typing import Any
from apifuzz.models.finding import Finding, OWASPCategory

TOOL_NAME = "apifuzz"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/dragonday3/apifuzz"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecificationDrafts/CSD01/sarif-schema-2.1.0.json"

_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_OWASP_HELP = {
    OWASPCategory.API1_BOLA: "Broken Object Level Authorization — verify object ownership before returning data.",
    OWASPCategory.API2_AUTH: "Broken Authentication — require valid credentials on all protected endpoints.",
    OWASPCategory.API3_BOPLA: "Broken Object Property Level Authorization — restrict response fields per user.",
    OWASPCategory.API4_RATE: "Unrestricted Resource Consumption — implement rate limiting per IP/user.",
    OWASPCategory.API5_BFLA: "Broken Function Level Authorization — enforce role checks on admin functions.",
    OWASPCategory.API6_MASS: "Unrestricted Access to Sensitive Business Flows / Mass Assignment — allowlist accepted fields.",
    OWASPCategory.API7_SSRF: "Server Side Request Forgery — validate and allowlist URL-type parameters.",
    OWASPCategory.API8_INJECT: "Security Misconfiguration / Injection — sanitize inputs and use parameterized queries.",
    OWASPCategory.API9_INVENTORY: "Improper Inventory Management — document and monitor all API versions.",
    OWASPCategory.API10_UNSAFE: "Unsafe Consumption of APIs — validate data from third-party APIs.",
}


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        help_text = _OWASP_HELP.get(f.owasp_category, f.owasp_category.value)
        seen[f.rule_id] = {
            "id": f.rule_id,
            "name": f.title.replace(" ", "").replace(":", "").replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "helpUri": TOOL_INFO_URI,
            "help": {"text": help_text, "markdown": help_text},
            "properties": {
                "tags": [f.owasp_category.value],
                "security-severity": _owasp_security_severity(f),
            },
        }
    return list(seen.values())


def _owasp_security_severity(finding: Finding) -> str:
    """CVSS-ish numeric string for GitHub security tab sorting."""
    scores = {
        "critical": "9.8",
        "high": "8.1",
        "medium": "5.3",
        "low": "3.1",
        "info": "0.0",
    }
    return scores.get(finding.severity.value, "0.0")


def _build_result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_LEVEL.get(finding.severity.value, "warning"),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.endpoint_path,
                        "uriBaseId": "%APIROOT%",
                    }
                },
                "logicalLocations": [
                    {
                        "name": f"{finding.endpoint_method} {finding.endpoint_path}",
                        "kind": "function",
                    }
                ],
            }
        ],
        "properties": {
            "owasp_category": finding.owasp_category.value,
            "severity": finding.severity.value,
            "remediation": finding.remediation,
        },
    }
    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence
    if finding.request_sample:
        result["properties"]["request_sample"] = finding.request_sample
    if finding.response_sample:
        result["properties"]["response_sample"] = finding.response_sample
    return result


class SARIFReporter:
    def generate(self, findings: list[Finding]) -> dict[str, Any]:
        rules = _build_rules(findings)
        results = [_build_result(f) for f in findings]

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": TOOL_VERSION,
                            "informationUri": TOOL_INFO_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "totalFindings": len(findings),
                        "criticalCount": sum(1 for f in findings if f.severity.value == "critical"),
                        "highCount": sum(1 for f in findings if f.severity.value == "high"),
                        "mediumCount": sum(1 for f in findings if f.severity.value == "medium"),
                    },
                }
            ],
        }

    def write(self, findings: list[Finding], path: str) -> None:
        sarif = self.generate(findings)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
