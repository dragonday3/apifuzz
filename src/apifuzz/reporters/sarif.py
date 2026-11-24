import hashlib
from urllib.parse import quote
import json
from typing import Any
from apifuzz import __version__
from apifuzz.models.finding import Finding, OWASPCategory

TOOL_NAME = "apifuzz"
TOOL_VERSION = __version__  # one version, in apifuzz/__init__.py
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
    OWASPCategory.API3_BOPLA: (
        "Broken Object Property Level Authorization / Mass Assignment — allowlist writable fields "
        "and restrict response fields per user."
    ),
    OWASPCategory.API4_RATE: "Unrestricted Resource Consumption — implement rate limiting per IP/user.",
    OWASPCategory.API5_BFLA: "Broken Function Level Authorization — enforce role checks on admin functions.",
    OWASPCategory.API6_BUSINESS_FLOWS: "Unrestricted Access to Sensitive Business Flows — limit automated abuse of flows.",
    OWASPCategory.API7_SSRF: "Server Side Request Forgery — validate and allowlist URL-type parameters.",
    OWASPCategory.API8_MISCONFIG: "Security Misconfiguration — harden CORS, headers and defaults.",
    OWASPCategory.API9_INVENTORY: "Improper Inventory Management — document and monitor all API versions.",
    OWASPCategory.API10_UNSAFE: "Unsafe Consumption of APIs — validate data from third-party APIs.",
    OWASPCategory.INJECTION: "Injection — use parameterized queries and never pass input to interpreters or shells.",
}


# GitHub fails a code-scanning check on the rule's security-severity (High+ by default), not the result
# level, so tentative findings get their own rule capped at medium.
TENTATIVE_SECURITY_SEVERITY = "5.0"


def _rule_id(finding: Finding) -> str:
    return f"{finding.rule_id}/tentative" if finding.confidence == "tentative" else finding.rule_id


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        rule_id = _rule_id(f)
        if rule_id in seen:
            continue
        help_text = _OWASP_HELP.get(f.owasp_category, f.owasp_category.value)
        seen[rule_id] = {
            "id": rule_id,
            "name": f.title.replace(" ", "").replace(":", "").replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "helpUri": TOOL_INFO_URI,
            "help": {"text": help_text, "markdown": help_text},
            "properties": {
                "tags": [f.owasp_category.value],
                "security-severity": (TENTATIVE_SECURITY_SEVERITY if f.confidence == "tentative"
                                      else _owasp_security_severity(f)),
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


def _location_uri(finding: Finding) -> str:
    if finding.endpoint and " " in finding.endpoint:
        return quote(finding.endpoint.split(" ", 1)[1], safe="/")
    return finding.endpoint_path


def _fingerprint(finding: Finding) -> str:
    """Stable across runs: rule + method + spec operation. Probe URLs carry random ids and payloads, so the
    concrete URL is used only when the operation is unknown."""
    key = "|".join([finding.rule_id, finding.endpoint_method, finding.endpoint or finding.endpoint_path,
                    finding.parameter])
    return hashlib.sha256(key.encode()).hexdigest()


def _build_result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        # GitHub code scanning uses this to recognise the same alert across runs instead of opening a new one.
        "partialFingerprints": {"apifuzzFinding/v1": _fingerprint(finding)},
        # Tentative findings need manual verification: never "error", so they don't fail a PR check.
        "level": "note" if finding.confidence == "tentative" else _SEVERITY_LEVEL.get(finding.severity.value,
                                                                                       "warning"),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        # The spec operation's path when known: probe URLs change every run.
                        "uri": _location_uri(finding),
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
            "confidence": finding.confidence,
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
    def generate(self, findings: list[Finding], oob_probes: dict[str, str] | None = None) -> dict[str, Any]:
        rules = _build_rules(findings)
        results = [_build_result(f) for f in findings]

        sarif: dict[str, Any] = {
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
        if oob_probes:  # blind-SSRF callbacks arrive later at the collector: map "apifuzz-<id>" back to a parameter
            sarif["runs"][0]["properties"]["oobProbes"] = oob_probes
        return sarif

    def write(self, findings: list[Finding], path: str, oob_probes: dict[str, str] | None = None) -> None:
        sarif = self.generate(findings, oob_probes)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
