import importlib.resources
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from apifuzz.models.finding import Finding


def _get_template_dir() -> str:
    # Resolve templates/ relative to the package root (two levels up from reporters/)
    pkg_root = Path(__file__).parent.parent.parent.parent  # src/apifuzz/reporters/ → project root
    templates_dir = pkg_root / "templates"
    if templates_dir.exists():
        return str(templates_dir)
    # Fallback: templates shipped inside package
    return str(Path(__file__).parent.parent / "templates")


class HTMLReporter:
    def __init__(self, template_dir: str | None = None):
        tdir = template_dir or _get_template_dir()
        env = Environment(
            loader=FileSystemLoader(tdir),
            autoescape=select_autoescape(["html", "j2"]),
        )
        self._template = env.get_template("report.html.j2")

    def generate(self, findings: list[Finding]) -> str:
        counts = {
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
            "info": sum(1 for f in findings if f.severity.value == "info"),
        }
        # Sort: critical first
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 99))

        # Build template-friendly dicts
        finding_dicts = [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "owasp_category": f.owasp_category.value,
                "endpoint_method": f.endpoint_method,
                "endpoint_path": f.endpoint_path,
                "evidence": f.evidence,
                "request_sample": f.request_sample,
                "response_sample": f.response_sample,
                "remediation": f.remediation,
                "rule_id": f.rule_id,
            }
            for f in sorted_findings
        ]

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return self._template.render(
            findings=finding_dicts,
            counts=counts,
            generated_at=generated_at,
        )

    def write(self, findings: list[Finding], path: str) -> None:
        html = self.generate(findings)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
