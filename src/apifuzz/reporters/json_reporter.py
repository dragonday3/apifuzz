import json
from typing import Any

from apifuzz.models.finding import Finding


class JSONReporter:
    def generate(self, findings: list[Finding],
                 oob_probes: dict[str, str] | None = None) -> list[dict] | dict[str, Any]:
        """A list of findings. With blind-SSRF probes (--oob-url), an object instead:
        {"findings": [...], "oob_probes": {"apifuzz-<id>": "METHOD /path [param]"}}."""
        data = [f.model_dump() for f in findings]
        return {"findings": data, "oob_probes": oob_probes} if oob_probes else data

    def write(self, findings: list[Finding], path: str, oob_probes: dict[str, str] | None = None) -> None:
        data = self.generate(findings, oob_probes)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
