import json
from apifuzz.models.finding import Finding


class JSONReporter:
    def generate(self, findings: list[Finding]) -> list[dict]:
        return [f.model_dump() for f in findings]

    def write(self, findings: list[Finding], path: str) -> None:
        data = self.generate(findings)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
