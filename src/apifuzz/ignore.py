"""Accepted findings (.apifuzz-ignore.yaml): known, reviewed findings that shouldn't fail CI again.

    ignore:
      - rule_id: APIFUZZ-RATE-001
        endpoint: "GET /health"            # spec operation; globs allowed; omit for every endpoint
        reason: rate limited at the gateway, not the app
        expires: 2027-01-31                # optional: the entry stops applying after this date
"""
import datetime
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from apifuzz.models.finding import Finding

DEFAULT_FILE = ".apifuzz-ignore.yaml"


@dataclass
class IgnoreRule:
    rule_id: str
    endpoint: str = "*"
    reason: str = ""
    expires: datetime.date | None = None

    def active(self, today: datetime.date) -> bool:
        return self.expires is None or today <= self.expires

    def matches(self, f: Finding) -> bool:
        return fnmatchcase(f.rule_id, self.rule_id) and fnmatchcase(f.endpoint or f.endpoint_path, self.endpoint)


def load(path: str | Path) -> list[IgnoreRule]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = doc.get("ignore", []) if isinstance(doc, dict) else []
    rules = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not e.get("rule_id"):
            raise ValueError(f"{path}: entry {i + 1} needs a rule_id")
        expires = e.get("expires")
        if isinstance(expires, str):
            expires = datetime.date.fromisoformat(expires)
        rules.append(IgnoreRule(str(e["rule_id"]), str(e.get("endpoint", "*")), str(e.get("reason", "")), expires))
    return rules


def apply(findings: list[Finding], rules: list[IgnoreRule],
          today: datetime.date | None = None) -> tuple[list[Finding], list[Finding], list[IgnoreRule]]:
    """(kept, suppressed, expired rules). Expired entries no longer suppress anything."""
    today = today or datetime.date.today()
    active = [r for r in rules if r.active(today)]
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        (suppressed if any(r.matches(f) for r in active) else kept).append(f)
    return kept, suppressed, [r for r in rules if not r.active(today)]


def write(findings: list[Finding], path: str | Path) -> int:
    """Write a starter ignore file accepting every current finding (one entry per rule and operation)."""
    seen = sorted({(f.rule_id, f.endpoint or f.endpoint_path) for f in findings})
    entries = [{"rule_id": r, "endpoint": e, "reason": "TODO: why this is accepted"} for r, e in seen]
    Path(path).write_text(yaml.safe_dump({"ignore": entries}, sort_keys=False), encoding="utf-8")
    return len(entries)
