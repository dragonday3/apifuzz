"""Accepted findings (.fuzzowl-ignore.yaml): known, reviewed findings that shouldn't fail CI again.

    ignore:
      - rule_id: FUZZOWL-RATE-001
        endpoint: "GET /health"            # spec operation; globs allowed; omit for every endpoint
        reason: rate limited at the gateway, not the app
        expires: 2027-01-31                # optional: the entry stops applying after this date
"""
import datetime
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from fuzzowl.models.finding import Finding

DEFAULT_FILE = ".fuzzowl-ignore.yaml"


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


def _date(value: object, where: str) -> datetime.date | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            pass
    raise ValueError(f"{where}: expires must be a date like 2027-01-31, got {value!r}")


def load(path: str | Path) -> list[IgnoreRule]:
    """Every problem is a ValueError raised here, before the scan runs."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: expected a mapping with an 'ignore:' list")
    entries = doc.get("ignore") or []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'ignore' must be a list of entries")
    rules = []
    for i, e in enumerate(entries, 1):
        where = f"{path}: entry {i}"
        if not isinstance(e, dict) or not e.get("rule_id"):
            raise ValueError(f"{where} needs a rule_id")
        rules.append(IgnoreRule(str(e["rule_id"]), str(e.get("endpoint", "*")), str(e.get("reason", "")),
                                _date(e.get("expires"), where)))
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


def write(findings: list[Finding], path: str | Path, existing: list[IgnoreRule] | None = None) -> int:
    """Write an ignore file accepting every finding. Entries already in the file are kept as they are (reason,
    expiry); one new entry is added per rule and operation not already covered. Returns the number added."""
    existing = existing or []
    new: list[IgnoreRule] = []
    for f in sorted(findings, key=lambda f: (f.rule_id, f.endpoint or f.endpoint_path)):
        if not any(r.matches(f) for r in existing + new):
            new.append(IgnoreRule(f.rule_id, f.endpoint or f.endpoint_path, "TODO: why this is accepted"))

    def entry(r: IgnoreRule) -> dict:
        d: dict = {"rule_id": r.rule_id, "endpoint": r.endpoint, "reason": r.reason}
        if r.expires:
            d["expires"] = r.expires.isoformat()
        return d
    Path(path).write_text(yaml.safe_dump({"ignore": [entry(r) for r in existing + new]}, sort_keys=False),
                          encoding="utf-8")
    return len(new)
