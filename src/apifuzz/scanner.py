import json
from pathlib import Path
from typing import Any

from apifuzz.analyzer import Analyzer
from apifuzz.checks.auth import AuthCheck
from apifuzz.checks.bola import BOLACheck
from apifuzz.checks.cors import CORSCheck
from apifuzz.checks.injection import InjectionCheck
from apifuzz.checks.mass_assignment import MassAssignmentCheck
from apifuzz.checks.rate_limit import RateLimitCheck
from apifuzz.checks.ssrf import SSRFCheck
from apifuzz.executor import Executor, TestCase
from apifuzz.models.endpoint import AuthConfig, Endpoint
from apifuzz.models.finding import Finding
from apifuzz.parsers.har import HARParser
from apifuzz.parsers.openapi import OpenAPIParser
from apifuzz.parsers.postman import PostmanParser

_ALL_CHECKS = {
    "bola": BOLACheck,
    "auth": AuthCheck,
    "mass_assignment": MassAssignmentCheck,
    "ssrf": SSRFCheck,
    "injection": InjectionCheck,
    "rate_limit": RateLimitCheck,
    "cors": CORSCheck,
}


def _detect_format(path: str) -> str:
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".har":
        return "har"
    if suffix in (".yaml", ".yml", ".json"):
        # Peek at content to distinguish OpenAPI from Postman
        try:
            content = p.read_text(encoding="utf-8")
            data: Any = None
            if suffix == ".json":
                data = json.loads(content)
            else:
                import yaml
                data = yaml.safe_load(content)
            if isinstance(data, dict):
                if "info" in data and "item" in data:
                    return "postman"
                if "openapi" in data or "swagger" in data or "paths" in data:
                    return "openapi"
        except Exception:
            pass
        return "openapi"
    return "openapi"


class Scanner:
    def __init__(
        self,
        spec_path: str,
        base_url: str,
        auth: AuthConfig | None = None,
        checks: list[str] | None = None,
        concurrency: int = 10,
        rate_limit_rps: float = 10.0,
        timeout: float = 15.0,
    ):
        self.spec_path = spec_path
        self.base_url = base_url.rstrip("/")
        self.auth = auth or AuthConfig()
        self.executor = Executor(self.auth, concurrency, rate_limit_rps, timeout)
        self.analyzer = Analyzer()

        enabled = checks if checks else list(_ALL_CHECKS.keys())
        self._checks = [_ALL_CHECKS[c]() for c in enabled if c in _ALL_CHECKS]

    async def run(self) -> list[Finding]:
        endpoints = self._parse(self.spec_path)

        # Inject base_url from CLI into each endpoint that doesn't have one
        for ep in endpoints:
            if not ep.base_url:
                ep.base_url = self.base_url

        test_cases = self._generate(endpoints)
        results = await self.executor.run(test_cases)

        findings = self.analyzer.analyze(results)

        # Rate limit aggregation (burst results need separate handling)
        findings += self.analyzer.analyze_rate_limit(results)

        return findings

    def _parse(self, path: str) -> list[Endpoint]:
        fmt = _detect_format(path)
        parsers = {
            "openapi": OpenAPIParser,
            "har": HARParser,
            "postman": PostmanParser,
        }
        parser_cls = parsers.get(fmt, OpenAPIParser)
        return parser_cls().parse(path)

    def _generate(self, endpoints: list[Endpoint]) -> list[TestCase]:
        test_cases: list[TestCase] = []
        for endpoint in endpoints:
            for check in self._checks:
                test_cases.extend(check.generate(endpoint, self.auth))
        return test_cases
