import json
from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import httpx

from apifuzz.analyzer import Analyzer
from apifuzz.checks.auth import AuthCheck
from apifuzz.checks.base import BaseCheck, build_url
from apifuzz.checks.bola import BOLACheck
from apifuzz.checks.cors import CORSCheck
from apifuzz.checks.data_exposure import DataExposureCheck
from apifuzz.checks.injection import InjectionCheck
from apifuzz.checks.inventory import InventoryCheck
from apifuzz.checks.mass_assignment import MassAssignmentCheck
from apifuzz.checks.rate_limit import RateLimitCheck
from apifuzz.checks.ssrf import SSRFCheck
from apifuzz.checks.user_enum import UserEnumCheck
from apifuzz.executor import Executor, RequestBudget, TestCase
from apifuzz.models.endpoint import AuthConfig, Endpoint
from apifuzz.models.finding import Finding
from apifuzz.parsers.base import BaseParser
from apifuzz.parsers.har import HARParser
from apifuzz.parsers.openapi import OpenAPIParser
from apifuzz.parsers.postman import PostmanParser
from apifuzz.redact import scrub, secrets_for

_ALL_CHECKS: dict[str, type[BaseCheck]] = {
    "bola": BOLACheck,
    "auth": AuthCheck,
    "mass_assignment": MassAssignmentCheck,
    "ssrf": SSRFCheck,
    "injection": InjectionCheck,
    "rate_limit": RateLimitCheck,
    "cors": CORSCheck,
    "data_exposure": DataExposureCheck,
    "user_enum": UserEnumCheck,
    "inventory": InventoryCheck,
}


# Methods that modify or remove existing objects: skipped unless --allow-destructive.
DESTRUCTIVE_METHODS = {"PUT", "PATCH", "DELETE"}

# Checks whose detectors compare against the per-endpoint baseline request.
_BASELINE_CHECKS = {"auth", "bola", "injection", "mass_assignment", "ssrf"}


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
        time_based: bool = False,
        *,
        allow_destructive: bool = False,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        max_requests: int | None = None,
        verify: bool = True,
        proxy: str | None = None,
        retries: int = 2,
    ):
        self.spec_path = spec_path
        self.base_url = base_url.rstrip("/")
        self.auth = auth or AuthConfig()
        self.allow_destructive = allow_destructive
        self.include, self.exclude = include or [], exclude or []
        self.skipped: list[str] = []  # "METHOD /path (reason)" for endpoints filtered out
        self.budget = RequestBudget(max_requests)
        # Every executor of the scan shares the scope lock (target origin), TLS/proxy settings and budget.
        self._executor_opts = dict(rate_limit_rps=rate_limit_rps, timeout=timeout, verify=verify, proxy=proxy,
                                   scope=self.base_url, budget=self.budget, retries=retries)
        self.executor = Executor(self.auth, concurrency, **self._executor_opts)  # type: ignore[arg-type]
        self.analyzer = Analyzer(sensitive_headers=(self.auth.header_name,))
        self.errors: Counter[str] = Counter()  # failed requests by error type (OutOfScope, ConnectError...)
        self.sent = 0

        enabled = checks if checks else list(_ALL_CHECKS.keys())
        self._checks = [_ALL_CHECKS[c]() for c in enabled if c in _ALL_CHECKS]
        for check in self._checks:
            if isinstance(check, InjectionCheck):
                check.time_based = time_based

    def plan(self) -> list[TestCase]:
        """The first-pass test cases a scan would send (follow-up confirmations depend on responses)."""
        return self._generate(self._endpoints())

    def _endpoints(self) -> list[Endpoint]:
        self.skipped = []
        kept = []
        for ep in self._parse(self.spec_path):
            # --target is authoritative: HAR/Postman/spec hosts are never used, so nothing leaves the scope.
            ep.base_url = self.base_url
            name = f"{ep.method} {ep.path}"
            if ep.method in DESTRUCTIVE_METHODS and not self.allow_destructive:
                self.skipped.append(f"{name} (destructive; use --allow-destructive)")
            elif self.include and not any(fnmatchcase(ep.path, g) for g in self.include):
                self.skipped.append(f"{name} (not in --include)")
            elif any(fnmatchcase(ep.path, g) for g in self.exclude):
                self.skipped.append(f"{name} (--exclude)")
            else:
                kept.append(ep)
        return kept

    async def run(self) -> list[Finding]:
        test_cases = self.plan()
        # Passes, in order:
        # 1. baselines, before any probe can change the object they read;
        # 2. probes;
        # 3. time-based SQLi one at a time (concurrent sleeps would delay innocent probes queued behind them);
        # 4. confirmations (GET the object a mass-assignment probe created);
        # 5. rate-limit bursts last, so they can't exhaust a real limit and turn other probes into 429s,
        #    one endpoint at a time.
        baselines = [tc for tc in test_cases if tc.check_id == "baseline"]
        timed = [tc for tc in test_cases if tc.extra.get("strategy") == "sqli_time"]
        bursts = [tc for tc in test_cases if not tc.throttle]
        probes = [tc for tc in test_cases if tc.throttle and tc.check_id != "baseline"
                  and tc.extra.get("strategy") != "sqli_time"]
        results = await self.executor.run(baselines)
        results += await self.executor.run(probes)
        if timed:
            results += await Executor(self.auth, 1, **self._executor_opts).run(timed)  # type: ignore[arg-type]
        followups = self.analyzer.followups(results)
        if followups:
            results += await self.executor.run(followups)
        # One endpoint's burst at a time: concurrent bursts interfere (a burst on a state-resetting endpoint
        # turned another endpoint's burst into 500s) and blur which endpoint is limited.
        by_endpoint: dict[str, list[TestCase]] = {}
        for tc in bursts:
            by_endpoint.setdefault(tc.extra.get("endpoint_key", ""), []).append(tc)
        for group in by_endpoint.values():
            results += await self.executor.run(group)

        findings = self.analyzer.analyze(results)

        # Rate limit aggregation (burst results need separate handling)
        findings += self.analyzer.analyze_rate_limit(results)

        self.sent = len(results)
        self.errors = Counter((r.error or "").split(":")[0] for r in results if r.is_error)

        # Credentials never reach a report: mask every configured token (and --target userinfo) wherever
        # it was echoed.
        userinfo = httpx.URL(self.base_url).userinfo.decode()
        secrets = secrets_for(self.auth.token, self.auth.second_token, userinfo)
        for f in findings:
            for name in ("title", "endpoint_path", "request_sample", "response_sample", "evidence", "description"):
                setattr(f, name, scrub(getattr(f, name), secrets))
        return findings

    def _parse(self, path: str) -> list[Endpoint]:
        fmt = _detect_format(path)
        parsers: dict[str, type[BaseParser]] = {
            "openapi": OpenAPIParser,
            "har": HARParser,
            "postman": PostmanParser,
        }
        parser_cls = parsers.get(fmt, OpenAPIParser)
        return parser_cls().parse(path)

    def _generate(self, endpoints: list[Endpoint]) -> list[TestCase]:
        test_cases: list[TestCase] = []
        for endpoint in endpoints:
            key = f"{endpoint.method} {endpoint.path}"
            cases: list[TestCase] = []
            for check in self._checks:
                cases.extend(check.generate(endpoint, self.auth))
            # Baseline: one normal request with the configured auth, which detectors compare against.
            # Only for endpoints that got a probe needing it (a baseline GET /createdb-style endpoint can
            # reset state), and never for DELETE (it would remove the object).
            if endpoint.method != "DELETE" and any(tc.check_id in _BASELINE_CHECKS for tc in cases):
                cases.insert(0, TestCase(method=endpoint.method, url=build_url(endpoint), headers={}, params={},
                                         body=endpoint.body_example, label=f"Baseline: {key}",
                                         check_id="baseline"))
            for tc in cases:
                tc.extra["endpoint_key"] = key
            test_cases.extend(cases)
        for check in self._checks:
            for tc in check.generate_global(endpoints, self.auth):
                tc.extra.setdefault("endpoint_key", f"GET {tc.extra.get('path', '')} (not in spec)")
                test_cases.append(tc)
        return test_cases
