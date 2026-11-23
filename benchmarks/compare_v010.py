"""Score apifuzz v0.1.0 against the same target, seeding, expected list and scoring as run.py.

v0.1.0's Scanner takes no safety options and its findings have no spec operation, so this adapter maps each
finding URL back to a spec template and drops /createdb findings (run.py excludes that endpoint).

    git worktree add ../apifuzz-v010 v0.1.0
    py -3.10 benchmarks/compare_v010.py ../apifuzz-v010/src            # tokens configured (like run.py)
    py -3.10 benchmarks/compare_v010.py ../apifuzz-v010/src --no-auth  # v0.1.0's documented default

Writes benchmarks/results/vampi-v0.1.0[-noauth].json. Note: with tokens configured, v0.1.0's auth probes are
overwritten by the real token (a v0.1.0 bug, fixed in later releases), which is where its false positives come from.
"""
import argparse
import asyncio
import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("v010_src", help="src/ directory of an apifuzz v0.1.0 checkout")
    ap.add_argument("--no-auth", action="store_true", help="scan without tokens")
    args = ap.parse_args()

    # Load this repo's harness (setup + scoring) first, then put v0.1.0 first on the path for its Scanner.
    spec = importlib.util.spec_from_file_location("bench_run", HERE / "run.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)  # type: ignore[union-attr]
    for name in [m for m in sys.modules if m == "apifuzz" or m.startswith("apifuzz.")]:
        del sys.modules[name]
    sys.path.insert(0, str(Path(args.v010_src).resolve()))
    from apifuzz.models.endpoint import AuthConfig as OldAuth  # v0.1.0
    from apifuzz.scanner import Scanner as OldScanner  # v0.1.0

    target = bench.TARGETS["vampi"]
    vulns = yaml.safe_load((HERE / "vampi" / "expected.yaml").read_text(encoding="utf-8"))["vulnerabilities"]
    paths = yaml.safe_load((HERE / "vampi" / "openapi3.yml").read_text(encoding="utf-8"))["paths"]
    templates = [(m.upper(), p) for p, item in paths.items() for m in item
                 if m in ("get", "post", "put", "patch", "delete")]

    def operation(method: str, url: str) -> str:
        path = re.sub(r"^https?://[^/]+", "", url).split("?")[0]
        for m, t in templates:
            if m == method and re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", t), path):
                return f"{m} {t}"
        return f"{method} ?"

    found = {}
    for mode in ("vulnerable", "secure"):
        base = target[f"{mode}_url"]
        spec_path, auth = target["setup"](base)
        old_auth = OldAuth() if args.no_auth else OldAuth(type="bearer", token=auth.token,
                                                           second_token=auth.second_token)
        findings = asyncio.run(OldScanner(spec_path, base, auth=old_auth, rate_limit_rps=20).run())
        for f in findings:  # v0.1.0 has no confidence levels and no spec operation
            f.__dict__.update(confidence="firm", endpoint=operation(f.endpoint_method, f.endpoint_path))
        found[mode] = [f for f in findings if "/createdb" not in f.endpoint_path]

    result = bench.score(vulns, found["vulnerable"], found["secure"])
    result["meta"] = {"apifuzz": "v0.1.0", "auth": "none" if args.no_auth else "bearer + second token"}
    out = HERE / "results" / f"vampi-v0.1.0{'-noauth' if args.no_auth else ''}.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if not isinstance(v, list)}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
