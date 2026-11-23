"""Benchmark apifuzz against a deliberately vulnerable API and score it against the target's own list of
documented vulnerabilities.

    docker compose -f benchmarks/vampi/docker-compose.yml up -d
    py -3.10 benchmarks/run.py vampi

Each target runs twice: against the vulnerable build (detections and misses) and against the same API
with its flaws switched off (false positives). Results go to benchmarks/results/<target>.{json,md}.
"""
import argparse
import asyncio
import datetime
import json
import quopri
import re
import secrets
import subprocess
import sys
import tempfile
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import httpx
import yaml

from apifuzz.models.endpoint import AuthConfig
from apifuzz.models.finding import Finding
from apifuzz.scanner import Scanner

HERE = Path(__file__).parent
RULE_CHECK = {"INJECT": "injection", "BOLA": "bola", "AUTH": "auth", "MASS": "mass_assignment",
              "RATE": "rate_limit", "SSRF": "ssrf", "CORS": "cors",
              "EXPOSURE": "data_exposure", "ENUM": "user_enum",
              "INVENTORY": "inventory", "BFLA": "bfla"}


def check_of(rule_id: str) -> str:
    return RULE_CHECK.get(rule_id.split("-")[1], "?")


def seed_param(spec: dict, name: str, value: str) -> None:
    """Point the spec's example for id parameter `name` (path or query) at an object that exists right now."""
    for item in spec.get("paths", {}).values():
        for op in [item, *[v for v in item.values() if isinstance(v, dict)]]:
            for p in op.get("parameters", []) if isinstance(op, dict) else []:
                if isinstance(p, dict) and p.get("name") == name and p.get("in") in ("path", "query"):
                    p["example"] = value
                    p.setdefault("schema", {})["example"] = value


def vampi_setup(base_url: str) -> tuple[str, AuthConfig]:
    """Reset the data, log in two users, seed the spec with user A's real (random per reset) book title."""
    with httpx.Client(base_url=base_url, timeout=15) as client:
        # VAmPI seeds book titles as bookTitle<0-99> under a UNIQUE constraint: ~3% of resets hit a
        # collision and answer 500. Retry instead of failing the run.
        for _ in range(5):
            if client.get("/createdb").status_code == 200:
                break
        else:
            raise RuntimeError(f"{base_url}/createdb kept failing")

        def login(user: str, password: str) -> str:
            r = client.post("/users/v1/login", json={"username": user, "password": password})
            r.raise_for_status()
            return r.json()["auth_token"]

        token_a, token_b = login("name1", "pass1"), login("name2", "pass2")
        books = client.get("/books/v1").json()["Books"]
    title = next(b["book_title"] for b in books if b["user"] == "name1")
    spec = yaml.safe_load((HERE / "vampi" / "openapi3.yml").read_text(encoding="utf-8"))
    seed_param(spec, "book_title", title)
    seeded = Path(tempfile.mkdtemp()) / "openapi3.seeded.yml"
    seeded.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    return str(seeded), AuthConfig(type="bearer", token=token_a, second_token=token_b)


def crapi_setup(base_url: str) -> tuple[str, AuthConfig]:
    """Sign up two fresh users (random credentials per run), give user A one of each object the challenges
    are about (vehicle, order, mechanic report, video, post), and seed the spec's id parameters with A's ids.
    Nothing else in the spec is changed."""
    suffix = secrets.token_hex(4)
    password = f"Bench-{secrets.token_urlsafe(9)}-1a"
    with httpx.Client(base_url=base_url, timeout=30) as client:
        def user(tag: str) -> tuple[str, str]:
            email = f"bench-{tag}-{suffix}@example.com"
            client.post("/identity/api/auth/signup", json={
                "name": f"bench{tag}{suffix}", "email": email, "password": password,
                "number": f"9{secrets.randbelow(10**9):09d}"}).raise_for_status()
            r = client.post("/identity/api/auth/login", json={"email": email, "password": password})
            r.raise_for_status()
            return email, r.json()["token"]

        email_a, token_a = user("a")
        _, token_b = user("b")
        auth = {"Authorization": f"Bearer {token_a}"}

        # The welcome email (crAPI's MailHog, proxied by crapi-web) carries the VIN + pincode of A's vehicle.
        mails = client.get("/mailhog/api/v2/search", params={"kind": "to", "query": email_a}).json()["items"]
        body = quopri.decodestring(mails[0]["Content"]["Body"]).decode("utf-8", "replace")
        vin, pincode = re.search(r"VIN:\D*?(\w{17}).*?Pincode:\D*?(\d+)", re.sub(r"<[^>]+>", " ", body), re.S).groups()
        client.post("/identity/api/v2/vehicle/add_vehicle", json={"vin": vin, "pincode": pincode},
                    headers=auth).raise_for_status()
        vehicle_id = client.get("/identity/api/v2/vehicle/vehicles", headers=auth).json()[0]["uuid"]

        order = client.post("/workshop/api/shop/orders", json={"product_id": 1, "quantity": 1}, headers=auth)
        order.raise_for_status()
        mechanic = client.get("/workshop/api/mechanic/", headers=auth).json()["mechanics"][0]["mechanic_code"]
        report = client.post("/workshop/api/merchant/contact_mechanic", headers=auth, json={
            "mechanic_code": mechanic, "problem_details": "brakes squeak", "vin": vin,
            "mechanic_api": "http://crapi-web/workshop/api/mechanic/receive_report",
            "repeat_request_if_failed": False, "number_of_repeats": 1})
        report.raise_for_status()
        report_id = re.search(r"report_id=(\d+)", report.json()["response_from_mechanic_api"]["report_link"]).group(1)
        video = client.post("/identity/api/v2/user/videos", headers=auth,
                            files={"file": ("bench.mp4", b"\x00\x00\x00\x18ftypmp42", "video/mp4")})
        video.raise_for_status()
        post = client.post("/community/api/v2/community/posts", headers=auth,
                           json={"title": "bench", "content": "bench post"})
        post.raise_for_status()

    spec = json.loads((HERE / "crapi" / "crapi-openapi-spec.json").read_text(encoding="utf-8"))
    for name, value in {"vehicleId": vehicle_id, "order_id": order.json()["id"], "report_id": report_id,
                        "video_id": video.json()["id"], "postId": post.json()["id"]}.items():
        seed_param(spec, name, value)
    seeded = Path(tempfile.mkdtemp()) / "crapi.seeded.json"
    seeded.write_text(json.dumps(spec), encoding="utf-8")
    return str(seeded), AuthConfig(type="bearer", token=token_a, second_token=token_b)


TARGETS: dict[str, dict[str, Any]] = {
    "vampi": {
        "setup": vampi_setup,
        "vulnerable_url": "http://127.0.0.1:5002",
        "secure_url": "http://127.0.0.1:5001",
        # Disposable target: destructive methods on; /createdb resets the data mid-scan, so skip it.
        "scan": {"allow_destructive": True, "exclude": ["/createdb"], "rate_limit_rps": 20},
    },
    "crapi": {
        "setup": crapi_setup,
        "vulnerable_url": "http://127.0.0.1:8888",
        "secure_url": None,  # crAPI has no fixed build: no false-positive run, unmatched findings get triaged
        # Disposable target: destructive methods on (challenges 7, 8 and 10 are DELETE/PUT).
        "scan": {"allow_destructive": True, "rate_limit_rps": 20},
    },
}


def scan(target: dict, base_url: str) -> tuple[list[Finding], dict[str, int], int]:
    spec, auth = target["setup"](base_url)
    scanner = Scanner(spec, base_url, auth=auth, **target["scan"])
    findings = asyncio.run(scanner.run())
    return findings, dict(scanner.errors), scanner.sent


def matching(f: Finding, vulns: list[dict]) -> list[dict]:
    return [v for v in vulns if any(fnmatchcase(f.rule_id, r) for r in v["rules"])
            and v["endpoint"] in ("*", f.endpoint)]


def score(vulns: list[dict], vuln_findings: list[Finding], secure_findings: list[Finding]) -> dict:
    per_vuln = []
    for v in vulns:
        hits = [f for f in vuln_findings if v in matching(f, [v])]
        per_vuln.append({
            "id": v["id"], "name": v["name"], "endpoint": v["endpoint"], "check": v["check"],
            "toggled": v["toggled"],
            "detected": bool(hits), "detected_firm": any(f.confidence == "firm" for f in hits),
            "secure_mode_hits": len([f for f in secure_findings if v in matching(f, [v])]),
        })

    def classify(findings: list[Finding], secure: bool) -> list[dict]:
        out = []
        for f in findings:
            m = matching(f, vulns)
            # In secure mode only flaws VAmPI doesn't switch off are still real.
            tp = any(not v["toggled"] for v in m) if secure else bool(m)
            out.append({"rule_id": f.rule_id, "check": check_of(f.rule_id), "endpoint": f.endpoint,
                        "confidence": f.confidence, "severity": f.severity.value, "tp": tp,
                        "vuln": m[0]["id"] if m else None, "url": f.endpoint_path})
        return out

    vf, sf = classify(vuln_findings, False), classify(secure_findings, True)
    covered = [v for v in vulns if v["check"]]
    detected = [p for p in per_vuln if p["detected"]]

    def precision(rows: list[dict]) -> float | None:
        return round(sum(r["tp"] for r in rows) / len(rows), 3) if rows else None

    return {
        "documented": len(vulns), "covered": len(covered),
        "detected": len(detected), "detected_firm": sum(p["detected_firm"] for p in per_vuln),
        "recall_documented": round(len(detected) / len(vulns), 3),
        "recall_covered": round(len(detected) / len(covered), 3) if covered else None,
        "vulnerable_findings": len(vf), "vulnerable_fp": sum(not r["tp"] for r in vf),
        "vulnerable_rate_findings": sum(r["check"] == "rate_limit" for r in vf),
        "precision": precision(vf), "precision_firm": precision([r for r in vf if r["confidence"] == "firm"]),
        # Rate limiting is documented API-wide, so every rate-limit finding matches: leave them out, and count
        # each (rule, operation) once, so the number can't be flattered by repeats.
        "precision_excl_rate_limit": precision(list({(r["rule_id"], r["endpoint"]): r for r in vf
                                                     if r["check"] != "rate_limit"}.values())),
        "secure_rate_findings": sum(r["check"] == "rate_limit" for r in sf),
        "secure_findings": len(sf), "secure_fp": sum(not r["tp"] for r in sf),
        "secure_fp_firm": sum(not r["tp"] and r["confidence"] == "firm" for r in sf),
        "per_vulnerability": per_vuln, "findings_vulnerable": vf, "findings_secure": sf,
    }


def git_commit() -> str:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=HERE, text=True).strip()
        # A result measured on uncommitted code must say so (the results files themselves don't count).
        changes = subprocess.check_output(["git", "status", "--porcelain", "--", ":/",
                                           ":(top,exclude)benchmarks/results"], cwd=HERE, text=True).strip()
        return f"{commit}-dirty" if changes else commit
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def markdown(name: str, meta: dict, s: dict) -> str:
    pct = lambda x: "n/a" if x is None else f"{x * 100:.0f}%"  # noqa: E731
    if not meta.get("has_secure", True):
        return markdown_no_secure(name, meta, s, pct)
    lines = [
        f"# apifuzz vs {name}",
        "",
        f"Measured {meta['date']} with apifuzz `{meta['commit']}`. Scan settings: `{meta['scan']}`. "
        f"Requests: {meta['sent_vulnerable']} (vulnerable) / {meta['sent_secure']} (secure); "
        f"failed: {meta['errors_vulnerable'] or 'none'} / {meta['errors_secure'] or 'none'}.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Documented vulnerabilities detected | {s['detected']} / {s['documented']} ({pct(s['recall_documented'])}) |",
        f"| ...of those apifuzz has a check for | {s['detected']} / {s['covered']} ({pct(s['recall_covered'])}) |",
        f"| ...detected with a firm finding | {s['detected_firm']} / {s['documented']} |",
        f"| Findings on the vulnerable build | {s['vulnerable_findings']} ({s['vulnerable_fp']} false positive) |",
        f"| ...of which rate-limit (one per endpoint) | {s['vulnerable_rate_findings']} |",
        f"| Precision (all / firm only) | {pct(s['precision'])} / {pct(s['precision_firm'])} |",
        f"| Precision excluding rate-limit, one per (rule, operation) | {pct(s['precision_excl_rate_limit'])} |",
        f"| Findings on the secure build | {s['secure_findings']} ({s['secure_rate_findings']} rate-limit: "
        f"VAmPI keeps that flaw in both builds) |",
        f"| False positives on the secure build (all / firm) | {s['secure_fp']} / {s['secure_fp_firm']} |",
        "",
        "## Per documented vulnerability",
        "",
        "| Vulnerability | Endpoint | Check | Vulnerable build | Secure build |",
        "|---|---|---|---|---|",
    ]
    for p in s["per_vulnerability"]:
        found = "missed" if not p["detected"] else ("detected (firm)" if p["detected_firm"] else "detected (tentative)")
        if not p["check"]:
            found = "not covered"
        secure = ("still present (not toggled)" if not p["toggled"] else
                  f"{p['secure_mode_hits']} false positive(s)" if p["secure_mode_hits"] else "clean")
        lines.append(f"| {p['name']} | `{p['endpoint']}` | {p['check'] or 'none'} | {found} | {secure} |")
    for title, rows in (("False positives, vulnerable build", s["findings_vulnerable"]),
                        ("False positives, secure build", s["findings_secure"])):
        fps = [r for r in rows if not r["tp"]]
        lines += ["", f"## {title}", ""]
        lines += [f"- `{r['rule_id']}` ({r['confidence']}) on `{r['endpoint']}`" for r in fps] or ["None."]
    return "\n".join(lines) + "\n"


def markdown_no_secure(name: str, meta: dict, s: dict, pct: Any) -> str:
    unmatched = [r for r in s["findings_vulnerable"] if not r["tp"]]
    lines = [
        f"# apifuzz vs {name}",
        "",
        f"Measured {meta['date']} with apifuzz `{meta['commit']}`. Scan settings: `{meta['scan']}`. "
        f"Requests: {meta['sent_vulnerable']}; failed: {meta['errors_vulnerable'] or 'none'}.",
        "",
        f"{name} has no fixed build, so there is no false-positive run. Findings that match no documented "
        "vulnerability are listed at the end and counted against precision; each is triaged by hand in "
        "benchmarks/README.md.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Documented vulnerabilities detected | {s['detected']} / {s['documented']} ({pct(s['recall_documented'])}) |",
        f"| ...of those apifuzz has a check for | {s['detected']} / {s['covered']} ({pct(s['recall_covered'])}) |",
        f"| ...detected with a firm finding | {s['detected_firm']} / {s['documented']} |",
        f"| Findings | {s['vulnerable_findings']} ({len(unmatched)} match no documented vulnerability) |",
        f"| ...of which rate-limit (one per endpoint) | {s['vulnerable_rate_findings']} |",
        f"| Precision, unmatched counted as false (all / firm only) | {pct(s['precision'])} / "
        f"{pct(s['precision_firm'])} |",
        f"| Same, excluding rate-limit, one per (rule, operation) | {pct(s['precision_excl_rate_limit'])} |",
        "",
        "## Per documented vulnerability",
        "",
        "| Vulnerability | Endpoint | Check | Result |",
        "|---|---|---|---|",
    ]
    for p in s["per_vulnerability"]:
        found = "missed" if not p["detected"] else ("detected (firm)" if p["detected_firm"] else "detected (tentative)")
        lines.append(f"| {p['name']} | `{p['endpoint']}` | {p['check'] or 'none'} | "
                     f"{found if p['check'] else 'not covered'} |")
    lines += ["", "## Findings matching no documented vulnerability", ""]
    lines += [f"- `{r['rule_id']}` ({r['confidence']}) on `{r['endpoint']}`" for r in unmatched] or ["None."]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", choices=sorted(TARGETS))
    ap.add_argument("--vulnerable-url")
    ap.add_argument("--secure-url")
    args = ap.parse_args()
    target = TARGETS[args.target]
    vulns = yaml.safe_load((HERE / args.target / "expected.yaml").read_text(encoding="utf-8"))["vulnerabilities"]

    vuln_findings, vuln_errors, vuln_sent = scan(target, args.vulnerable_url or target["vulnerable_url"])
    secure_url = args.secure_url or target["secure_url"]
    secure_findings, secure_errors, secure_sent = scan(target, secure_url) if secure_url else ([], {}, 0)
    result = score(vulns, vuln_findings, secure_findings)
    meta = {"date": datetime.date.today().isoformat(), "commit": git_commit(),
            "scan": json.dumps(target["scan"]), "sent_vulnerable": vuln_sent, "sent_secure": secure_sent,
            "errors_vulnerable": vuln_errors, "errors_secure": secure_errors, "has_secure": bool(secure_url)}

    out = HERE / "results"
    out.mkdir(exist_ok=True)
    (out / f"{args.target}.json").write_text(json.dumps({"meta": meta, **result}, indent=2), encoding="utf-8")
    report = markdown(args.target, meta, result)
    (out / f"{args.target}.md").write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
