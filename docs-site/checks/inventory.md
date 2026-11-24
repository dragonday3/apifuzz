# inventory: Improper Inventory Management

| | |
|---|---|
| OWASP | API9:2023 Improper Inventory Management |
| Rule ids | `APIFUZZ-INVENTORY-001` shadow spec, `APIFUZZ-INVENTORY-002` debug/management endpoint, `APIFUZZ-INVENTORY-003` undocumented API version (tentative) |
| Needs | nothing; runs once per scan, not per endpoint |

## What it sends

Up to 25 `GET`s per scan, with the configured credentials:

- **A control**: a random path that can't exist (`/apifuzz-nonexistent-<random>`), to see what a catch-all or
  single-page-app server answers for anything.
- **Well-known paths** not already in the spec: `/openapi.json`, `/openapi.yaml`, `/swagger.json`,
  `/swagger.yaml`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/actuator`, `/actuator/env`,
  `/actuator/configprops`, `/.env`, `/debug/vars`, `/metrics`, `/server-status`.
- **Neighbouring versions**: for each documented `GET` path without parameters containing `/vN`, the same path
  with `/v(N+1)` and `/v(N-1)` when undocumented (at most 10).

`--include`/`--exclude` globs apply to these paths too.

## How it decides

A 2xx whose content proves what was probed for, and which doesn't resemble the control's answer:

| Probe | Content required | Rule | Severity |
|---|---|---|---|
| spec path | a parseable OpenAPI/Swagger document whose paths **don't overlap** the scanned spec at all | `INVENTORY-001` | medium |
| `/actuator` | `"_links":` | `INVENTORY-002` | medium |
| `/actuator/env`, `/actuator/configprops` | `"propertySources"`, `"activeProfiles"` or `"contexts"` | `INVENTORY-002` | high |
| `/.env` | at least two consecutive `UPPER_CASE=value` lines | `INVENTORY-002` | high |
| `/debug/vars` | `"memstats":` (Go expvar) | `INVENTORY-002` | medium |
| `/metrics` | a Prometheus `# HELP` / `# TYPE` line | `INVENTORY-002` | medium |
| `/server-status` | "Server Status for" (Apache) | `INVENTORY-002` | medium |
| version | a JSON body (`{` or `[`) | `INVENTORY-003` (tentative) | medium |

All but the version probe are firm.

## False-positive guards

- The control: a server that answers every path the same way reports nothing.
- The API's own published spec and docs UI are not reported: publishing the documented API is a choice, not an
  inventory gap. Only a spec describing *other* operations (a shadow API) is.
- Content signatures: a `200` HTML error page on `/.env` is not an exposed `.env`.

## Example finding

From the scan in `tests/checks/test_inventory.py` with the handler of `test_exposed_items_need_matching_content` (serves `/.env`, `/actuator/env`, a shadow `/swagger.json` and `/api/v2/users`).

```json
{
  "rule_id": "APIFUZZ-INVENTORY-002",
  "title": "Inventory: .env file exposed (/.env)",
  "severity": "high",
  "confidence": "firm",
  "owasp_category": "API9:2023 - Improper Inventory Management",
  "endpoint": "GET /.env (not in spec)",
  "endpoint_method": "GET",
  "endpoint_path": "http://api/.env",
  "evidence": "HTTP 200, content matches dotenv; a random path answers differently",
  "request_sample": "# Inventory: GET /.env [dotenv]\nGET http://api/.env",
  "response_sample": "DB_PASSWORD=x\nSECRET_KEY=y\n",
  "remediation": "Remove or restrict the endpoint (network, auth), or document and own it in the inventory."
}
```

## Remediation

Remove or restrict the endpoint (network policy, authentication), or document it and own it in the API
inventory. Retire old API versions.

## Limitations

- A fixed list of well-known paths; no directory brute force or crawling.
- A served spec that shares even one path with the scanned spec is treated as the API's own, so a shadow spec
  that overlaps the documented one is missed.
- Version probes need a `/vN` segment in a parameterless `GET` path and only try one version up and down.
