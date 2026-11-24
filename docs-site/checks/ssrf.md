# ssrf: Server Side Request Forgery

| | |
|---|---|
| OWASP | API7:2023 Server Side Request Forgery |
| Rule id | `FUZZOWL-SSRF-001` (critical, firm) |
| Needs | parameters with URL-like names; `--oob-url` (a collector you control) for blind SSRF |

## What it sends

For each parameter named `url`, `uri`, `endpoint`, `redirect`, `callback`, `src`, `href`, `path`, `dest`,
`destination`, `link`, `target`, `next` or `returnUrl` (case-insensitive), in the query, the path or a header,
one request per payload:

- `http://169.254.169.254/latest/meta-data/` (cloud metadata)
- `http://localhost:8080`
- `http://127.0.0.1`
- `http://0.0.0.0`

With `--oob-url https://<your-collector>`, one more per parameter: `https://<your-collector>/fuzzowl-<id>`,
where `<id>` is 8 random hex characters unique to that parameter.

## How it decides

**In-band (firm)**: the response contains a marker only a real metadata or file read returns (`ami-id`,
`instance-id`, `root:x:0:0`, `computeMetadata`, `"AccessKeyId"`) and the endpoint's baseline response does not.
None of the markers occurs in the payloads themselves, so a reflected payload doesn't count.

**Blind (`--oob-url`)**: fuzzowl does not poll your collector and does not create findings for callbacks. It
records which probe id went to which parameter, prints the map at the end of the scan (even with `--quiet`), and
writes it into every report: SARIF `runs[0].properties.oobProbes`, an HTML section, and in JSON the object form
`{"findings": [...], "oob_probes": {...}}` ([Output formats](../reference/output.md)). A request to
`<collector>/fuzzowl-<id>` means that parameter makes the server fetch attacker-chosen URLs; it may arrive
later than the scan.

## False-positive guards

- Markers must be absent from the baseline (an API that documents AWS metadata in every response is not
  flagged).
- Markers are content only a real fetch returns, never a payload echo.

## Example finding

From a scan of the `/fetch?url=` spec of `tests/checks/test_ssrf_oob.py` against a minimal respx handler (written for this page) that fetches `url` and returns the content, with a canned AWS metadata listing for `169.254.169.254`.

```json
{
  "rule_id": "FUZZOWL-SSRF-001",
  "title": "SSRF: Internal metadata content in response",
  "severity": "critical",
  "confidence": "firm",
  "owasp_category": "API7:2023 - Server Side Request Forgery",
  "endpoint": "GET /fetch",
  "endpoint_method": "GET",
  "endpoint_path": "http://testserver/fetch",
  "parameter": "url",
  "evidence": "Metadata marker 'ami-id' in response, absent from baseline",
  "request_sample": "# SSRF: GET /fetch [url=http://169.254.169.254/latest/...]\nGET http://testserver/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
  "response_sample": "{\"fetched\":\"http://169.254.169.254/latest/meta-data/\",\"content\":\"ami-id\\nhostname\\ninstance-id\\nlocal-ipv4\\n\"}",
  "remediation": "Validate and allowlist URL parameters; block requests to internal networks."
}
```

## Remediation

Validate and allowlist URL parameters (scheme, host, port); resolve the host and block private, loopback and
link-local ranges, including after redirects; don't return fetched content to the client.

## Limitations

- Parameters are selected by name only; a URL in a field called `image` or `webhook` is not probed. JSON
  request-body fields of OpenAPI 3 operations are not probed.
- In-band detection needs the fetched content in the response. Without `--oob-url`, blind SSRF is not found:
  crAPI's SSRF through `mechanic_api` was missed because the benchmark run had no collector and crAPI has no
  cloud metadata to echo.
- No DNS-only callbacks, no protocol smuggling (`gopher://`, `file://`), no IP encodings or redirect tricks.
