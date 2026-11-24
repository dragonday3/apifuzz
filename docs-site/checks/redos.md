# redos: Regular-expression denial of service

| | |
|---|---|
| OWASP | API4:2023 Unrestricted Resource Consumption |
| Rule id | `APIFUZZ-REDOS-001` (medium, firm only; no tentative verdict) |
| Needs | `--time-based` (off by default: a vulnerable server really burns CPU on every probe) |

## What it sends

Targets: string query parameters and top-level string body fields that the server probably validates with a
regex: their schema has a `pattern`, a `format` of `email`, `idn-email`, `uri`, `url`, `iri`, `uri-reference`,
`hostname` or `idn-hostname`, or their name contains `email`, `e-mail`, `url`, `uri`, `link`, `domain`, `host`
or `website`. Not sent for `DELETE`.

Per target, 3 pairs, interleaved and sent one at a time in the serial pass (6 requests):

- **evil**: `"a" × 27 + "!"`. A nested quantifier such as `^(a+)+$` tries every way to split the run of `a`s
  before the final `!` fails the match: exponential backtracking.
- **control**: `"!" + "a" × 27`. Same length and characters, but it fails at the first character, so no
  backtracking.

Both are invalid for the field, so the server takes the same code path for both; only the regex cost differs.

## How it decides

Firm finding when **every** evil request took at least 2 seconds longer **and** at least 5 times longer than the
slowest control (a timed-out evil request counts as slow). No verdict when a control failed or got a `429`, or
an evil request got a `429` or failed for a reason other than a timeout. One slow request is network noise, so
there is no tentative verdict.

## False-positive guards

- Same-length controls interleaved with the evil inputs cancel out server load and network latency.
- The threshold is relative to the slowest control, and every evil repeat must exceed it.

## Remediation

Rewrite the regex without nested or overlapping quantifiers (`(a+)+`, `(\w+\s?)*`), cap the input length before
matching, or use a linear-time engine (RE2).

## Limitations

- **Calibration**: the length (27) and the control's shape were calibrated by timing VAmPI's own email regex in
  CPython (about 6 s; `^(\w+\s?)*$` takes about 12 s, under the default 15 s `--timeout`). Faster backtracking
  engines (V8, JVM) need longer input and may be missed; linear-time engines (RE2, Go, Rust) are immune.
- Only exponential backtracking on `a`-runs is tested; polynomial ReDoS and other character classes are not.
- Path parameters, headers and nested body fields are not probed.
- Written because VAmPI listed RegexDoS as uncovered; the rule is generic (see [Benchmarks](../benchmarks.md)).
