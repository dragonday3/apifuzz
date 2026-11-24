# Deployment Guide

## Releasing

Releases are automated by `.github/workflows/release.yml`. Pushing a tag `vX.Y.Z`:

1. checks the tag matches `__version__` in `src/fuzzowl/__init__.py`, runs the tests and builds the wheel/sdist;
2. publishes to PyPI as **`fuzzowl`** (package, import and CLI command share the name; before 0.2.0 the
   project was called apifuzz, a name another PyPI project uses);
3. pushes the image to `ghcr.io/dragonday3/fuzzowl:vX.Y.Z` and `:latest`;
4. creates the GitHub release with that version's `CHANGELOG.md` section and the built files.

### Release steps

```bash
# 1. Bump __version__ in src/fuzzowl/__init__.py (the only place the version lives)
# 2. Move the "Unreleased" notes in CHANGELOG.md under "## [X.Y.Z] - YYYY-MM-DD"
# 3. Commit, then tag and push the tag
git tag vX.Y.Z
git push origin vX.Y.Z
```

### One-time setup

- **PyPI trusted publishing** (no API token stored anywhere): on pypi.org, add a pending publisher for the
  project `fuzzowl` with owner `dragonday3`, repository `fuzzowl`, workflow `release.yml` and environment
  `pypi`. In the GitHub repo, create the environment `pypi` (Settings → Environments). Requiring a reviewer there
  gives you an approval step before each PyPI upload.
- **GHCR**: nothing to configure; the workflow uses `GITHUB_TOKEN`. After the first release, make the package
  public (GitHub → Packages → fuzzowl → Package settings → Change visibility).

### Build locally

```bash
py -3.10 -m pip install build && py -3.10 -m build     # dist/fuzzowl_scanner-X.Y.Z-py3-none-any.whl
docker build -t fuzzowl .
docker run --rm -v "$(pwd):/data" fuzzowl /data/openapi.yaml --target https://api.example.com \
  --output sarif --out-file /data/results.sarif
```

### Benchmark

`.github/workflows/benchmark.yml` re-runs the VAmPI benchmark weekly and on demand. It fails if detection
drops or false positives appear compared with the committed `benchmarks/results/vampi.json`.

---

## Self-Hosted (Docker Compose)

For running fuzzowl as a persistent service against internal APIs:

```yaml
# docker-compose.yml
version: "3.9"

services:
  fuzzowl:
    # Published by the release workflow from the first release on; until then: docker build -t fuzzowl .
    image: ghcr.io/dragonday3/fuzzowl:latest
    volumes:
      - ./specs:/specs:ro
      - ./reports:/reports
    command: >
      /specs/openapi.yaml
      --target http://api:8080
      --output html
      --out-file /reports/latest.html
      --quiet
    networks:
      - api-net

networks:
  api-net:
    external: true
```

```bash
docker compose run --rm fuzzowl
```

---

## Environment Variables

The CLI accepts all options as flags. For CI environments, set auth tokens via secrets — never in the spec file or committed config.

| Secret | Usage |
|--------|-------|
| `API_BASE_URL` | `--target` value |
| `API_TEST_TOKEN` | `--token` value for bearer auth |
| `API_TEST_TOKEN_B` | `--second-token` for BOLA cross-user tests |

**Defaults to know in CI** (see the README "Safety defaults"): TLS certificates are verified, so a staging API with a private CA or a self-signed certificate needs `--insecure`; otherwise every request fails and the run exits `2`. `PUT`/`PATCH`/`DELETE` endpoints are skipped unless you pass `--allow-destructive`.

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- `MAJOR` — breaking CLI or SDK interface changes
- `MINOR` — new checks, new input parsers, new output formats
- `PATCH` — bug fixes, detection improvements, dependency updates

Released: **v0.2.1** (2026-11-24, README fix) and **v0.2.0** (2026-11-24): PyPI `fuzzowl`,
`ghcr.io/dragonday3/fuzzowl:vX.Y.Z` and `:latest`, GitHub releases. v0.1.0 (as apifuzz) was a git tag only.
