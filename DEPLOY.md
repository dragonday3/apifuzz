# Deployment Guide

## PyPI

### Prerequisites

- PyPI account with 2FA
- `build` and `twine` installed: `pip install build twine`

### Release steps

```bash
# 1. Bump version in pyproject.toml
#    [project] version = "0.2.0"

# 2. Tag the release
git tag v0.2.0
git push origin v0.2.0

# 3. Build
python -m build

# 4. Verify the dist
twine check dist/*

# 5. Upload to TestPyPI first (optional)
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ apifuzz

# 6. Upload to PyPI
twine upload dist/*
```

> Trusted Publisher (OIDC) is the recommended alternative to API tokens — configure it in PyPI project settings to avoid storing credentials.

---

## Docker

### Build and push

```bash
# Build
docker build -t dragonday3/apifuzz:latest .
docker build -t dragonday3/apifuzz:0.2.0 .

# Test locally
docker run --rm dragonday3/apifuzz:latest --help
docker run --rm -v $(pwd):/data dragonday3/apifuzz:latest \
  /data/openapi.yaml --target https://api.example.com --output json

# Push
docker push dragonday3/apifuzz:latest
docker push dragonday3/apifuzz:0.2.0
```

### Multi-arch build (arm64 + amd64)

```bash
docker buildx create --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t dragonday3/apifuzz:latest \
  -t dragonday3/apifuzz:0.2.0 \
  --push .
```

---

## GitHub Actions — Automated Release

Add `.github/workflows/release.yml` to automate PyPI + Docker on tag push:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

jobs:
  pypi:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # OIDC trusted publisher

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Build
        run: |
          pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

  docker:
    runs-on: ubuntu-latest
    needs: pypi

    steps:
      - uses: actions/checkout@v4

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Buildx
        uses: docker/setup-buildx-action@v3

      - name: Extract version tag
        id: tag
        run: echo "VERSION=${GITHUB_REF_NAME#v}" >> $GITHUB_OUTPUT

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            dragonday3/apifuzz:latest
            dragonday3/apifuzz:${{ steps.tag.outputs.VERSION }}
```

**Required secrets:**
- `DOCKERHUB_USERNAME` — Docker Hub username
- `DOCKERHUB_TOKEN` — Docker Hub access token (not your password)

PyPI uses OIDC trusted publisher — no secret needed, configure once in PyPI project settings.

---

## Self-Hosted (Docker Compose)

For running apifuzz as a persistent service against internal APIs:

```yaml
# docker-compose.yml
version: "3.9"

services:
  apifuzz:
    image: dragonday3/apifuzz:latest
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
docker compose run --rm apifuzz
```

---

## Environment Variables

The CLI accepts all options as flags. For CI environments, set auth tokens via secrets — never in the spec file or committed config.

| Secret | Usage |
|--------|-------|
| `API_BASE_URL` | `--target` value |
| `API_TEST_TOKEN` | `--token` value for bearer auth |
| `API_TEST_TOKEN_B` | `--second-token` for BOLA cross-user tests |

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- `MAJOR` — breaking CLI or SDK interface changes
- `MINOR` — new checks, new input parsers, new output formats
- `PATCH` — bug fixes, detection improvements, dependency updates

Current: **v0.1.0** (initial release — all 7 OWASP checks, 3 output formats, 3 input parsers)
