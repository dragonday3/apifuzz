FROM python:3.11-slim AS builder

WORKDIR /app
# README.md is the package's readme (pyproject metadata); the build fails without it.
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

FROM python:3.11-slim

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/apifuzz /usr/local/bin/apifuzz

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["apifuzz"]
CMD ["--help"]
