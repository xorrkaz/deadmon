# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 deadmon contributors
# Based on the original deadman work by upa@haeena.net.

FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    DEADMON_CONFIG=/app/deadmon.conf \
    DEADMON_HOST=0.0.0.0 \
    DEADMON_PORT=8000 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        hping3 \
        iproute2 \
        iputils-ping \
        openssh-client \
        snmp \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY deadmon ./deadmon
COPY bin ./bin
COPY README.md LICENSE ./
RUN chmod +x /app/bin/deadmon /app/bin/deadmon-convert-config
RUN uv sync --frozen --no-dev
EXPOSE 8000

ENTRYPOINT ["/app/.venv/bin/deadmon"]
CMD ["--host", "0.0.0.0", "--port", "8000", "/app/deadmon.conf"]
