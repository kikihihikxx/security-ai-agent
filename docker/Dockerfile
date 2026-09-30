FROM ghcr.io/astral-sh/uv:0.12.17 AS uv

FROM python:3.12-slim

COPY --from=uv /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    HOST=0.0.0.0 \
    PORT=8001 \
    SQLITE_CHECKPOINT_PATH=/data/checkpoints.db

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY .chainlit ./.chainlit
COPY public ./public

RUN uv sync --frozen --no-dev --no-editable \
    && mkdir -p /data \
    && chown -R 10001:10001 /app /data

USER 10001:10001

EXPOSE 8001
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8001') + '/health', timeout=3)"]

CMD ["security-agent-v2-server"]
