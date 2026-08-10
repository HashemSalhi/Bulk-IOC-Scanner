# One image, one container, one port. The UI is built here and then served by
# the API, so there is no nginx and no second service to keep in sync.

FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/frontend

# Dependencies first so a UI source edit does not reinstall node_modules.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# vite.config.js writes to ../backend/bulk_ioc_scanner/web
RUN npm run build


FROM python:3.12-slim AS runtime

# PYTHONDONTWRITEBYTECODE: the source tree is read-only in normal operation.
# PYTHONUNBUFFERED: logs reach `docker logs` immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BULK_IOC_SCANNER_DATA_DIR=/data

WORKDIR /src

COPY pyproject.toml README.md LICENSE ./
COPY backend/ ./backend/
COPY --from=ui /src/backend/bulk_ioc_scanner/web ./backend/bulk_ioc_scanner/web

RUN pip install --no-cache-dir . && rm -rf /root/.cache

# The database holds API keys, so it lives on a volume owned by a non-root user
# rather than inside the image.
RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /data \
    && chown -R scanner:scanner /data
USER scanner
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

# 0.0.0.0 so the port is reachable from outside the container; --no-browser
# because there is no browser in here.
CMD ["bulk-ioc-scanner", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]
