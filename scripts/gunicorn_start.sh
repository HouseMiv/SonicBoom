#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"
BIND="${BIND:-127.0.0.1:8000}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"

exec gunicorn \
  --workers "$WEB_CONCURRENCY" \
  --bind "$BIND" \
  --timeout "$TIMEOUT" \
  --access-logfile - \
  --error-logfile - \
  app:app
