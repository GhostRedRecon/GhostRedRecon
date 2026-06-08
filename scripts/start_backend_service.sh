#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8100}"
SYSTEM_DIST_PACKAGES="${SYSTEM_DIST_PACKAGES:-/usr/lib/python3/dist-packages}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

resolve_backend_runner() {
  if [[ -x "$ROOT_DIR/backend/.venv/bin/python" ]]; then
    printf '%s\n' "$ROOT_DIR/backend/.venv/bin/python -m uvicorn"
    return 0
  fi
  if python3 -m uvicorn --version >/dev/null 2>&1; then
    printf 'python3 -m uvicorn\n'
    return 0
  fi
  return 1
}

main() {
  need_cmd python3 || {
    printf '[backend-service] python3 is required\n' >&2
    exit 1
  }

  local backend_runner
  backend_runner="$(resolve_backend_runner)" || {
    printf '[backend-service] uvicorn is required in the runtime Python environment\n' >&2
    exit 1
  }

  cd "$ROOT_DIR"
  export PYTHONPATH="${SYSTEM_DIST_PACKAGES}${PYTHONPATH:+:${PYTHONPATH}}"
  exec bash -lc "export PYTHONPATH='${PYTHONPATH}'; exec ${backend_runner} backend.main:app --host '$BACKEND_HOST' --port '$BACKEND_PORT' --app-dir '$ROOT_DIR'"
}

main "$@"
