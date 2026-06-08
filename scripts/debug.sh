#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/project.config.json"

read_config_value() {
  local key="$1"
  local fallback="$2"
  PROJECT_CONFIG_PATH="$CONFIG_FILE" PROJECT_CONFIG_KEY="$key" PROJECT_CONFIG_FALLBACK="$fallback" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["PROJECT_CONFIG_PATH"])
key = os.environ["PROJECT_CONFIG_KEY"].split(".")
fallback = os.environ["PROJECT_CONFIG_FALLBACK"]

try:
    data = json.loads(path.read_text(encoding="utf-8"))
    value = data
    for part in key:
        value = value[part]
except Exception:
    value = fallback

print(value)
PY
}

BACKEND_HOST="${BACKEND_HOST:-$(read_config_value network.backend.host 127.0.0.1)}"
BACKEND_PORT="${BACKEND_PORT:-$(read_config_value network.backend.port 8100)}"
FRONTEND_HOST="${FRONTEND_HOST:-$(read_config_value network.frontend.host 127.0.0.1)}"
FRONTEND_PORT="${FRONTEND_PORT:-$(read_config_value network.frontend.port 5174)}"
BACKEND_URL="http://${BACKEND_HOST}:${BACKEND_PORT}"
FRONTEND_URL="http://${FRONTEND_HOST}:${FRONTEND_PORT}"

section() {
  printf '\n== %s ==\n' "$1"
}

try_cmd() {
  local label="$1"
  shift
  printf '\n-- %s --\n' "$label"
  "$@" || true
}

section "GhostRedRecon Debug"
printf 'Project: %s\n' "$ROOT_DIR"
printf 'Backend: %s\n' "$BACKEND_URL"
printf 'Frontend: %s\n' "$FRONTEND_URL"

try_cmd "Python compile" python3 -m py_compile \
  "$ROOT_DIR/backend/main.py" \
  "$ROOT_DIR/backend/runtime.py" \
  "$ROOT_DIR/backend/api/system_api.py" \
  "$ROOT_DIR/backend/api/rf_api.py" \
  "$ROOT_DIR/backend/api/intel_api.py" \
  "$ROOT_DIR/backend/api/device_api.py" \
  "$ROOT_DIR/backend/api/attack_api.py"

try_cmd "HackRF info" hackrf_info
try_cmd "USB devices" lsusb
try_cmd "Project processes" ps -ef
try_cmd "Ports" ss -ltnp
try_cmd "Backend health" curl -fsS "$BACKEND_URL/health"
try_cmd "System health" curl -fsS "$BACKEND_URL/api/system/health"
try_cmd "System state" curl -fsS "$BACKEND_URL/api/system/state"
try_cmd "System diagnostics" curl -fsS "$BACKEND_URL/api/system/diagnostics"
try_cmd "RF health" curl -fsS "$BACKEND_URL/api/rf/health"
try_cmd "Live FFT" curl -fsS "$BACKEND_URL/api/live/fft"
try_cmd "Intel top" curl -fsS "$BACKEND_URL/api/intel/top?limit=10"
try_cmd "Frontend index" curl -I -s "$FRONTEND_URL/"

section "Recent Logs"
try_cmd "Backend log tail" tail -n 40 "$ROOT_DIR/logs/backend.log"
try_cmd "Frontend log tail" tail -n 40 "$ROOT_DIR/logs/frontend.log"
