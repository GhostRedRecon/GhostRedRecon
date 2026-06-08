#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
CONFIG_FILE="$ROOT_DIR/config/project.config.json"
BACKEND_PID_FILE="$LOG_DIR/backend.pid"
FRONTEND_PID_FILE="$LOG_DIR/frontend.pid"

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

BACKEND_PORT="${BACKEND_PORT:-$(read_config_value network.backend.port 8100)}"
FRONTEND_PORT="${FRONTEND_PORT:-$(read_config_value network.frontend.port 5174)}"

log() {
  printf '[stop] %s\n' "$*"
}

stop_pid_file() {
  local label="$1"
  local pid_file="$2"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      log "Stopping ${label} (pid ${pid})..."
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    fi
    rm -f "$pid_file"
  fi
}

stop_port() {
  local label="$1"
  local port="$2"
  local pids
  pids="$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {print $NF}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u || true)"
  if [[ -n "$pids" ]]; then
    for pid in $pids; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        log "Stopping ${label} port owner pid ${pid}..."
        kill "$pid" >/dev/null 2>&1 || true
        sleep 1
        if kill -0 "$pid" >/dev/null 2>&1; then
          kill -9 "$pid" >/dev/null 2>&1 || true
        fi
      fi
    done
  fi
}

main() {
  stop_pid_file "backend" "$BACKEND_PID_FILE"
  stop_pid_file "frontend" "$FRONTEND_PID_FILE"
  stop_port "backend" "$BACKEND_PORT"
  stop_port "frontend" "$FRONTEND_PORT"
  log "GhostRedRecon stopped."
}

main "$@"
