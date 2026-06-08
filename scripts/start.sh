#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/project.config.json"
LOG_DIR="$ROOT_DIR/logs"
FRONTEND_DIR="$ROOT_DIR/frontend"
FRONTEND_PUBLIC_DIR="$FRONTEND_DIR/public"
BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"
BACKEND_PID_FILE="$LOG_DIR/backend.pid"
FRONTEND_PID_FILE="$LOG_DIR/frontend.pid"
WIFI_MK7_PREFERRED_INTERFACE="${WIFI_MK7_PREFERRED_INTERFACE:-wlan1}"
WIFI_MK7_REQUIRE_PRIVILEGED_BACKEND="${WIFI_MK7_REQUIRE_PRIVILEGED_BACKEND:-auto}"
export WIFI_MK7_PREFERRED_INTERFACE
export WIFI_MK7_REQUIRE_PRIVILEGED_BACKEND

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

if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

BACKEND_HOST="${BACKEND_HOST:-$(read_config_value network.backend.host 127.0.0.1)}"
BACKEND_PORT="${BACKEND_PORT:-$(read_config_value network.backend.port 8100)}"
FRONTEND_HOST="${FRONTEND_HOST:-$(read_config_value network.frontend.host 127.0.0.1)}"
FRONTEND_PORT="${FRONTEND_PORT:-$(read_config_value network.frontend.port 5174)}"
BACKEND_URL="http://${BACKEND_HOST}:${BACKEND_PORT}"
FRONTEND_URL="http://${FRONTEND_HOST}:${FRONTEND_PORT}"

log() {
  printf '[start] %s\n' "$*"
}

fail() {
  printf '[start] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

can_passwordless_sudo() {
  sudo -n true >/dev/null 2>&1
}

resolve_uvicorn() {
  if [[ -x "$ROOT_DIR/backend/.venv/bin/uvicorn" ]]; then
    printf '%s\n' "$ROOT_DIR/backend/.venv/bin/uvicorn"
    return 0
  fi
  if need_cmd uvicorn; then
    printf 'uvicorn\n'
    return 0
  fi
  if python3 -m uvicorn --version >/dev/null 2>&1; then
    printf 'python3 -m uvicorn\n'
    return 0
  fi
  return 1
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

wifi_mk7_interface_present() {
  if ! need_cmd iw; then
    return 1
  fi
  iw dev 2>/dev/null | grep -q "Interface ${WIFI_MK7_PREFERRED_INTERFACE}\$"
}

backend_requires_privileges() {
  case "$WIFI_MK7_REQUIRE_PRIVILEGED_BACKEND" in
    always|true|1|yes)
      return 0
      ;;
    never|false|0|no)
      return 1
      ;;
  esac

  if [[ "$(id -u)" -eq 0 ]]; then
    return 0
  fi

  if wifi_mk7_interface_present; then
    return 0
  fi

  return 1
}

backend_launch_command() {
  local backend_runner
  backend_runner="$(resolve_backend_runner)" || return 1
  printf '%s backend.main:app --host %q --port %q --app-dir %q' "$backend_runner" "$BACKEND_HOST" "$BACKEND_PORT" "$ROOT_DIR"
}

write_frontend_config() {
  mkdir -p "$FRONTEND_PUBLIC_DIR"
  PROJECT_CONFIG_PATH="$CONFIG_FILE" PROJECT_CONFIG_BACKEND_URL="$BACKEND_URL" PROJECT_CONFIG_FRONTEND_URL="$FRONTEND_URL" PROJECT_CONFIG_OUTPUT="$FRONTEND_PUBLIC_DIR/config.js" python3 - <<'PY'
import json
import os
from pathlib import Path

config_path = Path(os.environ["PROJECT_CONFIG_PATH"])
output_path = Path(os.environ["PROJECT_CONFIG_OUTPUT"])
config = json.loads(config_path.read_text(encoding="utf-8"))
config.setdefault("network", {}).setdefault("backend", {})["resolvedUrl"] = os.environ["PROJECT_CONFIG_BACKEND_URL"]
config.setdefault("network", {}).setdefault("frontend", {})["resolvedUrl"] = os.environ["PROJECT_CONFIG_FRONTEND_URL"]
payload = "window.GHOSTRECON_CONFIG = " + json.dumps(config, indent=2) + ";\n"
output_path.write_text(payload, encoding="utf-8")
PY
}

cleanup_stale_pid() {
  local pid_file="$1"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
    fi
    rm -f "$pid_file"
  fi
}

stop_port_owner() {
  local port="$1"
  local pids
  pids="$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {print $NF}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u || true)"
  if [[ -n "$pids" ]]; then
    for pid in $pids; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        log "Stopping stale port owner ${pid} on ${port}..."
        kill "$pid" >/dev/null 2>&1 || true
        sleep 1
        if kill -0 "$pid" >/dev/null 2>&1; then
          kill -9 "$pid" >/dev/null 2>&1 || true
        fi
      fi
    done
  fi
}

store_port_owner_pid() {
  local port="$1"
  local pid_file="$2"
  local pid
  pid="$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {print $NF}' | grep -o 'pid=[0-9]\+' | head -n 1 | cut -d= -f2 || true)"
  if [[ -n "$pid" ]]; then
    echo "$pid" > "$pid_file"
  fi
}

wait_for_http() {
  local url="$1"
  local label="$2"
  for _ in $(seq 1 40); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "$label did not become ready"
}

open_browser() {
  if need_cmd xdg-open; then
    nohup xdg-open "$FRONTEND_URL" >/dev/null 2>&1 &
  fi
}

ensure_layout() {
  mkdir -p "$LOG_DIR"
  : > "$BACKEND_LOG"
  : > "$FRONTEND_LOG"
}

check_hackrf() {
  if need_cmd hackrf_info; then
    if hackrf_info >/dev/null 2>&1; then
      log "HackRF check passed."
    else
      log "HackRF check failed. Backend will still start, but SDR operations may fail until hardware access is restored."
    fi
  else
    log "hackrf_info not found. SDR validation skipped."
  fi
}

check_wifi_mk7() {
  if ! need_cmd iw; then
    log "iw not found. WiFi MK7 capability checks skipped."
    return
  fi

  if wifi_mk7_interface_present; then
    log "WiFi MK7 preferred interface ${WIFI_MK7_PREFERRED_INTERFACE} detected."
  else
    log "WiFi MK7 preferred interface ${WIFI_MK7_PREFERRED_INTERFACE} not detected. The GUI will warn until the adapter is connected."
  fi

  if backend_requires_privileges; then
    if [[ "$(id -u)" -eq 0 ]]; then
      log "Backend will run as root so WiFi MK7 channel control is available."
    elif can_passwordless_sudo; then
      log "Backend will use passwordless sudo for WiFi MK7 network capabilities."
    else
      log "WiFi MK7 requires CAP_NET_ADMIN/root for monitor-mode channel control."
      log "Start this script with sudo or use the provided systemd service for production WiFi MK7 scanning."
    fi
  fi
}

start_backend() {
  log "Starting backend on ${BACKEND_URL}..."
  local launch_cmd
  launch_cmd="$(backend_launch_command)" || fail "uvicorn is required"

  if backend_requires_privileges; then
    if [[ "$(id -u)" -eq 0 ]]; then
      setsid bash -lc "cd '$ROOT_DIR' && exec ${launch_cmd}" >>"$BACKEND_LOG" 2>&1 </dev/null &
      return
    fi
    if can_passwordless_sudo; then
      setsid bash -lc "cd '$ROOT_DIR' && exec sudo -n env PATH='$PATH' HOME='$HOME' ${launch_cmd}" >>"$BACKEND_LOG" 2>&1 </dev/null &
      return
    fi
  fi

  setsid bash -lc "cd '$ROOT_DIR' && exec ${launch_cmd}" >>"$BACKEND_LOG" 2>&1 </dev/null &
}

start_frontend() {
  log "Starting Node.js frontend on ${FRONTEND_URL}..."
  if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    log "Installing frontend dependencies..."
    npm --prefix "$FRONTEND_DIR" install >/dev/null
  fi
  setsid bash -lc "cd '$ROOT_DIR' && exec npm --prefix '$FRONTEND_DIR' run dev -- --host '$FRONTEND_HOST' --port '$FRONTEND_PORT'" >>"$FRONTEND_LOG" 2>&1 </dev/null &
}

main() {
  need_cmd python3 || fail "python3 is required"
  need_cmd curl || fail "curl is required"
  need_cmd npm || fail "npm is required"
  ensure_layout
  cleanup_stale_pid "$BACKEND_PID_FILE"
  cleanup_stale_pid "$FRONTEND_PID_FILE"
  stop_port_owner "$BACKEND_PORT"
  stop_port_owner "$FRONTEND_PORT"
  write_frontend_config
  check_hackrf
  check_wifi_mk7
  start_backend
  wait_for_http "${BACKEND_URL}/health" "Backend"
  store_port_owner_pid "$BACKEND_PORT" "$BACKEND_PID_FILE"
  start_frontend
  wait_for_http "${FRONTEND_URL}/" "Frontend"
  store_port_owner_pid "$FRONTEND_PORT" "$FRONTEND_PID_FILE"
  open_browser
  echo "Backend: ${BACKEND_URL}"
  echo "Frontend: ${FRONTEND_URL}"
  echo "Backend log: ${BACKEND_LOG}"
  echo "Frontend log: ${FRONTEND_LOG}"
}

main "$@"
