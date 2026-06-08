#!/usr/bin/env bash

audit_request_json() {
  curl --max-time 15 -fsS "$1"
}

audit_post_json() {
  curl --max-time 20 -fsS -X POST "$1"
}

audit_wait_backend() {
  local base_url="$1"
  local log_fn="$2"
  for _ in $(seq 1 60); do
    if curl --max-time 5 -fsS "${base_url}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  "$log_fn" "backend not reachable at ${base_url}"
  return 1
}

audit_fetch_rf_health() {
  local base_url="$1"
  audit_request_json "${base_url}/api/rf/health"
}

audit_write_rf_health() {
  local base_url="$1"
  local output_path="$2"
  audit_fetch_rf_health "$base_url" > "$output_path"
}

audit_require_sdr_attached() {
  local base_url="$1"
  local log_fn="$2"
  local payload
  payload="$(audit_fetch_rf_health "$base_url")" || {
    "$log_fn" "failed to fetch RF health"
    return 1
  }
  python3 - <<'PY' "$payload"
import json, sys
payload = json.loads(sys.argv[1])
if not payload.get("hackrf", {}).get("available"):
    raise SystemExit(2)
PY
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    "$log_fn" "SDR not connected. Please connect SDR."
    return 1
  fi
}

audit_wait_streaming_confirmed() {
  local base_url="$1"
  local log_fn="$2"
  local timeout_seconds="${3:-12}"
  local start_ts
  start_ts="$(date +%s)"
  while true; do
    local payload
    payload="$(audit_fetch_rf_health "$base_url")" || true
    if [[ -n "$payload" ]]; then
      if python3 - <<'PY' "$payload"
import json, sys
payload = json.loads(sys.argv[1])
if payload.get("sdr_streaming_confirmed"):
    raise SystemExit(0)
raise SystemExit(1)
PY
      then
        return 0
      fi
    fi
    if (( $(date +%s) - start_ts >= timeout_seconds )); then
      local reason=""
      if [[ -n "$payload" ]]; then
        reason="$(python3 - <<'PY' "$payload"
import json, sys
payload = json.loads(sys.argv[1])
print(payload.get("sdr_fault_reason", "streaming confirmation timed out"))
PY
)"
      else
        reason="streaming confirmation timed out"
      fi
      "$log_fn" "$reason"
      return 1
    fi
    sleep 1
  done
}
