#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/rf_reports"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-6}"
LIMIT="${LIMIT:-50}"
SKIP_STACK_BOOTSTRAP="${SKIP_STACK_BOOTSTRAP:-0}"
ADAPTIVE_DWELL="${ADAPTIVE_DWELL:-1}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAW_REPORT="$REPORT_DIR/ble_audit_${STAMP}.json"
SUMMARY_REPORT="$REPORT_DIR/ble_audit_${STAMP}.txt"
TRACE_LOG="$REPORT_DIR/ble_audit_${STAMP}.log"
TMP_DIR="$(mktemp -d)"
source "$ROOT_DIR/scripts/audit_common.sh"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

on_error() {
  local exit_code=$?
  log "audit failed with exit code ${exit_code}"
  log "if backend bootstrap is unreliable in your shell, run:"
  log "  bash $ROOT_DIR/scripts/start.sh"
  log "  SKIP_STACK_BOOTSTRAP=1 DWELL_SECONDS=${DWELL_SECONDS} LIMIT=${LIMIT} bash $ROOT_DIR/scripts/run_ble_audit.sh ${BASE_URL}"
  exit "$exit_code"
}
trap on_error ERR

log() {
  printf '[ble-audit] %s\n' "$*" | tee -a "$TRACE_LOG"
}

request_json() {
  curl --max-time 15 -fsS "$1"
}

post_json() {
  curl --max-time 20 -fsS -X POST "$1"
}

wait_backend() {
  for _ in $(seq 1 60); do
    if curl --max-time 5 -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  log "backend not reachable at ${BASE_URL}"
  return 1
}

ensure_stack() {
  if curl --max-time 5 -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    log "backend already healthy"
    return 0
  fi

  if [[ "$SKIP_STACK_BOOTSTRAP" == "1" ]]; then
    log "backend unavailable and bootstrap disabled"
    return 1
  fi

  log "backend unavailable, starting GhostRedRecon stack"
  bash "$ROOT_DIR/scripts/start.sh" >/dev/null 2>&1 &
  wait_backend
  log "backend is healthy"
}

capture_channel() {
  local freq="$1"
  local action="$2"
  local output="$3"
  local dwell="$DWELL_SECONDS"

  log "channel ${freq} MHz action=${action}"
  if [[ "$action" == "start" ]]; then
    post_json "${BASE_URL}/api/system/start?freq_mhz=${freq}" >/dev/null
  else
    post_json "${BASE_URL}/api/system/retune?freq_mhz=${freq}" >/dev/null
  fi
  audit_wait_streaming_confirmed "$BASE_URL" log
  audit_write_rf_health "$BASE_URL" "$TMP_DIR/rf_health_${freq}.json"

  if [[ "$ADAPTIVE_DWELL" == "1" ]]; then
    local status_json
    status_json="$(request_json "${BASE_URL}/api/intel/ble/decoder/status" || true)"
    if [[ -n "$status_json" ]]; then
      dwell="$(python3 - <<'PY' "$status_json" "$freq" "$DWELL_SECONDS"
import json
import sys

payload = json.loads(sys.argv[1])
freq = str(int(float(sys.argv[2])))
fallback = float(sys.argv[3])
channel_dwell = payload.get("channel_dwell_ms") or {}
dwell_ms = float(channel_dwell.get(freq) or (fallback * 1000.0))
print(max(1.0, round(dwell_ms / 1000.0, 2)))
PY
)"
    fi
  fi

  log "dwell ${freq} MHz for ${dwell}s"
  sleep "$dwell"
  log "snapshot ${freq} MHz -> ${output}"
  request_json "${BASE_URL}/api/intel/band/BLE?limit=${LIMIT}" > "$output"
}

main() {
  mkdir -p "$REPORT_DIR"
  : > "$TRACE_LOG"
  ensure_stack
  audit_require_sdr_attached "$BASE_URL" log

  log "capturing BLE advertising-channel cycle"
  capture_channel "2402" "start" "$TMP_DIR/ch37.json"
  capture_channel "2426" "retune" "$TMP_DIR/ch38.json"
  capture_channel "2480" "retune" "$TMP_DIR/ch39.json"

  log "running BLE consistency validation"
  python3 "$ROOT_DIR/scripts/validate_ble_detection.py" --base-url "$BASE_URL" --limit 250 > "$TMP_DIR/validation.json"

  log "stopping session"
  curl --max-time 10 -fsS -X POST "${BASE_URL}/api/system/stop" >/dev/null || true

  python3 - <<'PY' "$TMP_DIR/ch37.json" "$TMP_DIR/ch38.json" "$TMP_DIR/ch39.json" "$TMP_DIR/validation.json" "$RAW_REPORT" "$SUMMARY_REPORT" "$DWELL_SECONDS" "$BASE_URL" "$TMP_DIR/rf_health_2402.json" "$TMP_DIR/rf_health_2426.json" "$TMP_DIR/rf_health_2480.json"
import json
import sys
from pathlib import Path

ch37_path, ch38_path, ch39_path, validation_path, raw_path, summary_path, dwell_seconds, base_url, health37_path, health38_path, health39_path = sys.argv[1:]

def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

snapshots = {
    "ch37_2402": load(ch37_path),
    "ch38_2426": load(ch38_path),
    "ch39_2480": load(ch39_path),
}
validation = load(validation_path)
rf_health = {
    "ch37_2402": load(health37_path),
    "ch38_2426": load(health38_path),
    "ch39_2480": load(health39_path),
}

raw_report = {
    "base_url": base_url,
    "dwell_seconds": int(dwell_seconds),
    "snapshots": snapshots,
    "rf_health": rf_health,
    "validation": validation,
}
Path(raw_path).write_text(json.dumps(raw_report, indent=2), encoding="utf-8")

lines = []
lines.append("GhostRedRecon BLE Audit Report")
lines.append(f"Base URL: {base_url}")
lines.append(f"Dwell Seconds: {dwell_seconds}")
lines.append(f"Hardware Verified: {all(v.get('sdr_streaming_confirmed') for v in rf_health.values())}")
lines.append("")

for label, payload in snapshots.items():
    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []
    ble_signals = sum(
        1 for signal in signals
        if str(signal.get("protocol") or "").upper() == "BLE"
        or str(signal.get("rf_protocol") or "").upper() == "BLUETOOTH_LE"
    )
    adv_hits = sum(1 for signal in signals if signal.get("ble_channel") in {37, 38, 39})
    lines.append(f"{label}:")
    lines.append(f"  signals={len(signals)} ble_signals={ble_signals} adv_hits={adv_hits} devices={len(devices)} entities={len(entities)}")
    if signals:
      first = signals[0]
      lines.append(
          "  top_signal="
          f"{first.get('signal_id')} protocol={first.get('protocol')} "
          f"rf_protocol={first.get('rf_protocol')} ble_channel={first.get('ble_channel')} "
          f"confidence={first.get('confidence')}"
      )
    else:
      lines.append("  top_signal=none")
    lines.append("")

ble_validation = validation.get("ble_validation") or {}
lines.append("Validation Summary:")
for key in [
    "signal_count",
    "device_count",
    "entity_count",
    "ble_signal_ratio",
    "adv_channel_ratio",
    "ble_role_device_ratio",
    "polluted_device_ratio",
    "duplicate_entity_ids",
    "consistency_score",
]:
    lines.append(f"  {key}={ble_validation.get(key)}")

Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  log "raw report: ${RAW_REPORT}"
  log "summary report: ${SUMMARY_REPORT}"
  log "trace log: ${TRACE_LOG}"
}

main "$@"
