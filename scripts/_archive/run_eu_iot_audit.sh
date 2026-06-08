#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/rf_reports"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-2}"
LIMIT="${LIMIT:-20}"
SKIP_STACK_BOOTSTRAP="${SKIP_STACK_BOOTSTRAP:-0}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAW_REPORT="$REPORT_DIR/eu_iot_audit_${STAMP}.json"
SUMMARY_REPORT="$REPORT_DIR/eu_iot_audit_${STAMP}.txt"
TRACE_LOG="$REPORT_DIR/eu_iot_audit_${STAMP}.log"
TMP_DIR="$(mktemp -d)"
source "$ROOT_DIR/scripts/audit_common.sh"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
  printf '[eu-iot-audit] %s\n' "$*" | tee -a "$TRACE_LOG"
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

capture_point() {
  local freq="$1"
  local action="$2"
  local label="$3"
  local output="$4"

  log "capture ${label} @ ${freq} MHz action=${action}"
  if [[ "$action" == "start" ]]; then
    post_json "${BASE_URL}/api/system/start?freq_mhz=${freq}" >/dev/null
  else
    post_json "${BASE_URL}/api/system/retune?freq_mhz=${freq}" >/dev/null
  fi
  audit_wait_streaming_confirmed "$BASE_URL" log
  audit_write_rf_health "$BASE_URL" "$output.health.json"
  sleep "$DWELL_SECONDS"
  request_json "${BASE_URL}/api/intel/band/IOT?limit=${LIMIT}" > "$output"
}

main() {
  mkdir -p "$REPORT_DIR"
  : > "$TRACE_LOG"
  ensure_stack
  audit_require_sdr_attached "$BASE_URL" log

  capture_point "2402" "start" "ble_adv_37" "$TMP_DIR/ble37.json"
  capture_point "2426" "retune" "ble_adv_38" "$TMP_DIR/ble38.json"
  capture_point "2480" "retune" "ble_adv_39" "$TMP_DIR/ble39.json"
  capture_point "2405" "retune" "zigbee_11" "$TMP_DIR/zb11.json"
  capture_point "2425" "retune" "zigbee_15" "$TMP_DIR/zb15.json"
  capture_point "2450" "retune" "zigbee_20" "$TMP_DIR/zb20.json"
  capture_point "2475" "retune" "zigbee_25" "$TMP_DIR/zb25.json"
  capture_point "2412" "retune" "wifi_1" "$TMP_DIR/wifi1.json"
  capture_point "2437" "retune" "wifi_6" "$TMP_DIR/wifi6.json"
  capture_point "2462" "retune" "wifi_11" "$TMP_DIR/wifi11.json"
  capture_point "433.92" "retune" "eu_srd_43392" "$TMP_DIR/srd43392.json"
  capture_point "434.08" "retune" "eu_srd_43408" "$TMP_DIR/srd43408.json"
  capture_point "868.30" "retune" "eu_868_telemetry" "$TMP_DIR/eu86830.json"
  capture_point "868.95" "retune" "eu_868_meter" "$TMP_DIR/eu86895.json"
  capture_point "869.525" "retune" "eu_869525" "$TMP_DIR/eu869525.json"

  log "running EU IoT validation"
  python3 "$ROOT_DIR/scripts/validate_iot_detection.py" --base-url "$BASE_URL" --limit 250 \
    --snapshot "$TMP_DIR/ble37.json" \
    --snapshot "$TMP_DIR/ble38.json" \
    --snapshot "$TMP_DIR/ble39.json" \
    --snapshot "$TMP_DIR/zb11.json" \
    --snapshot "$TMP_DIR/zb15.json" \
    --snapshot "$TMP_DIR/zb20.json" \
    --snapshot "$TMP_DIR/zb25.json" \
    --snapshot "$TMP_DIR/wifi1.json" \
    --snapshot "$TMP_DIR/wifi6.json" \
    --snapshot "$TMP_DIR/wifi11.json" \
    --snapshot "$TMP_DIR/srd43392.json" \
    --snapshot "$TMP_DIR/srd43408.json" \
    --snapshot "$TMP_DIR/eu86830.json" \
    --snapshot "$TMP_DIR/eu86895.json" \
    --snapshot "$TMP_DIR/eu869525.json" > "$TMP_DIR/validation.json"

  log "stopping session"
  curl --max-time 10 -fsS -X POST "${BASE_URL}/api/system/stop" >/dev/null || true

  python3 - <<'PY' "$TMP_DIR/validation.json" "$RAW_REPORT" "$SUMMARY_REPORT" "$DWELL_SECONDS" "$BASE_URL" "$TMP_DIR"
import json
import sys
from pathlib import Path

validation_path, raw_path, summary_path, dwell_seconds, base_url, tmp_dir = sys.argv[1:]
validation = json.loads(Path(validation_path).read_text(encoding="utf-8"))
snapshots = {}
rf_health = {}
for path in sorted(Path(tmp_dir).glob("*.json")):
    if path.name == "validation.json":
        continue
    if path.name.endswith(".health.json"):
        rf_health[path.stem.replace(".json", "")] = json.loads(path.read_text(encoding="utf-8"))
        continue
    snapshots[path.stem] = json.loads(path.read_text(encoding="utf-8"))

raw_report = {
    "base_url": base_url,
    "dwell_seconds": int(dwell_seconds),
    "snapshots": snapshots,
    "rf_health": rf_health,
    "validation": validation,
}
Path(raw_path).write_text(json.dumps(raw_report, indent=2), encoding="utf-8")

metrics = validation.get("iot_validation") or {}
lines = [
    "GhostRedRecon EU IoT Audit Report",
    f"Base URL: {base_url}",
    f"Dwell Seconds: {dwell_seconds}",
    f"Hardware Verified: {all(v.get('sdr_streaming_confirmed') for v in rf_health.values())}",
    "",
]

for label, payload in snapshots.items():
    indicators = payload.get("indicators") or {}
    lines.append(
        f"{label}: signals={len(payload.get('signals') or [])} devices={len(payload.get('devices') or [])} "
        f"protocols={len(indicators.get('protocol_density') or [])} profiles={len(indicators.get('matched_profile_density') or [])}"
    )

lines.append("")
lines.append("Validation Summary:")
for key in [
    "signal_count",
    "device_count",
    "entity_count",
    "iot_signal_ratio",
    "typed_device_ratio",
    "matched_profile_ratio",
    "utility_meter_ratio",
    "wifi_iot_signal_ratio",
    "subghz_iot_signal_ratio",
    "consistency_score",
]:
    lines.append(f"  {key}={metrics.get(key)}")
lines.append(f"  family_counts={metrics.get('family_counts')}")

Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  log "raw report: ${RAW_REPORT}"
  log "summary report: ${SUMMARY_REPORT}"
  log "trace log: ${TRACE_LOG}"
}

main "$@"
