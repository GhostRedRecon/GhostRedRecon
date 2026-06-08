#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/rf_reports"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-2}"
LIMIT="${LIMIT:-25}"
SKIP_STACK_BOOTSTRAP="${SKIP_STACK_BOOTSTRAP:-0}"
CHANNELS=(${CHANNELS_OVERRIDE:-2412 2437 2462})
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAW_REPORT="$REPORT_DIR/wifi_iot_audit_${STAMP}.json"
SUMMARY_REPORT="$REPORT_DIR/wifi_iot_audit_${STAMP}.txt"
TRACE_LOG="$REPORT_DIR/wifi_iot_audit_${STAMP}.log"
TMP_DIR="$(mktemp -d)"
source "$ROOT_DIR/scripts/audit_common.sh"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

on_error() {
  local exit_code=$?
  log "audit failed with exit code ${exit_code}"
  exit "$exit_code"
}
trap on_error ERR

log() {
  printf '[wifi-iot-audit] %s\n' "$*" | tee -a "$TRACE_LOG"
}

request_json() {
  curl --max-time 15 -fsS "$1"
}

post_json() {
  curl --max-time 20 -fsS -X POST "$1"
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
  log "backend unavailable, starting GhostRedRecon backend directly"
  python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8100 --app-dir "$ROOT_DIR" >/dev/null 2>&1 &
  audit_wait_backend "$BASE_URL" log
  log "backend is healthy"
}

capture_channel() {
  local freq="$1"
  local action="$2"
  local output="$3"

  log "channel ${freq} MHz action=${action}"
  if [[ "$action" == "start" ]]; then
    post_json "${BASE_URL}/api/system/start?freq_mhz=${freq}" >/dev/null
  else
    post_json "${BASE_URL}/api/system/retune?freq_mhz=${freq}" >/dev/null
  fi
  audit_wait_streaming_confirmed "$BASE_URL" log
  audit_write_rf_health "$BASE_URL" "$output.health.json"
  sleep "$DWELL_SECONDS"
  request_json "${BASE_URL}/api/intel/band/WIFI?limit=${LIMIT}" > "$output"
}

main() {
  mkdir -p "$REPORT_DIR"
  : > "$TRACE_LOG"
  ensure_stack
  audit_require_sdr_attached "$BASE_URL" log

  log "capturing WiFi IoT channel cycle"
  local first=1
  local idx=0
  for freq in "${CHANNELS[@]}"; do
    idx=$((idx + 1))
    if [[ "$first" -eq 1 ]]; then
      capture_channel "$freq" "start" "$TMP_DIR/ch${idx}.json"
      first=0
    else
      capture_channel "$freq" "retune" "$TMP_DIR/ch${idx}.json"
    fi
  done

  log "running WiFi IoT validation"
  local validator_args=()
  for idx in $(seq 1 ${#CHANNELS[@]}); do
    validator_args+=("--snapshot" "$TMP_DIR/ch${idx}.json")
  done
  python3 "$ROOT_DIR/scripts/validate_wifi_iot_detection.py" "${validator_args[@]}" > "$TMP_DIR/validation.json"

  log "stopping session"
  curl --max-time 10 -fsS -X POST "${BASE_URL}/api/system/stop" >/dev/null || true

  python3 - <<'PY' "$TMP_DIR" "$RAW_REPORT" "$SUMMARY_REPORT" "$DWELL_SECONDS" "$BASE_URL" "${CHANNELS[@]}"
import json
import sys
from pathlib import Path

tmp_dir, raw_path, summary_path, dwell_seconds, base_url, *channels = sys.argv[1:]

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

snapshots = {}
rf_health = {}
for idx, freq in enumerate(channels, start=1):
    snapshots[f"ch{idx}_{freq}"] = load(Path(tmp_dir) / f"ch{idx}.json")
    rf_health[f"ch{idx}_{freq}"] = load(Path(tmp_dir) / f"ch{idx}.json.health.json")

validation = load(Path(tmp_dir) / "validation.json")
raw_report = {
    "base_url": base_url,
    "dwell_seconds": int(dwell_seconds),
    "channels": channels,
    "snapshots": snapshots,
    "rf_health": rf_health,
    "validation": validation,
}
Path(raw_path).write_text(json.dumps(raw_report, indent=2), encoding="utf-8")

metrics = validation.get("wifi_iot_validation") or {}
lines = [
    "GhostRedRecon WiFi IoT Audit Report",
    f"Base URL: {base_url}",
    f"Dwell Seconds: {dwell_seconds}",
    f"Hardware Verified: {all(v.get('sdr_streaming_confirmed') for v in rf_health.values())}",
    "",
]

for label, payload in snapshots.items():
    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []
    wifi_signals = sum(
        1 for signal in signals
        if str(signal.get("protocol") or "").upper() == "WIFI"
        or "802.11" in str(signal.get("rf_protocol") or "")
    )
    lines.append(f"{label}:")
    lines.append(f"  signals={len(signals)} wifi_signals={wifi_signals} devices={len(devices)} entities={len(entities)}")
    if devices:
        top = devices[0]
        lines.append(
            "  top_device="
            f"{top.get('device_id')} protocols={top.get('protocols')} "
            f"device_type={top.get('device_type')} category={top.get('device_category')} "
            f"product={top.get('product')}"
        )
    else:
        lines.append("  top_device=none")
    lines.append("")

for key in [
    "signal_count",
    "device_count",
    "entity_count",
    "wifi_signal_ratio",
    "wifi_iot_signal_ratio",
    "wifi_iot_device_ratio",
    "signal_label_purity_ratio",
    "device_label_purity_ratio",
    "matched_profile_ratio",
    "consistency_score",
]:
    lines.append(f"  {key}={metrics.get(key)}")

Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  log "raw report: ${RAW_REPORT}"
  log "summary report: ${SUMMARY_REPORT}"
  log "trace log: ${TRACE_LOG}"
}

main "$@"
