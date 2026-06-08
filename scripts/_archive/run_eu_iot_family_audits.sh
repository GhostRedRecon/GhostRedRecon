#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/rf_reports"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-2}"
LIMIT="${LIMIT:-20}"
SKIP_STACK_BOOTSTRAP="${SKIP_STACK_BOOTSTRAP:-1}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY_REPORT="$REPORT_DIR/eu_iot_family_audit_${STAMP}.txt"
RAW_REPORT="$REPORT_DIR/eu_iot_family_audit_${STAMP}.json"
TRACE_LOG="$REPORT_DIR/eu_iot_family_audit_${STAMP}.log"
TMP_DIR="$(mktemp -d)"
source "$ROOT_DIR/scripts/audit_common.sh"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
  printf '[eu-iot-family] %s\n' "$*" | tee -a "$TRACE_LOG"
}

request_json() {
  curl --max-time 15 -fsS "$1"
}

post_json() {
  curl --max-time 20 -fsS -X POST "$1"
}

capture_wifi_channel() {
  local freq="$1"
  local action="$2"
  local output="$3"
  log "wifi channel ${freq} MHz action=${action}"
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

latest_file() {
  local pattern="$1"
  ls -1t $pattern 2>/dev/null | head -n 1
}

main() {
  mkdir -p "$REPORT_DIR"
  : > "$TRACE_LOG"
  audit_wait_backend "$BASE_URL" log
  audit_require_sdr_attached "$BASE_URL" log

  log "running EU BLE audit"
  SKIP_STACK_BOOTSTRAP="$SKIP_STACK_BOOTSTRAP" DWELL_SECONDS="$DWELL_SECONDS" LIMIT="$LIMIT" bash "$ROOT_DIR/scripts/run_ble_audit.sh" "$BASE_URL" >/dev/null
  local ble_report
  ble_report="$(latest_file "$REPORT_DIR/ble_audit_*.json")"

  log "running EU Zigbee audit"
  SKIP_STACK_BOOTSTRAP="$SKIP_STACK_BOOTSTRAP" DWELL_SECONDS="$DWELL_SECONDS" LIMIT="$LIMIT" CHANNELS_OVERRIDE="2405 2425 2450 2475" bash "$ROOT_DIR/scripts/run_zigbee_audit.sh" "$BASE_URL" >/dev/null
  local zigbee_report
  zigbee_report="$(latest_file "$REPORT_DIR/zigbee_audit_*.json")"

  log "running EU WiFi IoT audit"
  capture_wifi_channel "2412" "start" "$TMP_DIR/wifi1.json"
  capture_wifi_channel "2437" "retune" "$TMP_DIR/wifi6.json"
  capture_wifi_channel "2462" "retune" "$TMP_DIR/wifi11.json"
  python3 "$ROOT_DIR/scripts/validate_wifi_iot_detection.py" --base-url "$BASE_URL" --limit 250 \
    --snapshot "$TMP_DIR/wifi1.json" \
    --snapshot "$TMP_DIR/wifi6.json" \
    --snapshot "$TMP_DIR/wifi11.json" > "$TMP_DIR/wifi_validation.json"
  curl --max-time 10 -fsS -X POST "${BASE_URL}/api/system/stop" >/dev/null || true

  log "running EU LPWAN audit"
  LORA_REGION_PROFILE="eu868_lab" SKIP_STACK_BOOTSTRAP="$SKIP_STACK_BOOTSTRAP" DWELL_SECONDS="$DWELL_SECONDS" LIMIT="$LIMIT" bash "$ROOT_DIR/scripts/run_lora_audit.sh" "$BASE_URL" >/dev/null
  local lora_report
  lora_report="$(latest_file "$REPORT_DIR/lora_audit_*.json")"

  python3 - <<'PY' "$ble_report" "$zigbee_report" "$lora_report" "$TMP_DIR/wifi1.json" "$TMP_DIR/wifi6.json" "$TMP_DIR/wifi11.json" "$TMP_DIR/wifi_validation.json" "$RAW_REPORT" "$SUMMARY_REPORT" "$BASE_URL" "$DWELL_SECONDS"
import json
import sys
from pathlib import Path

ble_path, zigbee_path, lora_path, wifi1_path, wifi6_path, wifi11_path, wifi_validation_path, raw_path, summary_path, base_url, dwell_seconds = sys.argv[1:]

def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

ble = load(ble_path)
zigbee = load(zigbee_path)
lora = load(lora_path)
wifi = {
    "snapshots": {
        "wifi1_2412": load(wifi1_path),
        "wifi6_2437": load(wifi6_path),
        "wifi11_2462": load(wifi11_path),
    },
    "validation": load(wifi_validation_path),
}

raw = {
    "base_url": base_url,
    "dwell_seconds": int(dwell_seconds),
    "ble": ble,
    "zigbee": zigbee,
    "wifi": wifi,
    "lora": lora,
}
Path(raw_path).write_text(json.dumps(raw, indent=2), encoding="utf-8")

ble_metrics = ble.get("validation", {}).get("ble_validation", {})
zigbee_metrics = zigbee.get("validation", {}).get("zigbee_validation", {})
wifi_metrics = wifi.get("validation", {}).get("wifi_iot_validation", {})
lora_metrics = lora.get("validation", {}).get("true_lora_validation", {})

lines = [
    "GhostRedRecon EU IoT Family Hunt",
    f"Base URL: {base_url}",
    f"Dwell Seconds: {dwell_seconds}",
    "",
    "BLE:",
    f"  consistency_score={ble_metrics.get('consistency_score')}",
    f"  ble_signal_ratio={ble_metrics.get('ble_signal_ratio')}",
    f"  adv_channel_ratio={ble_metrics.get('adv_channel_ratio')}",
    f"  ble_role_device_ratio={ble_metrics.get('ble_role_device_ratio')}",
    "",
    "Zigbee:",
    f"  consistency_score={zigbee_metrics.get('consistency_score')}",
    f"  zigbee_signal_ratio={zigbee_metrics.get('zigbee_signal_ratio')}",
    f"  channel_ratio={zigbee_metrics.get('channel_ratio')}",
    f"  role_device_ratio={zigbee_metrics.get('role_device_ratio')}",
    "",
    "WiFi IoT:",
    f"  consistency_score={wifi_metrics.get('consistency_score')}",
    f"  wifi_signal_ratio={wifi_metrics.get('wifi_signal_ratio')}",
    f"  wifi_iot_signal_ratio={wifi_metrics.get('wifi_iot_signal_ratio')}",
    f"  signal_label_purity_ratio={wifi_metrics.get('signal_label_purity_ratio')}",
    f"  device_label_purity_ratio={wifi_metrics.get('device_label_purity_ratio')}",
    "",
    "EU LPWAN:",
    f"  consistency_score={lora_metrics.get('consistency_score')}",
    f"  lora_signal_ratio={lora_metrics.get('lora_signal_ratio')}",
    f"  typed_device_ratio={lora_metrics.get('typed_device_ratio')}",
    f"  polluted_device_ratio={lora_metrics.get('polluted_device_ratio')}",
    f"  identity_family_counts={lora_metrics.get('identity_family_counts')}",
]
Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  log "raw report: ${RAW_REPORT}"
  log "summary report: ${SUMMARY_REPORT}"
  log "trace log: ${TRACE_LOG}"
}

main "$@"
