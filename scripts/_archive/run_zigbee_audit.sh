#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/rf_reports"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-2}"
LIMIT="${LIMIT:-50}"
SKIP_STACK_BOOTSTRAP="${SKIP_STACK_BOOTSTRAP:-0}"
CHANNELS=(${CHANNELS_OVERRIDE:-2405 2420 2435 2450 2465 2480})
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAW_REPORT="$REPORT_DIR/zigbee_audit_${STAMP}.json"
SUMMARY_REPORT="$REPORT_DIR/zigbee_audit_${STAMP}.txt"
TRACE_LOG="$REPORT_DIR/zigbee_audit_${STAMP}.log"
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
  log "  SKIP_STACK_BOOTSTRAP=1 DWELL_SECONDS=${DWELL_SECONDS} LIMIT=${LIMIT} bash $ROOT_DIR/scripts/run_zigbee_audit.sh ${BASE_URL}"
  exit "$exit_code"
}
trap on_error ERR

log() {
  printf '[zigbee-audit] %s\n' "$*" | tee -a "$TRACE_LOG"
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

  log "channel ${freq} MHz action=${action}"
  if [[ "$action" == "start" ]]; then
    post_json "${BASE_URL}/api/system/start?freq_mhz=${freq}" >/dev/null
  else
    post_json "${BASE_URL}/api/system/retune?freq_mhz=${freq}" >/dev/null
  fi
  audit_wait_streaming_confirmed "$BASE_URL" log
  audit_write_rf_health "$BASE_URL" "$output.health.json"

  log "dwell ${freq} MHz for ${DWELL_SECONDS}s"
  sleep "$DWELL_SECONDS"
  log "snapshot ${freq} MHz -> ${output}"
  request_json "${BASE_URL}/api/intel/band/ZIGBEE?limit=${LIMIT}" > "$output"
}

main() {
  mkdir -p "$REPORT_DIR"
  : > "$TRACE_LOG"
  ensure_stack
  audit_require_sdr_attached "$BASE_URL" log

  log "capturing Zigbee channel cycle"
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

  log "running Zigbee consistency validation"
  python3 "$ROOT_DIR/scripts/validate_zigbee_detection.py" --base-url "$BASE_URL" --limit 250 \
    --snapshot "$TMP_DIR/ch1.json" \
    --snapshot "$TMP_DIR/ch2.json" \
    --snapshot "$TMP_DIR/ch3.json" \
    --snapshot "$TMP_DIR/ch4.json" \
    --snapshot "$TMP_DIR/ch5.json" \
    --snapshot "$TMP_DIR/ch6.json" \
    > "$TMP_DIR/validation.json"

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
for idx, freq in enumerate(channels, start=1):
    snapshots[f"ch{idx}_{freq}"] = load(Path(tmp_dir) / f"ch{idx}.json")

validation = load(Path(tmp_dir) / "validation.json")
rf_health = {}
for idx, freq in enumerate(channels, start=1):
    rf_health[f"ch{idx}_{freq}"] = load(Path(tmp_dir) / f"ch{idx}.json.health.json")

raw_report = {
    "base_url": base_url,
    "dwell_seconds": int(dwell_seconds),
    "channels": channels,
    "snapshots": snapshots,
    "rf_health": rf_health,
    "validation": validation,
}
Path(raw_path).write_text(json.dumps(raw_report, indent=2), encoding="utf-8")

lines = []
lines.append("GhostRedRecon Zigbee Audit Report")
lines.append(f"Base URL: {base_url}")
lines.append(f"Dwell Seconds: {dwell_seconds}")
lines.append(f"Hardware Verified: {all(v.get('sdr_streaming_confirmed') for v in rf_health.values())}")
lines.append("")

for label, payload in snapshots.items():
    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []
    zigbee_signals = sum(
        1 for signal in signals
        if str(signal.get("protocol") or "").upper() in {"ZIGBEE", "IEEE_802.15.4", "IEEE_802.15.4_ZIGBEE", "IEEE_802154_ZIGBEE"}
        or str(signal.get("rf_protocol") or "").upper() == "IEEE_802.15.4"
    )
    channel_hits = sum(1 for signal in signals if signal.get("zigbee_channel") is not None)
    lines.append(f"{label}:")
    lines.append(f"  signals={len(signals)} zigbee_signals={zigbee_signals} channel_hits={channel_hits} devices={len(devices)} entities={len(entities)}")
    if signals:
        first = signals[0]
        lines.append(
            "  top_signal="
            f"{first.get('signal_id')} protocol={first.get('protocol')} "
            f"rf_protocol={first.get('rf_protocol')} zigbee_channel={first.get('zigbee_channel')} "
            f"confidence={first.get('confidence')}"
        )
    else:
        lines.append("  top_signal=none")
    lines.append("")

zigbee_validation = validation.get("zigbee_validation") or {}
lines.append("Validation Summary:")
for key in [
    "signal_count",
    "device_count",
    "entity_count",
    "zigbee_signal_ratio",
    "channel_ratio",
    "role_device_ratio",
    "polluted_device_ratio",
    "correlation_purity_ratio",
    "duplicate_entity_ids",
    "consistency_score",
]:
    lines.append(f"  {key}={zigbee_validation.get(key)}")

Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  log "raw report: ${RAW_REPORT}"
  log "summary report: ${SUMMARY_REPORT}"
  log "trace log: ${TRACE_LOG}"
}

main "$@"
