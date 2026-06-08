#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/rf_reports"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-3}"
LIMIT="${LIMIT:-50}"
SKIP_STACK_BOOTSTRAP="${SKIP_STACK_BOOTSTRAP:-0}"
LORA_REGION_PROFILE="${LORA_REGION_PROFILE:-all_lab}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAW_REPORT="$REPORT_DIR/lora_audit_${STAMP}.json"
SUMMARY_REPORT="$REPORT_DIR/lora_audit_${STAMP}.txt"
TRACE_LOG="$REPORT_DIR/lora_audit_${STAMP}.log"
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
  log "  python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8100 --app-dir $ROOT_DIR"
  log "  SKIP_STACK_BOOTSTRAP=1 DWELL_SECONDS=${DWELL_SECONDS} LIMIT=${LIMIT} bash $ROOT_DIR/scripts/run_lora_audit.sh ${BASE_URL}"
  exit "$exit_code"
}
trap on_error ERR

log() {
  printf '[lora-audit] %s\n' "$*" | tee -a "$TRACE_LOG"
}

channels_for_profile() {
  case "$1" in
    eu868|eu868_lab)
      printf '%s\n' 867.10 867.30 867.50 867.70 867.90 868.10 868.30 868.50 869.525
      ;;
    us915|us915_lab)
      printf '%s\n' 903.90 904.10 904.30 904.50 904.70 904.90 905.10 905.30 923.30
      ;;
    ism433|433|ism433_lab)
      printf '%s\n' 433.175 433.375 433.775 433.920
      ;;
    all|all_lab|*)
      printf '%s\n' 433.175 433.375 433.775 433.920 867.10 867.30 867.50 867.70 867.90 868.10 868.30 868.50 869.525 903.90 904.10 904.30 904.50 904.70 904.90 905.10 905.30 923.30
      ;;
  esac
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

  log "backend unavailable, starting GhostRedRecon backend directly"
  python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8100 --app-dir "$ROOT_DIR" >/dev/null 2>&1 &
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
  request_json "${BASE_URL}/api/intel/band/sub-ghz?limit=${LIMIT}" > "$output"
}

main() {
  mkdir -p "$REPORT_DIR"
  : > "$TRACE_LOG"
  local CHANNELS=()
  if [[ -n "${CHANNELS_OVERRIDE:-}" ]]; then
    CHANNELS=(${CHANNELS_OVERRIDE})
  else
    mapfile -t CHANNELS < <(channels_for_profile "$LORA_REGION_PROFILE")
  fi
  ensure_stack
  audit_require_sdr_attached "$BASE_URL" log

  log "capturing LoRa-focused channel cycle profile=${LORA_REGION_PROFILE}"
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

  log "running true LoRa consistency validation"
  local validator_args=()
  for idx in $(seq 1 ${#CHANNELS[@]}); do
    validator_args+=("--snapshot" "$TMP_DIR/ch${idx}.json")
  done
  python3 "$ROOT_DIR/scripts/validate_true_lora_detection.py" --base-url "$BASE_URL" --limit 250 "${validator_args[@]}" > "$TMP_DIR/validation.json"

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
lines.append("GhostRedRecon True LoRa Audit Report")
lines.append(f"Base URL: {base_url}")
lines.append(f"Dwell Seconds: {dwell_seconds}")
lines.append(f"Hardware Verified: {all(v.get('sdr_streaming_confirmed') for v in rf_health.values())}")
lines.append("")

for label, payload in snapshots.items():
    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []
    lora_signals = sum(
        1 for signal in signals
        if str(signal.get("protocol") or "").upper() in {"LORA", "LORA_PHY"}
        or str(signal.get("rf_protocol") or "").upper() in {"LORA", "LORA_PHY"}
    )
    chirp_hits = 0
    for signal in signals:
        meta = signal.get("metadata") if isinstance(signal.get("metadata"), dict) else {}
        if meta.get("rf_chirp_detected") or str(meta.get("rf_frame_structure") or "").lower() == "chirp" or str(meta.get("rf_modulation_hint") or "").lower() == "lora_like":
            chirp_hits += 1
    lines.append(f"{label}:")
    lines.append(f"  signals={len(signals)} lora_signals={lora_signals} chirp_hits={chirp_hits} devices={len(devices)} entities={len(entities)}")
    if signals:
        first = signals[0]
        lines.append(
            "  top_signal="
            f"{first.get('signal_id')} protocol={first.get('protocol')} "
            f"rf_protocol={first.get('rf_protocol')} frequency_mhz={first.get('frequency_mhz')} "
            f"lora_role_hint={first.get('lora_role_hint')} confidence={first.get('confidence')}"
        )
    else:
        lines.append("  top_signal=none")
    lines.append("")

lora_validation = validation.get("true_lora_validation") or {}
lines.append("Validation Summary:")
for key in [
    "signal_count",
    "device_count",
    "entity_count",
    "lora_signal_ratio",
    "lora_center_ratio",
    "chirp_evidence_ratio",
    "periodic_lora_ratio",
    "role_device_ratio",
    "typed_device_ratio",
    "matched_lab_profile_ratio",
    "meter_like_ratio",
    "mesh_like_ratio",
    "lorawan_like_ratio",
    "polluted_device_ratio",
    "correlation_purity_ratio",
    "duplicate_entity_ids",
    "consistency_score",
]:
    lines.append(f"  {key}={lora_validation.get(key)}")

identity_family_counts = lora_validation.get("identity_family_counts") or {}
if identity_family_counts:
    lines.append("  identity_family_counts=" + json.dumps(identity_family_counts, sort_keys=True))
bandplan_counts = lora_validation.get("bandplan_counts") or {}
if bandplan_counts:
    lines.append("  bandplan_counts=" + json.dumps(bandplan_counts, sort_keys=True))
cadence_counts = lora_validation.get("cadence_counts") or {}
if cadence_counts:
    lines.append("  cadence_counts=" + json.dumps(cadence_counts, sort_keys=True))
matched_profile_counts = lora_validation.get("matched_profile_counts") or {}
if matched_profile_counts:
    lines.append("  matched_profile_counts=" + json.dumps(matched_profile_counts, sort_keys=True))

Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  log "raw report: ${RAW_REPORT}"
  log "summary report: ${SUMMARY_REPORT}"
  log "trace log: ${TRACE_LOG}"
}

main "$@"
