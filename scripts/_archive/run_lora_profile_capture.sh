#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-2}"
LIMIT="${LIMIT:-25}"
LORA_REGION_PROFILE="${LORA_REGION_PROFILE:-eu868_lab}"
PROFILE_NAME="${PROFILE_NAME:?set PROFILE_NAME}"
VENDOR="${VENDOR:?set VENDOR}"
PRODUCT="${PRODUCT:?set PRODUCT}"
DEVICE_TYPE="${DEVICE_TYPE:?set DEVICE_TYPE}"
IDENTITY_FAMILY="${IDENTITY_FAMILY:-lorawan_endpoint}"
ROLE="${ROLE:-end_device}"
FILTER_FAMILY="${FILTER_FAMILY:-}"
NOTES="${NOTES:-}"
TAGS="${TAGS:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP_JSON="/tmp/lora_profile_${STAMP}.json"

log() {
  printf '[lora-profile] %s\n' "$*"
}

curl_json() {
  curl --max-time 15 -fsS "$1"
}

post_json() {
  curl --max-time 15 -fsS -X POST "$1" >/dev/null
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
    *)
      printf '%s\n' 867.10 867.30 867.50 867.70 867.90 868.10 868.30 868.50 869.525
      ;;
  esac
}

mapfile -t CHANNELS < <(channels_for_profile "$LORA_REGION_PROFILE")

first=1
for freq in "${CHANNELS[@]}"; do
  if [[ "$first" -eq 1 ]]; then
    log "start ${freq} MHz"
    post_json "${BASE_URL}/api/system/start?freq_mhz=${freq}"
    first=0
  else
    log "retune ${freq} MHz"
    post_json "${BASE_URL}/api/system/retune?freq_mhz=${freq}"
  fi
  sleep "$DWELL_SECONDS"
done

log "capture snapshot"
curl_json "${BASE_URL}/api/intel/band/lora?limit=${LIMIT}" > "$TMP_JSON"
post_json "${BASE_URL}/api/system/stop" || true

args=(
  --snapshot "$TMP_JSON"
  --profile-name "$PROFILE_NAME"
  --vendor "$VENDOR"
  --product "$PRODUCT"
  --device-type "$DEVICE_TYPE"
  --bandplan "${LORA_REGION_PROFILE%%_*}"
  --region "${LORA_REGION_PROFILE%%_*}"
  --identity-family "$IDENTITY_FAMILY"
  --role "$ROLE"
)

if [[ -n "$FILTER_FAMILY" ]]; then
  args+=(--filter-family "$FILTER_FAMILY")
fi
if [[ -n "$NOTES" ]]; then
  args+=(--notes "$NOTES")
fi
if [[ -n "$TAGS" ]]; then
  args+=(--tags "$TAGS")
fi

python3 "$ROOT_DIR/scripts/profile_lora_device.py" "${args[@]}"

log "profile capture complete"
