#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-4}"
LORA_REGION_PROFILE="${LORA_REGION_PROFILE:-all_lab}"

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

if [[ -n "${CHANNELS_OVERRIDE:-}" ]]; then
  CHANNELS=(${CHANNELS_OVERRIDE})
else
  mapfile -t CHANNELS < <(channels_for_profile "$LORA_REGION_PROFILE")
fi

log() {
  printf '[lora-cycle] %s\n' "$*"
}

request_json() {
  curl -fsS "$1"
}

post_json() {
  curl -fsS -X POST "$1"
}

wait_backend() {
  for _ in $(seq 1 20); do
    if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  log "backend not reachable at ${BASE_URL}"
  return 1
}

main() {
  wait_backend

  log "starting LoRa channel cycle"

  local first=1
  for freq in "${CHANNELS[@]}"; do
    if [[ "$first" -eq 1 ]]; then
      log "start ${freq} MHz"
      post_json "${BASE_URL}/api/system/start?freq_mhz=${freq}" >/dev/null
      first=0
    else
      log "retune ${freq} MHz"
      post_json "${BASE_URL}/api/system/retune?freq_mhz=${freq}" >/dev/null
    fi

    sleep "$DWELL_SECONDS"

    log "snapshot ${freq} MHz"
    request_json "${BASE_URL}/api/intel/band/sub-ghz?limit=50"
    printf '\n'
  done

  log "LoRa channel cycle complete"
}

main "$@"
