#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8100}"
DWELL_SECONDS="${DWELL_SECONDS:-6}"
CHANNELS=("2402" "2426" "2480")

log() {
  printf '[ble-cycle] %s\n' "$*"
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

  log "starting BLE advertising-channel cycle"

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
    request_json "${BASE_URL}/api/intel/band/BLE?limit=50"
    printf '\n'
  done

  log "BLE advertising-channel cycle complete"
}

main "$@"
