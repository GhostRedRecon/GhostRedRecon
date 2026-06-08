#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${1:-http://127.0.0.1:8100}"

LORA_REGION_PROFILE="${LORA_REGION_PROFILE:-eu868_lab}" \
bash "$ROOT_DIR/scripts/run_lora_profile_capture.sh" "$BASE_URL"
