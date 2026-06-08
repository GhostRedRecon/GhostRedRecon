#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_SCRIPT="$ROOT_DIR/scripts/install_kali_dependencies.sh"
FIX_SCRIPT="$ROOT_DIR/scripts/fix_project_permissions_and_dependencies.sh"
START_SCRIPT="$ROOT_DIR/scripts/start.sh"

log() {
  printf '[bootstrap-kali] %s\n' "$*"
}

fail() {
  printf '[bootstrap-kali] ERROR: %s\n' "$*" >&2
  exit 1
}

run_step() {
  local label="$1"
  shift
  log "Running: ${label}"
  "$@"
}

need_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "required file missing: $path"
}

main() {
  need_file "$INSTALL_SCRIPT"
  need_file "$FIX_SCRIPT"
  need_file "$START_SCRIPT"

  chmod 755 "$INSTALL_SCRIPT" "$FIX_SCRIPT" "$START_SCRIPT" "$ROOT_DIR/scripts/bootstrap_kali_wifi_hunt.sh" || true

  log "GhostRedRecon Kali WiFi Hunt bootstrap starting"
  log "Project root: $ROOT_DIR"

  run_step "Install Kali dependencies" bash "$INSTALL_SCRIPT"
  run_step "Fix project permissions and runtime dependencies" bash "$FIX_SCRIPT"

  cat <<EOF

[bootstrap-kali] Ready for launch.
[bootstrap-kali] Next steps:
[bootstrap-kali]   1. Connect the MK7AC-compatible Wi-Fi adapter.
[bootstrap-kali]   2. Start the stack with: bash scripts/start.sh
[bootstrap-kali]   3. Open WiFi Hunt and run a fresh session.
[bootstrap-kali]   4. Verify evidence output under:
[bootstrap-kali]      - evidence/wifi_hunt/sessions/
[bootstrap-kali]      - evidence/Audit/

[bootstrap-kali] Optional:
[bootstrap-kali]   RUN_START_CHECK=1 bash scripts/install_kali_dependencies.sh
[bootstrap-kali] This performs an extra startup smoke test during install.

EOF
}

main "$@"
