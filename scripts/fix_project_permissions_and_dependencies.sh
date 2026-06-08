#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_OPERATOR_USER="${TARGET_OPERATOR_USER:-${SUDO_USER:-${USER:-ghost}}}"
TARGET_OPERATOR_GROUP="${TARGET_OPERATOR_GROUP:-$(id -gn "$TARGET_OPERATOR_USER" 2>/dev/null || id -gn 2>/dev/null || printf 'ghost')}"
LOG_DIR="$ROOT_DIR/logs"
WIFI_LOG_DIR="$LOG_DIR/wifi_mk7"
BLE_LOG_DIR="$LOG_DIR/ble_nr5"
TMP_WIFI_DIR="/tmp/ghostrecon_wifi_mk7"
REPORTS_DIR="$ROOT_DIR/rf_reports"
IDENTITIES_DIR="$ROOT_DIR/identities"
CONFIG_DIR="$ROOT_DIR/config"
EVIDENCE_DIR="$ROOT_DIR/evidence"
WIFI_EVIDENCE_DIR="$EVIDENCE_DIR/wifi_hunt"
WIFI_SESSION_EVIDENCE_DIR="$WIFI_EVIDENCE_DIR/sessions"
AUDIT_EVIDENCE_DIR="$EVIDENCE_DIR/Audit"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
SCRIPTS_DIR="$ROOT_DIR/scripts"
FRONTEND_PUBLIC_DIR="$FRONTEND_DIR/public"
BACKEND_VENV_DIR="$BACKEND_DIR/.venv"
UDEV_RULE_PATH="/etc/udev/rules.d/99-ghostrecon-nrf52840.rules"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() {
  printf '[PASS] %s\n' "$1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

warn() {
  printf '[WARN] %s\n' "$1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

fail() {
  printf '[FAIL] %s\n' "$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    return 1
  fi
}

require_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    pass "dependency present: $1"
  else
    fail "dependency missing: $1"
  fi
}

ensure_dir() {
  local dir="$1"
  mkdir -p "$dir"
  chmod 775 "$dir" || true
  if [[ -w "$dir" ]]; then
    pass "directory writable: $dir"
  else
    fail "directory not writable: $dir"
  fi
}

check_file_mode() {
  local path="$1"
  local desired="$2"
  if [[ -e "$path" ]]; then
    chmod "$desired" "$path" || true
    pass "permission checked: $path"
  else
    warn "path missing: $path"
  fi
}

check_tree_writable() {
  local dir="$1"
  if [[ -d "$dir" && -w "$dir" ]]; then
    pass "tree writable: $dir"
  else
    fail "tree not writable: $dir"
  fi
}

check_json_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    warn "json file missing: $path"
    return
  fi
  if python3 -m json.tool "$path" >/dev/null 2>&1; then
    pass "json valid: $path"
  else
    fail "json invalid: $path"
  fi
}

check_python_import() {
  local python_bin="$1"
  local module="$2"
  if "$python_bin" -c "import ${module}" >/dev/null 2>&1; then
    pass "python module available: ${module}"
  else
    fail "python module missing: ${module}"
  fi
}

ensure_venv() {
  if [[ -x "$BACKEND_VENV_DIR/bin/python" ]]; then
    pass "backend virtualenv present: $BACKEND_VENV_DIR"
    return
  fi
  warn "backend virtualenv missing: $BACKEND_VENV_DIR"
}

repair_project_ownership() {
  if [[ ! -e "$ROOT_DIR" ]]; then
    fail "project root missing: $ROOT_DIR"
    return
  fi
  if as_root chown -R "${TARGET_OPERATOR_USER}:${TARGET_OPERATOR_GROUP}" "$ROOT_DIR" "$TMP_WIFI_DIR" >/dev/null 2>&1; then
    pass "project ownership repaired for ${TARGET_OPERATOR_USER}:${TARGET_OPERATOR_GROUP}"
  else
    warn "unable to repair project ownership automatically"
  fi
}

fix_dumpcap_caps() {
  local dumpcap_path
  local current_caps
  dumpcap_path="$(command -v dumpcap || true)"
  if [[ -z "$dumpcap_path" ]]; then
    fail "dumpcap not installed"
    return
  fi

  current_caps="$(getcap "$dumpcap_path" 2>/dev/null || true)"
  if [[ "$current_caps" == *cap_net_admin* && "$current_caps" == *cap_net_raw* ]]; then
    pass "dumpcap capabilities already set"
    return
  fi

  if as_root setcap cap_net_raw,cap_net_admin+eip "$dumpcap_path" >/dev/null 2>&1; then
    pass "dumpcap capabilities repaired"
  else
    fail "unable to set dumpcap capabilities"
  fi
}

check_dumpcap_caps() {
  local dumpcap_path
  local current_caps
  dumpcap_path="$(command -v dumpcap || true)"
  if [[ -z "$dumpcap_path" ]]; then
    fail "dumpcap not installed"
    return
  fi
  current_caps="$(getcap "$dumpcap_path" 2>/dev/null || true)"
  if [[ "$current_caps" == *cap_net_admin* && "$current_caps" == *cap_net_raw* ]]; then
    pass "dumpcap usable capabilities present"
  else
    warn "dumpcap capabilities not visible after repair attempt"
  fi
}

ensure_operator_group() {
  local group_name="$1"
  if ! getent group "$group_name" >/dev/null 2>&1; then
    warn "group missing on host: $group_name"
    return
  fi
  if id -nG "$TARGET_OPERATOR_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$group_name"; then
    pass "operator already in group: $group_name"
    return
  fi
  if as_root usermod -aG "$group_name" "$TARGET_OPERATOR_USER" >/dev/null 2>&1; then
    warn "added ${TARGET_OPERATOR_USER} to ${group_name}; log out and back in before using capture tools"
  else
    warn "unable to add ${TARGET_OPERATOR_USER} to ${group_name}"
  fi
}

fix_ble_nr5_groups() {
  for group_name in dialout plugdev wireshark netdev; do
    ensure_operator_group "$group_name"
  done
}

install_ble_nr5_udev_rule() {
  local tmp_rule
  tmp_rule="$(mktemp)"
  cat >"$tmp_rule" <<'EOF'
SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="522a", MODE:="0660", GROUP:="dialout", SYMLINK+="ghostrecon_nrf52840"
EOF
  if as_root install -m 644 "$tmp_rule" "$UDEV_RULE_PATH" >/dev/null 2>&1; then
    pass "installed Nordic nRF52840 udev rule"
    as_root udevadm control --reload-rules >/dev/null 2>&1 || true
    as_root udevadm trigger >/dev/null 2>&1 || true
  else
    warn "unable to install Nordic nRF52840 udev rule"
  fi
  rm -f "$tmp_rule"
}

check_ble_nr5_serial_access() {
  local lsusb_output tty_paths by_id_paths
  lsusb_output="$(lsusb 2>/dev/null || true)"
  if grep -Eiq '1915:522a|nordic|nrf' <<<"$lsusb_output"; then
    pass "Nordic USB device visible via lsusb"
  else
    warn "Nordic nRF52840 USB descriptor not visible via lsusb"
  fi

  by_id_paths="$(find /dev/serial/by-id -maxdepth 1 -type l 2>/dev/null | grep -Ei 'nordic|nrf|52840' || true)"
  if [[ -n "$by_id_paths" ]]; then
    pass "BLE NR5 serial path visible under /dev/serial/by-id"
  else
    warn "BLE NR5 serial symlink not visible under /dev/serial/by-id"
  fi

  tty_paths="$(find /dev -maxdepth 1 -type c -name 'ttyACM*' 2>/dev/null || true)"
  if [[ -n "$tty_paths" ]]; then
    pass "BLE NR5 ttyACM serial device detected"
  else
    warn "no ttyACM serial devices detected for BLE NR5"
  fi
}

main() {
  printf '== GhostRedRecon dependency and permission audit ==\n'

  for cmd in python3 npm dumpcap tshark mergecap iw ip curl ss setcap getcap jq lsusb udevadm; do
    require_cmd "$cmd"
  done

  repair_project_ownership
  ensure_dir "$LOG_DIR"
  ensure_dir "$WIFI_LOG_DIR"
  ensure_dir "$BLE_LOG_DIR"
  ensure_dir "$TMP_WIFI_DIR"
  ensure_dir "$REPORTS_DIR"
  ensure_dir "$IDENTITIES_DIR"
  ensure_dir "$EVIDENCE_DIR"
  ensure_dir "$WIFI_EVIDENCE_DIR"
  ensure_dir "$WIFI_SESSION_EVIDENCE_DIR"
  ensure_dir "$AUDIT_EVIDENCE_DIR"
  ensure_dir "$FRONTEND_PUBLIC_DIR"

  check_tree_writable "$ROOT_DIR"
  check_tree_writable "$CONFIG_DIR"
  check_tree_writable "$BACKEND_DIR"
  check_tree_writable "$FRONTEND_DIR"
  check_tree_writable "$SCRIPTS_DIR"
  check_tree_writable "$EVIDENCE_DIR"

  check_file_mode "$ROOT_DIR/scripts/start_backend_service.sh" 755
  check_file_mode "$ROOT_DIR/scripts/start.sh" 755
  check_file_mode "$ROOT_DIR/scripts/stop.sh" 755
  check_file_mode "$ROOT_DIR/scripts/fix_project_permissions_and_dependencies.sh" 755
  check_file_mode "$ROOT_DIR/scripts/install_kali_dependencies.sh" 755

  fix_dumpcap_caps
  check_dumpcap_caps
  fix_ble_nr5_groups
  install_ble_nr5_udev_rule
  check_ble_nr5_serial_access
  ensure_venv

  check_json_file "$ROOT_DIR/config/project.config.json"

  if [[ -x "$BACKEND_VENV_DIR/bin/python" ]]; then
    check_python_import "$BACKEND_VENV_DIR/bin/python" fastapi
    check_python_import "$BACKEND_VENV_DIR/bin/python" uvicorn
    check_python_import "$BACKEND_VENV_DIR/bin/python" requests
    check_python_import "$BACKEND_VENV_DIR/bin/python" psutil
    check_python_import "$BACKEND_VENV_DIR/bin/python" scapy
    check_python_import "$BACKEND_VENV_DIR/bin/python" serial
    check_python_import "$BACKEND_VENV_DIR/bin/python" aiofiles
  fi

  printf '\n== Summary ==\n'
  printf 'PASS: %d\n' "$PASS_COUNT"
  printf 'WARN: %d\n' "$WARN_COUNT"
  printf 'FAIL: %d\n' "$FAIL_COUNT"

  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
