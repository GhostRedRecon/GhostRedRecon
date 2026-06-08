#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_VENV="$ROOT_DIR/backend/.venv"
FRONTEND_DIR="$ROOT_DIR/frontend"
START_SCRIPT="$ROOT_DIR/scripts/start.sh"
START_BACKEND_SCRIPT="$ROOT_DIR/scripts/start_backend_service.sh"
PROJECT_CONFIG="$ROOT_DIR/config/project.config.json"
TARGET_OPERATOR_USER="${TARGET_OPERATOR_USER:-${SUDO_USER:-${USER:-}}}"
SUDOERS_FILE="/etc/sudoers.d/ghostredrecon-monitor-mode"

APT_PACKAGES=(
  build-essential
  python3
  python3-dev
  python3-venv
  python3-pip
  python3-gi
  gir1.2-glib-2.0
  curl
  git
  ca-certificates
  dbus
  nodejs
  npm
  jq
  usbutils
  pciutils
  iproute2
  iputils-ping
  net-tools
  procps
  psmisc
  wireless-tools
  iw
  ethtool
  rfkill
  aircrack-ng
  tshark
  wireshark-common
  tcpdump
  tcpflow
  foremost
  exiftool
  binwalk
  bettercap
  kismet
  nmap
  ffmpeg
  arp-scan
  avahi-utils
  v4l-utils
  rtl-433
  hackrf
  bluez
  bluez-tools
  bluetooth
  ubertooth
  libcap2-bin
)

PIP_PACKAGES=(
  fastapi
  "uvicorn[standard]"
  numpy
  requests
  psutil
  scapy
  aiofiles
  python-multipart
  pyserial
  pydantic
  pyyaml
)

RUNTIME_DIRS=(
  "$ROOT_DIR/logs"
  "$ROOT_DIR/logs/wifi_mk7"
  "$ROOT_DIR/logs/ble_nr5"
  "$ROOT_DIR/rf_reports"
  "$ROOT_DIR/identities"
  "$ROOT_DIR/evidence"
  "$ROOT_DIR/evidence/Audit"
  "$ROOT_DIR/evidence/wifi_hunt"
  "$ROOT_DIR/evidence/wifi_hunt/sessions"
  "$ROOT_DIR/frontend/public"
  "/tmp/ghostrecon_wifi_mk7"
)

REQUIRED_COMMANDS=(
  python3
  node
  npm
  curl
  iw
  ip
  rfkill
  airodump-ng
  aircrack-ng
  tshark
  dumpcap
  mergecap
  tcpdump
  nmap
  ffmpeg
  bettercap
  kismet
  kismetdb_dump_devices
  setcap
  getcap
  bluetoothctl
  btmon
  btattach
  ss
)

log() {
  printf '[ghostredrecon-install] %s\n' "$*"
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

require_kali_or_linux() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log "Detected OS: ${PRETTY_NAME:-unknown Linux}"
    if [[ "${ID:-}" != "kali" ]]; then
      log "Warning: this installer is tuned for Kali Linux. Continuing on ${ID:-unknown}."
    fi
  fi
}

require_operator_user() {
  if [[ -z "$TARGET_OPERATOR_USER" ]] || ! id "$TARGET_OPERATOR_USER" >/dev/null 2>&1; then
    log "Unable to identify operator user. Re-run with TARGET_OPERATOR_USER=<username>."
    exit 1
  fi
  TARGET_OPERATOR_GROUP="$(id -gn "$TARGET_OPERATOR_USER")"
  log "Operator user: $TARGET_OPERATOR_USER:$TARGET_OPERATOR_GROUP"
}

install_apt_packages() {
  log "Installing Kali/Linux system dependencies..."
  as_root apt-get update
  DEBIAN_FRONTEND=noninteractive as_root apt-get install -y "${APT_PACKAGES[@]}"
}

ensure_runtime_dirs() {
  log "Creating runtime directories..."
  for dir in "${RUNTIME_DIRS[@]}"; do
    as_root mkdir -p "$dir"
    as_root chown -R "$TARGET_OPERATOR_USER:$TARGET_OPERATOR_GROUP" "$dir"
    as_root chmod 775 "$dir"
  done
}

ensure_backend_venv() {
  log "Preparing backend Python virtualenv at $BACKEND_VENV..."
  if [[ ! -d "$BACKEND_VENV" ]]; then
    python3 -m venv "$BACKEND_VENV"
  fi
  "$BACKEND_VENV/bin/python" -m pip install --upgrade pip wheel setuptools
  "$BACKEND_VENV/bin/python" -m pip install "${PIP_PACKAGES[@]}"
  as_root chown -R "$TARGET_OPERATOR_USER:$TARGET_OPERATOR_GROUP" "$BACKEND_VENV"
}

ensure_frontend_deps() {
  log "Installing frontend React/Vite dependencies..."
  if [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
    log "Missing frontend/package.json"
    exit 1
  fi

  if [[ -f "$FRONTEND_DIR/package-lock.json" ]]; then
    npm --prefix "$FRONTEND_DIR" ci
  else
    npm --prefix "$FRONTEND_DIR" install
  fi

  as_root chown -R "$TARGET_OPERATOR_USER:$TARGET_OPERATOR_GROUP" "$FRONTEND_DIR/node_modules" "$FRONTEND_DIR/package-lock.json" 2>/dev/null || true
}

repair_script_permissions() {
  log "Ensuring project scripts are executable..."
  find "$ROOT_DIR/scripts" -type f -name '*.sh' -exec chmod 755 {} +
}

configure_dumpcap() {
  local dumpcap_path
  dumpcap_path="$(command -v dumpcap || true)"
  if [[ -z "$dumpcap_path" ]]; then
    log "Warning: dumpcap not found after install."
    return 0
  fi
  as_root setcap cap_net_raw,cap_net_admin+eip "$dumpcap_path" || true
}

configure_operator_groups() {
  log "Adding operator to capture/hardware groups when available..."
  for group_name in wireshark netdev plugdev dialout bluetooth; do
    if getent group "$group_name" >/dev/null 2>&1; then
      as_root usermod -aG "$group_name" "$TARGET_OPERATOR_USER"
    fi
  done
}

configure_bluez_host() {
  log "Configuring BlueZ host-side BLE validation path..."
  if command -v systemctl >/dev/null 2>&1; then
    as_root systemctl enable --now bluetooth || log "Warning: unable to enable/start bluetooth.service"
  fi
  if command -v rfkill >/dev/null 2>&1; then
    as_root rfkill unblock bluetooth || true
  fi
  if command -v bluetoothctl >/dev/null 2>&1; then
    bluetoothctl power on >/dev/null 2>&1 || log "Warning: no powered Bluetooth adapter available yet"
  fi
}

install_monitor_mode_sudoers() {
  log "Installing limited monitor-mode sudoers policy..."
  local tmp_file
  tmp_file="$(mktemp)"
  cat >"$tmp_file" <<EOF
$TARGET_OPERATOR_USER ALL=(root) NOPASSWD: /usr/sbin/ip, /usr/bin/ip, /usr/sbin/iw, /usr/bin/iw, /usr/sbin/ifconfig, /usr/bin/ifconfig, /usr/sbin/iwconfig, /usr/bin/iwconfig, /usr/sbin/rfkill, /usr/bin/rfkill, /usr/sbin/airmon-ng, /usr/bin/airmon-ng, /usr/bin/killall, /usr/bin/pkill, /usr/bin/systemctl, /usr/sbin/setcap, /usr/bin/setcap
EOF
  as_root install -m 440 "$tmp_file" "$SUDOERS_FILE"
  rm -f "$tmp_file"
}

check_required_commands() {
  local missing=0
  log "Checking required operator commands..."
  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      log "found: $cmd"
    else
      log "missing: $cmd"
      missing=1
    fi
  done
  return "$missing"
}

check_node_and_react() {
  log "Checking Node/npm and React installation..."
  node --version
  npm --version
  npm --prefix "$FRONTEND_DIR" ls react react-dom vite @vitejs/plugin-react --depth=0 >/dev/null
}

check_backend_imports() {
  log "Checking backend Python imports and compilation..."
  "$BACKEND_VENV/bin/python" -m compileall "$ROOT_DIR/backend" >/dev/null
  (cd "$ROOT_DIR" && "$BACKEND_VENV/bin/python" -m py_compile backend/main.py)
}

check_frontend_build() {
  log "Checking frontend production build..."
  npm --prefix "$FRONTEND_DIR" run build
}

check_project_config() {
  if [[ -f "$PROJECT_CONFIG" ]]; then
    log "Checking project config JSON..."
    python3 -m json.tool "$PROJECT_CONFIG" >/dev/null
  else
    log "Warning: project config missing: $PROJECT_CONFIG"
  fi
}

check_hardware_state() {
  log "Checking connected WiFi/USB hardware state..."
  log "Recommended first-run setup: connect the nRF52840 BLE dongle and MK7AC WiFi adapter before running this installer."
  iw dev || true
  lsusb || true
  if ip link show wlan1 >/dev/null 2>&1; then
    log "wlan1 detected."
  else
    log "wlan1 not detected right now. Connect the MK7AC before WiFi Hunt operation, or use a monitor-mode adapter and start with WIFI_MK7_PREFERRED_INTERFACE=<iface> ./scripts/start.sh."
  fi
  log "If the GUI does not show connected adapters after installation, run ./scripts/stop.sh and then ./scripts/start.sh."
}

main() {
  require_kali_or_linux
  require_operator_user
  install_apt_packages
  ensure_runtime_dirs
  repair_script_permissions
  ensure_backend_venv
  ensure_frontend_deps
  configure_dumpcap
  configure_operator_groups
  configure_bluez_host
  install_monitor_mode_sudoers
  check_required_commands
  check_node_and_react
  check_project_config
  check_backend_imports
  check_frontend_build
  check_hardware_state
  log "Installation and verification complete."
  log "If group membership changed for $TARGET_OPERATOR_USER, log out and back in before using monitor-mode workflows."
}

main "$@"
