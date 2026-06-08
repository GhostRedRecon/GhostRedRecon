#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# =============================================================================
# GhostRedRecon NR9 IoT Forensic Audit
# Authorized security + forensic audit for IoT cameras, routers, hubs, doorbells.
#
# Flow:
# A Threat Modeling & Preparation
# B Network Discovery & Scanning
# C Traffic Capture & Logging
# D Protocol & Service Analysis
# E Firmware Acquisition & Analysis
# F Hardware Debug Access Documentation
# G Storage Imaging / Storage Evidence
# H Data Carving & Decoding
# I Reporting & Chain-of-Custody
#
# Does NOT brute-force, exploit, bypass authentication, or break encryption.
# =============================================================================

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "ERROR: run with bash: sudo -E bash ghost_nr9_iot_forensic_audit.sh"
  exit 1
fi

VERSION="NR9-IOT-FORENSIC-AUDIT-1.0"

TARGET_IP="${TARGET_IP:-192.168.0.29}"
LAN_IFACE="${LAN_IFACE:-wlan0}"
CONFIRM_AUTH="${CONFIRM_AUTH:-YES}"

OUT_BASE="${OUT_BASE:-./evidence}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-300}"
MAX_BYTES="${MAX_BYTES:-10485760}"

TCP_PORTS="${TCP_PORTS:-1-65535}"
UDP_PORTS="${UDP_PORTS:-53,67,68,123,137,161,1900,5353,5683,54321}"

HTTP_PORTS="${HTTP_PORTS:-80 81 82 83 88 443 554 591 8000 8001 8008 8080 8081 8088 8090 8443 8554 8888 9000 9090 10000}"
RTSP_PORTS="${RTSP_PORTS:-554 8554 10554}"

FIRMWARE_FILE="${FIRMWARE_FILE:-}"
DISK_IMAGE="${DISK_IMAGE:-}"
EXTRA_INPUT_DIR="${EXTRA_INPUT_DIR:-}"
MOUNT_SCAN="${MOUNT_SCAN:-NO}"

if [[ "$CONFIRM_AUTH" != "YES" ]]; then
  echo "ERROR: Set CONFIRM_AUTH=YES for owned/authorized testing."
  echo "Example:"
  echo "sudo -E CONFIRM_AUTH=YES TARGET_IP=192.168.0.29 LAN_IFACE=wlan0 bash $0"
  exit 1
fi

SCRIPT_NAME="$(basename "$0" .sh)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="$OUT_BASE/${SCRIPT_NAME}_${RUN_ID}"

mkdir -p \
"$ROOT/00_chain_of_custody" \
"$ROOT/01_threat_model" \
"$ROOT/02_network_discovery" \
"$ROOT/03_traffic_capture" \
"$ROOT/04_protocol_service_analysis" \
"$ROOT/05_firmware_analysis" \
"$ROOT/06_hardware_debug_access" \
"$ROOT/07_storage_imaging" \
"$ROOT/08_carving_decoding" \
"$ROOT/09_reports" \
"$ROOT/logs"

CHAIN="$ROOT/00_chain_of_custody"
THREAT="$ROOT/01_threat_model"
NET="$ROOT/02_network_discovery"
CAP="$ROOT/03_traffic_capture"
PROTO="$ROOT/04_protocol_service_analysis"
FW="$ROOT/05_firmware_analysis"
HW="$ROOT/06_hardware_debug_access"
STOR="$ROOT/07_storage_imaging"
DECODE="$ROOT/08_carving_decoding"
REP="$ROOT/09_reports"
LOGS="$ROOT/logs"

TESTS="$REP/tests.tsv"
FINDINGS="$REP/findings.tsv"
ARTIFACTS="$REP/artifacts.tsv"
HASHES="$REP/sha256_manifest.txt"
REPORT="$REP/report.md"
JSON="$REP/report.json"

: > "$TESTS"
: > "$FINDINGS"
: > "$ARTIFACTS"
: > "$HASHES"

ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
have(){ command -v "$1" >/dev/null 2>&1; }
safe(){ echo "$1" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-180; }
log(){ echo "[$(ts)] $*" | tee -a "$LOGS/run.log"; }

artifact(){
  local f="$1"
  local kind="${2:-artifact}"
  local source="${3:-unknown}"

  [[ -f "$f" ]] || return 0

  local h s m
  h="$(sha256sum "$f" | awk '{print $1}')"
  s="$(wc -c < "$f" 2>/dev/null || echo 0)"
  m="$(file -b "$f" 2>/dev/null || echo unknown)"

  echo "$h  $f" >> "$HASHES"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(ts)" "$(basename "$f")" "$kind" "$s" "$h" "$m" "$f" "$source" >> "$ARTIFACTS"
}

testlog(){
  local stage="$1"
  local id="$2"
  local name="$3"
  local status="$4"
  local reason="$5"
  local evidence="${6:-}"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(ts)" "$stage" "$id" "$name" "$status" "$reason" "$evidence" >> "$TESTS"

  log "[$stage][$id] $status - $name - $reason"
}

finding(){
  local sev="$1"
  local cat="$2"
  local item="$3"
  local evidence="$4"

  printf '%s\t%s\t%s\t%s\t%s\n' "$(ts)" "$sev" "$cat" "$item" "$evidence" >> "$FINDINGS"
}

run_cmd(){
  local stage="$1"
  local id="$2"
  local name="$3"
  local outfile="$4"
  shift 4

  testlog "$stage" "$id" "$name" "RUN" "$*" "$outfile"

  set +e
  "$@" > "$outfile" 2>&1
  local rc=$?
  set -e

  artifact "$outfile" "command_output" "$name"

  if [[ $rc -eq 0 ]]; then
    testlog "$stage" "$id" "$name" "PASS" "Command completed" "$outfile"
  else
    testlog "$stage" "$id" "$name" "WARN" "Command exited rc=$rc" "$outfile"
  fi
}

REQUIRED=(bash nmap curl nc awk sed grep sha256sum file strings python3 ping xxd ip)
missing=()
for t in "${REQUIRED[@]}"; do
  have "$t" || missing+=("$t")
done

if (( ${#missing[@]} > 0 )); then
  echo "Missing required tools: ${missing[*]}"
  exit 1
fi

log "GhostRedRecon $VERSION"
log "Target: $TARGET_IP"
log "Output: $ROOT"

# =============================================================================
# A. THREAT MODELING & PREPARATION
# =============================================================================

{
  echo "tool=$VERSION"
  echo "script=$SCRIPT_NAME"
  echo "target_ip=$TARGET_IP"
  echo "interface=$LAN_IFACE"
  echo "run_id=$RUN_ID"
  echo "operator=$(whoami)"
  echo "host=$(hostname)"
  echo "kernel=$(uname -a)"
  echo "start_utc=$(ts)"
  echo "scope=authorized IoT forensic/security audit"
  echo "limits=no brute-force, no exploit, no auth bypass, no encryption breaking"
} > "$CHAIN/case_metadata.txt"

artifact "$CHAIN/case_metadata.txt" "case_metadata" "system"
testlog "A" "NR9-A001" "Case metadata" "PASS" "Chain-of-custody metadata created" "$CHAIN/case_metadata.txt"

cat > "$THREAT/threat_model.md" <<EOF
# Threat Model

Target: $TARGET_IP

Device classes covered:
- IP/Wi-Fi camera
- Doorbell camera
- Router / hub
- Generic IoT sensor
- Storage-backed device with SD/eMMC/USB/SSD

Audit questions:
- What ports are open?
- What services/protocols are exposed?
- Is the device streaming?
- Is it a video device, sensor, router, or hub?
- What cloud endpoints are contacted?
- Is traffic encrypted?
- Are files, configs, images, recordings, databases, or logs exposed?
- Can storage be accessed?
- Is firmware available or analyzable?
- Are chipset/firmware indicators present?
- What evidence was collected and hashed?

Evidence confidence:
- HIGH: direct file/storage/firmware/stream/object evidence
- MEDIUM: packet capture, service fingerprint, protocol behavior
- LOW: inferred OS/chip hints from banners/strings
EOF

artifact "$THREAT/threat_model.md" "threat_model" "operator"
testlog "A" "NR9-A002" "Threat model" "PASS" "Threat model created" "$THREAT/threat_model.md"

# =============================================================================
# B. NETWORK DISCOVERY & SCANNING
# =============================================================================

run_cmd "B" "NR9-B001" "Reachability ping" "$NET/ping.txt" ping -c 3 -W 2 "$TARGET_IP"
run_cmd "B" "NR9-B002" "ARP neighbor" "$NET/arp_neighbor.txt" ip neigh show "$TARGET_IP"

if have arp-scan; then
  run_cmd "B" "NR9-B003" "ARP local network scan" "$NET/arp_scan_localnet.txt" arp-scan --localnet
else
  testlog "B" "NR9-B003" "ARP local network scan" "SKIP" "arp-scan not installed" "-"
fi

run_cmd "B" "NR9-B010" "TCP full scan" "$NET/nmap_tcp_full.txt" nmap -Pn -sT -p "$TCP_PORTS" --reason "$TARGET_IP"
grep -E '^[0-9]+/tcp[[:space:]]+open' "$NET/nmap_tcp_full.txt" > "$NET/open_tcp.txt" || true
artifact "$NET/open_tcp.txt" "open_tcp_index" "nmap"

run_cmd "B" "NR9-B011" "UDP selected scan" "$NET/nmap_udp_selected.txt" nmap -Pn -sU -p "$UDP_PORTS" --reason "$TARGET_IP"
grep -E '^[0-9]+/udp[[:space:]]+(open|open\|filtered)' "$NET/nmap_udp_selected.txt" > "$NET/open_udp.txt" || true
artifact "$NET/open_udp.txt" "open_udp_index" "nmap"

run_cmd "B" "NR9-B012" "Service version scan" "$NET/nmap_service_versions.txt" nmap -Pn -sV --version-all "$TARGET_IP"
run_cmd "B" "NR9-B013" "OS fingerprint attempt" "$NET/nmap_os_guess.txt" nmap -Pn -O --osscan-guess "$TARGET_IP"

if have nbtscan; then
  run_cmd "B" "NR9-B014" "NetBIOS scan" "$NET/nbtscan.txt" nbtscan "$TARGET_IP"
else
  testlog "B" "NR9-B014" "NetBIOS scan" "SKIP" "nbtscan not installed" "-"
fi

TCP_OPEN="$(wc -l < "$NET/open_tcp.txt" | tr -d ' ')"
UDP_OPEN="$(wc -l < "$NET/open_udp.txt" | tr -d ' ')"

[[ "$TCP_OPEN" -gt 0 ]] && finding "MEDIUM" "Open TCP ports" "$TCP_OPEN open TCP ports" "$NET/open_tcp.txt"
[[ "$UDP_OPEN" -gt 0 ]] && finding "LOW" "UDP surface" "$UDP_OPEN open/open-filtered UDP ports" "$NET/open_udp.txt"

# =============================================================================
# C. TRAFFIC CAPTURE & LOGGING
# =============================================================================

PCAP="$CAP/behavior_capture.pcap"

if have tcpdump; then
  testlog "C" "NR9-C001" "Behavior PCAP capture" "RUN" "Capture $CAPTURE_SECONDS seconds; use mobile app/device during this window" "$PCAP"
  timeout "$CAPTURE_SECONDS" tcpdump -i "$LAN_IFACE" host "$TARGET_IP" -s0 -w "$PCAP" > "$LOGS/tcpdump_stdout.log" 2>"$LOGS/tcpdump_stderr.log" || true

  if [[ -s "$PCAP" ]]; then
    artifact "$PCAP" "pcap" "tcpdump"
    testlog "C" "NR9-C001" "Behavior PCAP capture" "PASS" "PCAP captured" "$PCAP"
  else
    testlog "C" "NR9-C001" "Behavior PCAP capture" "WARN" "No packets captured" "$PCAP"
  fi
else
  testlog "C" "NR9-C001" "Behavior PCAP capture" "SKIP" "tcpdump not installed" "-"
fi

# =============================================================================
# D. PROTOCOL & SERVICE ANALYSIS
# =============================================================================

if have tshark && [[ -s "$PCAP" ]]; then
  run_cmd "D" "NR9-D001" "Protocol hierarchy" "$PROTO/protocol_hierarchy.txt" tshark -r "$PCAP" -q -z io,phs
  run_cmd "D" "NR9-D002" "Conversation map" "$PROTO/conversations.txt" tshark -r "$PCAP" -q -z conv,tcp -z conv,udp
  run_cmd "D" "NR9-D003" "Flow index" "$PROTO/flow_index.tsv" tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP" -T fields -e frame.time -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info

  tshark -r "$PCAP" -Y "dns" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.a -e dns.aaaa > "$PROTO/dns_index.tsv" 2>/dev/null || true
  artifact "$PROTO/dns_index.tsv" "dns_index" "tshark"

  tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name > "$PROTO/tls_sni.tsv" 2>/dev/null || true
  artifact "$PROTO/tls_sni.tsv" "tls_sni" "tshark"

  tshark -r "$PCAP" -Y "tls || ssl || quic || tcp.port==443 || udp.port==443" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info > "$PROTO/encryption_indicators.tsv" 2>/dev/null || true
  artifact "$PROTO/encryption_indicators.tsv" "encryption_index" "tshark"

  tshark -r "$PCAP" -Y "http || ftp || telnet || data-text-lines" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info > "$PROTO/plaintext_indicators.tsv" 2>/dev/null || true
  artifact "$PROTO/plaintext_indicators.tsv" "plaintext_index" "tshark"

  mkdir -p "$PROTO/objects/http" "$PROTO/objects/smb" "$PROTO/objects/tftp" "$PROTO/objects/imf"
  tshark -Q -r "$PCAP" --export-objects "http,$PROTO/objects/http" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "smb,$PROTO/objects/smb" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "tftp,$PROTO/objects/tftp" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "imf,$PROTO/objects/imf" 2>/dev/null || true

  find "$PROTO/objects" -type f -print0 | while IFS= read -r -d '' f; do
    artifact "$f" "pcap_exported_object" "tshark"
  done

  [[ -s "$PROTO/encryption_indicators.tsv" ]] && finding "INFO" "Encrypted transport observed" "TLS/QUIC/443 indicators found" "$PROTO/encryption_indicators.tsv"
  [[ -s "$PROTO/plaintext_indicators.tsv" ]] && finding "HIGH" "Plaintext traffic indicator" "HTTP/FTP/Telnet/text-like traffic found" "$PROTO/plaintext_indicators.tsv"
else
  testlog "D" "NR9-D001" "Protocol analysis" "SKIP" "tshark missing or no PCAP" "-"
fi

# Camera / RTSP / ONVIF
mkdir -p "$PROTO/camera"
: > "$PROTO/camera/rtsp_tests.tsv"

RTSP_PATHS=(
"/" "/live" "/live.sdp" "/stream" "/stream1" "/h264" "/video" "/videoMain"
"/cam/realmonitor?channel=1&subtype=0" "/onvif1" "/11" "/0" "/ch0_0.h264"
)

if have ffprobe; then
  for port in $RTSP_PORTS; do
    for path in "${RTSP_PATHS[@]}"; do
      url="rtsp://$TARGET_IP:$port$path"
      out="$PROTO/camera/rtsp_$(safe "$url").txt"
      timeout 8 ffprobe -v error -show_format -show_streams "$url" > "$out" 2>&1 || true
      artifact "$out" "rtsp_probe" "$url"

      if grep -qiE 'codec_type=video|codec_name|width=|height=' "$out"; then
        printf 'FOUND\t%s\t%s\n' "$url" "$out" >> "$PROTO/camera/rtsp_tests.tsv"
        finding "HIGH" "Camera stream exposed" "$url" "$out"

        if have ffmpeg; then
          snap="$PROTO/camera/rtsp_snapshot_$(safe "$url").jpg"
          timeout 10 ffmpeg -y -rtsp_transport tcp -i "$url" -frames:v 1 "$snap" > "$PROTO/camera/ffmpeg_$(safe "$url").log" 2>&1 || true
          artifact "$snap" "rtsp_snapshot" "$url"
        fi
      else
        printf 'NO_STREAM\t%s\t%s\n' "$url" "$out" >> "$PROTO/camera/rtsp_tests.tsv"
      fi
    done
  done

  artifact "$PROTO/camera/rtsp_tests.tsv" "rtsp_index" "ffprobe"
else
  testlog "D" "NR9-D010" "RTSP detection" "SKIP" "ffprobe not installed" "-"
fi

: > "$PROTO/camera/onvif_inventory.tsv"
ONVIF_PATHS=("/onvif/device_service" "/onvif/Device" "/onvif" "/onvif/device")

for port in 80 8000 8080 8899 8999; do
  for path in "${ONVIF_PATHS[@]}"; do
    url="http://$TARGET_IP:$port$path"
    out="$PROTO/camera/onvif_$(safe "$url").txt"
    curl -sS -m 5 -i "$url" > "$out" 2>&1 || true
    artifact "$out" "onvif_probe" "$url"

    if grep -qiE 'onvif|tds:|SOAP|GetDeviceInformation|device_service' "$out"; then
      printf 'FOUND\t%s\t%s\n' "$url" "$out" >> "$PROTO/camera/onvif_inventory.tsv"
      finding "MEDIUM" "ONVIF indicator" "$url" "$out"
    fi
  done
done

artifact "$PROTO/camera/onvif_inventory.tsv" "onvif_index" "curl"

# HTTP/storage endpoint exposure
mkdir -p "$PROTO/http_probe"
cat > "$PROTO/http_probe/paths.txt" <<'EOF'
/
/index.html
/login
/login.html
/admin
/admin/
/web
/web/
/www/
/cgi-bin/
/status
/system
/info
/version
/device
/device_info
/api
/api/
/api/status
/api/info
/api/v1/status
/check_update
/update
/firmware
/firmware.bin
/firmware.img
/firmware.tar
/firmware.tar.gz
/download
/download/
/download/firmware.bin
/backup
/backup/
/backups/
/data
/data/
/logs/
/log/
/tmp/
/upload/
/uploads/
/sdcard/
/sdcard/DCIM/
/mnt/
/mnt/sdcard/
/storage/
/storage/sdcard/
/media/
/usb/
/record/
/records/
/recordings/
/snapshots/
/snapshot.jpg
/image.jpg
/current.jpg
/photo.jpg
/video
/video/
/stream
/config
/config/
/config.json
/config.yaml
/config.yml
/settings.json
/settings.conf
/webconfig.cfg
/device.conf
/default.prop
/build.prop
/etc/version
/etc/hostname
/etc/passwd
/etc/shadow
/etc/config/network
/etc/config/wireless
/proc/version
/proc/cpuinfo
/proc/meminfo
/proc/mounts
/var/log/messages
/var/log/syslog
/db/
/database/
/sqlite.db
/data.db
/config.db
/users.db
/camera.db
/robots.txt
/sitemap.xml
/.env
/.git/config
EOF

: > "$PROTO/http_probe/http_inventory.tsv"

fetch_url(){
  local url="$1"
  local name h b m code size ctype

  name="$(safe "$url")"
  h="$PROTO/http_probe/${name}.headers"
  b="$PROTO/http_probe/${name}.body"
  m="$PROTO/http_probe/${name}.meta"

  code="$(curl -k -sS -L --max-time 7 --connect-timeout 4 --range "0-$MAX_BYTES" -D "$h" -o "$b" -w "%{http_code}" "$url" 2>/dev/null || echo "000")"
  size="$(wc -c < "$b" 2>/dev/null || echo 0)"
  ctype="$(grep -i '^content-type:' "$h" 2>/dev/null | head -n1 | tr -d '\r' || true)"

  if [[ -f "$h" || -f "$b" ]]; then
    printf 'url=%s\ncode=%s\nbytes=%s\ncontent_type=%s\ntime=%s\n' "$url" "$code" "$size" "$ctype" "$(ts)" > "$m"
    artifact "$h" "http_headers" "$url"
    artifact "$b" "http_body" "$url"
    artifact "$m" "http_meta" "$url"
    printf '%s\t%s\t%s\t%s\t%s\n' "$code" "$size" "$ctype" "$url" "$b" >> "$PROTO/http_probe/http_inventory.tsv"
  fi
}

while read -r path; do
  [[ -z "$path" ]] && continue
  for port in $HTTP_PORTS; do
    fetch_url "http://$TARGET_IP:$port$path"
    if [[ "$port" == "443" || "$port" == "8443" ]]; then
      fetch_url "https://$TARGET_IP:$port$path"
    fi
  done
done < "$PROTO/http_probe/paths.txt"

artifact "$PROTO/http_probe/http_inventory.tsv" "http_inventory" "curl"

HTTP_OK="$(awk -F'\t' '$1=="200" || $1=="206"{c++} END{print c+0}' "$PROTO/http_probe/http_inventory.tsv")"
[[ "$HTTP_OK" -gt 0 ]] && finding "HIGH" "HTTP exposed objects" "$HTTP_OK HTTP objects accessible" "$PROTO/http_probe/http_inventory.tsv"

# =============================================================================
# E. FIRMWARE ACQUISITION & ANALYSIS
# =============================================================================

if [[ -n "$FIRMWARE_FILE" && -f "$FIRMWARE_FILE" ]]; then
  cp "$FIRMWARE_FILE" "$FW/input_firmware.bin"
  artifact "$FW/input_firmware.bin" "firmware_input" "$FIRMWARE_FILE"

  strings "$FW/input_firmware.bin" > "$FW/firmware_strings.txt" || true
  artifact "$FW/firmware_strings.txt" "firmware_strings" "strings"

  if have binwalk; then
    binwalk "$FW/input_firmware.bin" > "$FW/binwalk_scan.txt" 2>&1 || true
    artifact "$FW/binwalk_scan.txt" "binwalk_scan" "firmware"

    mkdir -p "$FW/binwalk_extract"
    binwalk -eM --directory "$FW/binwalk_extract" "$FW/input_firmware.bin" > "$FW/binwalk_extract.log" 2>&1 || true
    artifact "$FW/binwalk_extract.log" "binwalk_extract_log" "firmware"

    find "$FW/binwalk_extract" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
      artifact "$f" "firmware_extracted_file" "binwalk"
    done
  else
    testlog "E" "NR9-E002" "Binwalk firmware analysis" "SKIP" "binwalk not installed" "-"
  fi

  grep -RInaE 'password|passwd|token|secret|api[_-]?key|credential|ssid|psk|BEGIN RSA|BEGIN OPENSSH|PRIVATE KEY|root:' "$FW" > "$FW/firmware_secret_hits.txt" 2>/dev/null || true
  artifact "$FW/firmware_secret_hits.txt" "firmware_secret_hits" "grep"

  grep -RInaE 'hi351|hisilicon|ingenic|t31|t40|ambarella|novatek|realtek|rtl|mediatek|busybox|openwrt|linux version|u-boot|squashfs|mips|armv7|aarch64' "$FW" > "$FW/firmware_chip_indicators.txt" 2>/dev/null || true
  artifact "$FW/firmware_chip_indicators.txt" "firmware_chip_indicators" "grep"

  [[ -s "$FW/firmware_secret_hits.txt" ]] && finding "CRITICAL" "Firmware secret indicators" "Secret-like strings found in firmware" "$FW/firmware_secret_hits.txt"
  [[ -s "$FW/firmware_chip_indicators.txt" ]] && finding "INFO" "Firmware/chip indicators" "Firmware/chip indicators found" "$FW/firmware_chip_indicators.txt"

  testlog "E" "NR9-E001" "Firmware analysis" "PASS" "Firmware input analyzed" "$FW"
else
  testlog "E" "NR9-E001" "Firmware analysis" "SKIP" "No FIRMWARE_FILE provided" "-"
fi

# =============================================================================
# F. HARDWARE DEBUG ACCESS DOCUMENTATION
# =============================================================================

cat > "$HW/hardware_debug_checklist.md" <<'EOF'
# Hardware Debug Access Checklist

Use this stage only with physical ownership/authorization.

Document:
- Device photos before opening
- PCB front/back photos
- Chip markings
- Flash/eMMC/NAND markings
- UART/JTAG/SWD test pads
- Voltage levels measured
- GND/VCC/TX/RX candidate pins
- Serial baud rates tested
- Console output captured
- Whether console requires authentication
- Whether bootloader is locked
- Whether flash can be read externally

Suggested tools:
- Multimeter
- Logic analyzer
- FTDI/USB-TTL adapter
- Bus Pirate
- JTAGulator
- OpenOCD
- flashrom
- minicom/screen

Evidence to place here:
- photos/
- uart_bootlog.txt
- openocd_scan.txt
- flashrom_read.log
- chip_markings.txt
EOF

artifact "$HW/hardware_debug_checklist.md" "hardware_checklist" "operator"
testlog "F" "NR9-F001" "Hardware debug checklist" "PASS" "Hardware evidence checklist generated" "$HW/hardware_debug_checklist.md"

# =============================================================================
# G. STORAGE IMAGING
# =============================================================================

run_cmd "G" "NR9-G001" "Local block devices" "$STOR/local_block_devices.txt" lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,SERIAL,MOUNTPOINTS

if [[ "$MOUNT_SCAN" == "YES" ]]; then
  run_cmd "G" "NR9-G002" "Mounted filesystems" "$STOR/mounted_filesystems.txt" findmnt
  find /media /mnt -maxdepth 6 -type f 2>/dev/null > "$STOR/media_mnt_file_index.txt" || true
  artifact "$STOR/media_mnt_file_index.txt" "storage_file_index" "/media /mnt"
else
  testlog "G" "NR9-G002" "Mounted media scan" "SKIP" "Set MOUNT_SCAN=YES to index mounted SD/USB/SSD media" "-"
fi

if [[ -n "$DISK_IMAGE" && -f "$DISK_IMAGE" ]]; then
  cp "$DISK_IMAGE" "$STOR/input_disk_image.bin"
  artifact "$STOR/input_disk_image.bin" "disk_image" "$DISK_IMAGE"

  if have mmls; then run_cmd "G" "NR9-G010" "Disk partition map" "$STOR/mmls.txt" mmls "$STOR/input_disk_image.bin"; fi
  if have fsstat; then run_cmd "G" "NR9-G011" "Filesystem stats" "$STOR/fsstat.txt" fsstat "$STOR/input_disk_image.bin"; fi
  if have fls; then run_cmd "G" "NR9-G012" "Filesystem listing" "$STOR/fls_recursive.txt" fls -r -p "$STOR/input_disk_image.bin"; fi
else
  testlog "G" "NR9-G010" "Disk image analysis" "SKIP" "No DISK_IMAGE provided" "-"
fi

if [[ -n "$EXTRA_INPUT_DIR" && -d "$EXTRA_INPUT_DIR" ]]; then
  mkdir -p "$STOR/extra_input_copy"
  cp -a "$EXTRA_INPUT_DIR"/. "$STOR/extra_input_copy/" 2>/dev/null || true
  find "$STOR/extra_input_copy" -type f -print0 | while IFS= read -r -d '' f; do
    artifact "$f" "extra_input_file" "$EXTRA_INPUT_DIR"
  done
else
  testlog "G" "NR9-G020" "Extra input directory" "SKIP" "No EXTRA_INPUT_DIR provided" "-"
fi

# =============================================================================
# H. DATA CARVING & DECODING
# =============================================================================

mkdir -p "$DECODE"/{images,text,configs,databases,binaries,archives,certs,keys,unknown,carved}

if have foremost && [[ -s "${PCAP:-}" ]]; then
  mkdir -p "$DECODE/carved/foremost_pcap"
  foremost -i "$PCAP" -o "$DECODE/carved/foremost_pcap" > "$DECODE/foremost_pcap.log" 2>&1 || true
  artifact "$DECODE/foremost_pcap.log" "foremost_log" "pcap"
  find "$DECODE/carved/foremost_pcap" -type f -print0 | while IFS= read -r -d '' f; do
    artifact "$f" "carved_file" "foremost pcap"
  done
fi

if have bulk_extractor && [[ -s "${PCAP:-}" ]]; then
  mkdir -p "$DECODE/carved/bulk_pcap"
  bulk_extractor -o "$DECODE/carved/bulk_pcap" "$PCAP" > "$DECODE/bulk_extractor_pcap.log" 2>&1 || true
  artifact "$DECODE/bulk_extractor_pcap.log" "bulk_extractor_log" "pcap"
  find "$DECODE/carved/bulk_pcap" -type f -print0 | while IFS= read -r -d '' f; do
    artifact "$f" "bulk_feature_file" "bulk_extractor"
  done
fi

if have foremost && [[ -n "$DISK_IMAGE" && -f "$DISK_IMAGE" ]]; then
  mkdir -p "$DECODE/carved/foremost_disk"
  foremost -i "$DISK_IMAGE" -o "$DECODE/carved/foremost_disk" > "$DECODE/foremost_disk.log" 2>&1 || true
  artifact "$DECODE/foremost_disk.log" "foremost_log" "disk image"
fi

: > "$DECODE/file_type_inventory.tsv"
: > "$DECODE/strings_index.txt"
: > "$DECODE/secret_hits.txt"
: > "$DECODE/firmware_chip_indicators.txt"
: > "$DECODE/encryption_compression_indicators.txt"

find "$ROOT" -type f \
  ! -path "$DECODE/strings_index.txt" \
  ! -path "$DECODE/file_type_inventory.tsv" \
  ! -path "$DECODE/secret_hits.txt" \
  -print0 | while IFS= read -r -d '' f; do

  ft="$(file -b "$f" 2>/dev/null || echo unknown)"
  printf '%s\t%s\n' "$f" "$ft" >> "$DECODE/file_type_inventory.tsv"

  base="$(safe "$(basename "$f")")"

  if echo "$ft $f" | grep -qiE 'JPEG|PNG|GIF|WebP|BMP|TIFF|image'; then
    cp "$f" "$DECODE/images/$base" 2>/dev/null || true
    finding "MEDIUM" "Image artifact" "$f" "$DECODE/images/$base"
  elif echo "$ft $f" | grep -qiE 'ASCII|Unicode|UTF-8|HTML|JSON|XML|text|script'; then
    cp "$f" "$DECODE/text/$base.txt" 2>/dev/null || true
  elif echo "$ft $f" | grep -qiE 'SQLite|database'; then
    cp "$f" "$DECODE/databases/$base" 2>/dev/null || true
    finding "HIGH" "Database artifact" "$f" "$DECODE/databases/$base"
  elif echo "$ft $f" | grep -qiE 'Zip|gzip|xz|bzip2|tar|archive|7-zip'; then
    cp "$f" "$DECODE/archives/$base" 2>/dev/null || true
  elif echo "$ft $f" | grep -qiE 'ELF|executable|firmware|filesystem|Squashfs|u-boot|kernel|data'; then
    cp "$f" "$DECODE/binaries/$base" 2>/dev/null || true
  fi

  if echo "$f $ft" | grep -qiE 'config|conf|settings|json|yaml|yml|xml|ini|env|passwd|shadow|wireless|network'; then
    cp "$f" "$DECODE/configs/$base" 2>/dev/null || true
    finding "HIGH" "Config-like artifact" "$f" "$DECODE/configs/$base"
  fi

  if echo "$ft $f" | grep -qiE 'certificate|PEM|PGP|public key'; then
    cp "$f" "$DECODE/certs/$base" 2>/dev/null || true
  fi

  strings "$f" 2>/dev/null | head -n 300 >> "$DECODE/strings_index.txt" || true
  strings "$f" 2>/dev/null | grep -iE 'password|passwd|token|secret|api[_-]?key|credential|ssid|psk|BEGIN RSA|BEGIN OPENSSH|PRIVATE KEY|root:' >> "$DECODE/secret_hits.txt" || true
  strings "$f" 2>/dev/null | grep -iE 'hi351|hisilicon|ingenic|t31|t40|ambarella|novatek|realtek|rtl|mediatek|busybox|openwrt|linux version|u-boot|squashfs|mips|armv7|aarch64' >> "$DECODE/firmware_chip_indicators.txt" || true
  strings "$f" 2>/dev/null | grep -iE 'encrypted|cipher|aes|rsa|ecdsa|tls|ssl|certificate|BEGIN CERTIFICATE|salted|openssl|gzip|xz|lzma|zip|squashfs|quic' >> "$DECODE/encryption_compression_indicators.txt" || true
done

artifact "$DECODE/file_type_inventory.tsv" "classification" "file"
artifact "$DECODE/strings_index.txt" "classification" "strings"
artifact "$DECODE/secret_hits.txt" "classification" "secrets"
artifact "$DECODE/firmware_chip_indicators.txt" "classification" "chip_indicators"
artifact "$DECODE/encryption_compression_indicators.txt" "classification" "crypto_compression"

[[ -s "$DECODE/secret_hits.txt" ]] && finding "CRITICAL" "Secret indicators" "Secret-like strings found in collected evidence" "$DECODE/secret_hits.txt"
[[ -s "$DECODE/firmware_chip_indicators.txt" ]] && finding "INFO" "Firmware/chip indicators" "Chipset/firmware strings found" "$DECODE/firmware_chip_indicators.txt"
[[ -s "$DECODE/encryption_compression_indicators.txt" ]] && finding "INFO" "Encryption/compression indicators" "Crypto/compression strings found; decryption requires keys" "$DECODE/encryption_compression_indicators.txt"

if have ent; then
  find "$DECODE" -type f -size +1k -exec sh -c 'echo "===== $1 ====="; ent "$1" 2>/dev/null' _ {} \; > "$DECODE/entropy_report.txt" || true
  artifact "$DECODE/entropy_report.txt" "entropy_report" "ent"
fi

if have exiftool; then
  exiftool -r "$DECODE/images" > "$DECODE/image_exif_report.txt" 2>/dev/null || true
  artifact "$DECODE/image_exif_report.txt" "image_metadata" "exiftool"
fi

if have sqlite3; then
  find "$DECODE/databases" -type f -print0 2>/dev/null | while IFS= read -r -d '' db; do
    out="$DECODE/sqlite_$(safe "$(basename "$db")").schema.txt"
    sqlite3 "$db" ".schema" > "$out" 2>/dev/null || true
    artifact "$out" "sqlite_schema" "$db"
  done
fi

testlog "H" "NR9-H001" "Data carving and decoding" "PASS" "Classification, decoding, carving stage completed" "$DECODE"

# =============================================================================
# I. REPORTING & CHAIN OF CUSTODY
# =============================================================================

# Final hash sweep
find "$ROOT" -type f ! -path "$HASHES" -print0 | while IFS= read -r -d '' f; do
  grep -qF "$f" "$HASHES" 2>/dev/null || artifact "$f" "final_artifact" "final sweep"
done

PASS="$(awk -F'\t' '$5=="PASS"{c++} END{print c+0}' "$TESTS")"
WARN="$(awk -F'\t' '$5=="WARN"{c++} END{print c+0}' "$TESTS")"
FAIL="$(awk -F'\t' '$5=="FAIL"{c++} END{print c+0}' "$TESTS")"
SKIP="$(awk -F'\t' '$5=="SKIP"{c++} END{print c+0}' "$TESTS")"

CRIT="$(awk -F'\t' '$2=="CRITICAL"{c++} END{print c+0}' "$FINDINGS")"
HIGH="$(awk -F'\t' '$2=="HIGH"{c++} END{print c+0}' "$FINDINGS")"
MED="$(awk -F'\t' '$2=="MEDIUM"{c++} END{print c+0}' "$FINDINGS")"

IMG_COUNT="$(find "$DECODE/images" -type f 2>/dev/null | wc -l | tr -d ' ')"
TXT_COUNT="$(find "$DECODE/text" -type f 2>/dev/null | wc -l | tr -d ' ')"
CFG_COUNT="$(find "$DECODE/configs" -type f 2>/dev/null | wc -l | tr -d ' ')"
DB_COUNT="$(find "$DECODE/databases" -type f 2>/dev/null | wc -l | tr -d ' ')"
BIN_COUNT="$(find "$DECODE/binaries" -type f 2>/dev/null | wc -l | tr -d ' ')"

RTSP_FOUND="$(grep -c '^FOUND' "$PROTO/camera/rtsp_tests.tsv" 2>/dev/null || true)"
DNS_COUNT="$(wc -l < "$PROTO/dns_index.tsv" 2>/dev/null || echo 0)"
HTTP_200="$(awk -F'\t' '$1=="200" || $1=="206"{c++} END{print c+0}' "$PROTO/http_probe/http_inventory.tsv" 2>/dev/null || echo 0)"

if (( CRIT > 0 )); then
  LEVEL="CRITICAL"
elif (( HIGH > 0 )); then
  LEVEL="WEAK"
elif (( MED > 0 || WARN > 2 )); then
  LEVEL="MODERATE"
else
  LEVEL="STRONG"
fi

{
  echo "# GhostRedRecon NR9 IoT Forensic Audit Report"
  echo
  echo "**Target:** $TARGET_IP"
  echo "**Run ID:** $RUN_ID"
  echo "**Script:** $SCRIPT_NAME"
  echo "**Version:** $VERSION"
  echo "**Level:** $LEVEL"
  echo "**Timestamp UTC:** $(ts)"
  echo
  echo "## Flow"
  echo "A Threat Modeling & Preparation → B Network Discovery & Scanning → C Traffic Capture & Logging → D Protocol & Service Analysis → E Firmware Acquisition & Analysis → F Hardware Debug Access → G Storage Imaging → H Data Carving & Decoding → I Reporting & Chain-of-Custody"
  echo
  echo "## Summary"
  echo "- PASS: $PASS"
  echo "- WARN: $WARN"
  echo "- FAIL: $FAIL"
  echo "- SKIP: $SKIP"
  echo "- CRITICAL findings: $CRIT"
  echo "- HIGH findings: $HIGH"
  echo "- MEDIUM findings: $MED"
  echo "- Open TCP ports: $TCP_OPEN"
  echo "- Open/open-filtered UDP ports: $UDP_OPEN"
  echo "- RTSP streams found: $RTSP_FOUND"
  echo "- HTTP objects returned 200/206: $HTTP_200"
  echo "- DNS rows observed: $DNS_COUNT"
  echo
  echo "## Decoded Evidence Counts"
  echo "- Images: $IMG_COUNT"
  echo "- Text/web files: $TXT_COUNT"
  echo "- Config-like files: $CFG_COUNT"
  echo "- Databases: $DB_COUNT"
  echo "- Binaries/firmware-like files: $BIN_COUNT"
  echo
  echo "## Important Limits"
  echo "- This audit does not bypass authentication."
  echo "- This audit does not brute-force credentials."
  echo "- Encrypted data is reported as encrypted unless keys are present in collected evidence."
  echo "- Internal flash/eMMC contents require firmware file, disk image, UART/JTAG/SPI/eMMC access, or exposed services."
  echo
  echo "## Evidence Map"
  echo "- Chain of custody: \`00_chain_of_custody/\`"
  echo "- Threat model: \`01_threat_model/\`"
  echo "- Network discovery: \`02_network_discovery/\`"
  echo "- Traffic capture: \`03_traffic_capture/\`"
  echo "- Protocol/service analysis: \`04_protocol_service_analysis/\`"
  echo "- Firmware analysis: \`05_firmware_analysis/\`"
  echo "- Hardware debug checklist: \`06_hardware_debug_access/\`"
  echo "- Storage imaging: \`07_storage_imaging/\`"
  echo "- Carving/decoding: \`08_carving_decoding/\`"
  echo "- Reports/hashes: \`09_reports/\`"
  echo
  echo "## Tests"
  echo "| Time | Stage | ID | Test | Status | Reason | Evidence |"
  echo "|---|---|---|---|---:|---|---|"
  awk -F'\t' '{printf("| %s | %s | %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7)}' "$TESTS"
  echo
  echo "## Findings"
  echo "| Time | Severity | Category | Item | Evidence |"
  echo "|---|---|---|---|---|"
  awk -F'\t' '{printf("| %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5)}' "$FINDINGS"
} > "$REPORT"

python3 - "$VERSION" "$TARGET_IP" "$RUN_ID" "$LEVEL" "$TESTS" "$FINDINGS" "$ARTIFACTS" "$IMG_COUNT" "$TXT_COUNT" "$CFG_COUNT" "$DB_COUNT" "$BIN_COUNT" "$RTSP_FOUND" "$DNS_COUNT" "$HTTP_200" > "$JSON" <<'PY'
import json, sys
from datetime import datetime, timezone

version,target,run_id,level,tests,findings,artifacts,img,txt,cfg,db,binc,rtsp,dns,http200=sys.argv[1:]

def read_tsv(path, keys):
    rows=[]
    try:
        for line in open(path, errors="replace"):
            p=line.rstrip("\n").split("\t")
            if len(p)>=len(keys):
                rows.append({k:p[i] for i,k in enumerate(keys)})
    except FileNotFoundError:
        pass
    return rows

print(json.dumps({
  "tool": "GhostRedRecon NR9 IoT Forensic Audit",
  "version": version,
  "target": target,
  "run_id": run_id,
  "level": level,
  "timestamp_utc": datetime.now(timezone.utc).isoformat(),
  "flow": [
    "Threat Modeling & Preparation",
    "Network Discovery & Scanning",
    "Traffic Capture & Logging",
    "Protocol & Service Analysis",
    "Firmware Acquisition & Analysis",
    "Hardware Debug Access",
    "Storage Imaging",
    "Data Carving & Decoding",
    "Reporting & Chain-of-Custody"
  ],
  "counts": {
    "images": int(img),
    "text_web_files": int(txt),
    "configs": int(cfg),
    "databases": int(db),
    "binaries": int(binc),
    "rtsp_streams_found": int(rtsp),
    "dns_rows": int(dns),
    "http_200_206_objects": int(http200)
  },
  "tests": read_tsv(tests, ["time","stage","id","name","status","reason","evidence"]),
  "findings": read_tsv(findings, ["time","severity","category","item","evidence"]),
  "artifacts": read_tsv(artifacts, ["time","name","kind","size","sha256","mime","path","source"])
}, indent=2))
PY

artifact "$REPORT" "report" "markdown"
artifact "$JSON" "report" "json"

echo
echo "=== NR9 IOT FORENSIC AUDIT COMPLETE ==="
echo "Level   : $LEVEL"
echo "Report  : $REPORT"
echo "JSON    : $JSON"
echo "Hashes  : $HASHES"
echo "Output  : $ROOT"
