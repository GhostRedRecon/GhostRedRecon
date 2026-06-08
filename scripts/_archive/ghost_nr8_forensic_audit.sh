#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "ERROR: run with bash: sudo -E bash ghost_nr8_forensic_audit.sh"
  exit 1
fi

SCRIPT_NAME="$(basename "$0" .sh)"
VERSION="NR8-FORENSIC-AUDIT-1.0"

TARGET_IP="${TARGET_IP:-192.168.0.29}"
LAN_IFACE="${LAN_IFACE:-wlan0}"
CONFIRM_AUTH="${CONFIRM_AUTH:-YES}"
OUT_BASE="${OUT_BASE:-./evidence}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-300}"
MAX_BYTES="${MAX_BYTES:-10485760}"
TCP_PORTS="${TCP_PORTS:-1-65535}"
UDP_PORTS="${UDP_PORTS:-53,67,68,123,137,161,1900,5353,5683,54321}"
FIRMWARE_FILE="${FIRMWARE_FILE:-}"
DISK_IMAGE="${DISK_IMAGE:-}"
EXTRA_INPUT_DIR="${EXTRA_INPUT_DIR:-}"
MOUNT_SCAN="${MOUNT_SCAN:-NO}"

HTTP_PORTS="${HTTP_PORTS:-80 81 82 83 88 443 554 591 8000 8001 8008 8080 8081 8088 8090 8443 8554 8888 9000 9090 10000}"
RTSP_PORTS="${RTSP_PORTS:-554 8554 10554}"

if [[ "$CONFIRM_AUTH" != "YES" ]]; then
  echo "ERROR: Set CONFIRM_AUTH=YES for owned/authorized testing."
  echo "Example:"
  echo "sudo -E CONFIRM_AUTH=YES TARGET_IP=192.168.0.29 LAN_IFACE=wlan0 CAPTURE_SECONDS=300 bash $0"
  exit 1
fi

RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="$OUT_BASE/${SCRIPT_NAME}_${RUN_ID}"
mkdir -p "$ROOT"/{00_case,01_capture,02_surface,03_camera_protocols,04_cloud_behavior,05_web_storage,06_shares,07_objects,08_carving,09_firmware,10_storage,11_decoded,12_reports,logs}

CASE="$ROOT/00_case"
CAP="$ROOT/01_capture"
SURF="$ROOT/02_surface"
CAM="$ROOT/03_camera_protocols"
CLOUD="$ROOT/04_cloud_behavior"
WEB="$ROOT/05_web_storage"
SHARES="$ROOT/06_shares"
OBJ="$ROOT/07_objects"
CARVE="$ROOT/08_carving"
FW="$ROOT/09_firmware"
STOR="$ROOT/10_storage"
DEC="$ROOT/11_decoded"
REP="$ROOT/12_reports"
LOGS="$ROOT/logs"

TESTS="$REP/tests.tsv"
FINDINGS="$REP/findings.tsv"
ARTIFACTS="$REP/artifacts.tsv"
HASHES="$REP/sha256_manifest.txt"
REPORT="$REP/report.md"
JSON="$REP/report.json"

: > "$TESTS"; : > "$FINDINGS"; : > "$ARTIFACTS"; : > "$HASHES"

ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
have(){ command -v "$1" >/dev/null 2>&1; }
safe(){ echo "$1" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-180; }
log(){ echo "[$(ts)] $*" | tee -a "$LOGS/run.log"; }

artifact(){
  local f="$1" kind="${2:-artifact}" source="${3:-unknown}"
  [[ -f "$f" ]] || return 0
  local h s m
  h="$(sha256sum "$f" | awk '{print $1}')"
  s="$(wc -c < "$f" 2>/dev/null || echo 0)"
  m="$(file -b "$f" 2>/dev/null || echo unknown)"
  echo "$h  $f" >> "$HASHES"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(ts)" "$(basename "$f")" "$kind" "$s" "$h" "$m" "$f" "$source" >> "$ARTIFACTS"
}

testlog(){
  local stage="$1" id="$2" name="$3" status="$4" reason="$5" evidence="${6:-}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(ts)" "$stage" "$id" "$name" "$status" "$reason" "$evidence" >> "$TESTS"
  log "[$stage][$id] $status - $name - $reason"
}

finding(){
  local sev="$1" cat="$2" item="$3" evidence="$4"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(ts)" "$sev" "$cat" "$item" "$evidence" >> "$FINDINGS"
}

run_cmd(){
  local stage="$1" id="$2" name="$3" outfile="$4"; shift 4
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

need=(bash nmap curl nc awk sed grep sha256sum file strings python3 ping xxd)
missing=()
for x in "${need[@]}"; do have "$x" || missing+=("$x"); done
if (( ${#missing[@]} )); then
  echo "Missing required tools: ${missing[*]}"
  exit 1
fi

log "GhostRedRecon $VERSION"
log "Target: $TARGET_IP"
log "Output: $ROOT"

# STAGE 0: CASE
{
  echo "tool=$VERSION"
  echo "script=$SCRIPT_NAME"
  echo "target_ip=$TARGET_IP"
  echo "interface=$LAN_IFACE"
  echo "run_id=$RUN_ID"
  echo "operator=$(whoami)"
  echo "host=$(hostname)"
  echo "start_utc=$(ts)"
  echo "kernel=$(uname -a)"
  echo "scope=authorized IoT camera forensic security audit"
} > "$CASE/case_metadata.txt"
artifact "$CASE/case_metadata.txt" "case_metadata" "system"
testlog "S0" "NR8-000" "Case metadata" "PASS" "Case metadata created" "$CASE/case_metadata.txt"

# STAGE 1: CAPTURE
PCAP="$CAP/behavior_capture.pcap"
if have tcpdump; then
  testlog "S1" "NR8-100" "Behavior PCAP capture" "RUN" "Capture $CAPTURE_SECONDS seconds; use the camera app during this window" "$PCAP"
  timeout "$CAPTURE_SECONDS" tcpdump -i "$LAN_IFACE" host "$TARGET_IP" -w "$PCAP" > "$LOGS/tcpdump_stdout.log" 2>"$LOGS/tcpdump_stderr.log" || true
  if [[ -s "$PCAP" ]]; then
    artifact "$PCAP" "pcap" "tcpdump"
    testlog "S1" "NR8-100" "Behavior PCAP capture" "PASS" "PCAP captured" "$PCAP"
  else
    testlog "S1" "NR8-100" "Behavior PCAP capture" "WARN" "No packets captured" "$PCAP"
  fi
else
  testlog "S1" "NR8-100" "Behavior PCAP capture" "SKIP" "tcpdump missing" "-"
fi

# STAGE 2: PORTS / SERVICES / IDENTITY
run_cmd "S2" "NR8-200" "Reachability ping" "$SURF/ping.txt" ping -c 3 -W 2 "$TARGET_IP"
run_cmd "S2" "NR8-201" "ARP neighbor" "$SURF/arp_neighbor.txt" ip neigh show "$TARGET_IP"
run_cmd "S2" "NR8-202" "TCP full scan" "$SURF/nmap_tcp.txt" nmap -Pn -sT -p "$TCP_PORTS" --reason "$TARGET_IP"
grep -E '^[0-9]+/tcp[[:space:]]+open' "$SURF/nmap_tcp.txt" > "$SURF/open_tcp.txt" || true
artifact "$SURF/open_tcp.txt" "index" "open tcp"

run_cmd "S2" "NR8-203" "UDP selected scan" "$SURF/nmap_udp.txt" nmap -Pn -sU -p "$UDP_PORTS" --reason "$TARGET_IP"
grep -E '^[0-9]+/udp[[:space:]]+(open|open\|filtered)' "$SURF/nmap_udp.txt" > "$SURF/open_udp.txt" || true
artifact "$SURF/open_udp.txt" "index" "open udp"

run_cmd "S2" "NR8-204" "Service fingerprint" "$SURF/nmap_services.txt" nmap -Pn -sV --version-all "$TARGET_IP"
run_cmd "S2" "NR8-205" "OS fingerprint attempt" "$SURF/nmap_os.txt" nmap -Pn -O --osscan-guess "$TARGET_IP"

TCP_OPEN="$(wc -l < "$SURF/open_tcp.txt" | tr -d ' ')"
UDP_OPEN="$(wc -l < "$SURF/open_udp.txt" | tr -d ' ')"
[[ "$TCP_OPEN" -gt 0 ]] && finding "MEDIUM" "Open TCP ports" "$TCP_OPEN open TCP ports" "$SURF/open_tcp.txt"
[[ "$UDP_OPEN" -gt 0 ]] && finding "LOW" "UDP surface" "$UDP_OPEN open/open-filtered UDP ports" "$SURF/open_udp.txt"

# STAGE 3: CAMERA / STREAM / ONVIF / RTSP
: > "$CAM/rtsp_tests.tsv"
RTSP_PATHS=(
"/" "/live" "/live.sdp" "/stream" "/stream1" "/h264" "/video" "/videoMain"
"/cam/realmonitor?channel=1&subtype=0" "/onvif1" "/11" "/0" "/ch0_0.h264"
)

if have ffprobe; then
  for p in $RTSP_PORTS; do
    for path in "${RTSP_PATHS[@]}"; do
      url="rtsp://$TARGET_IP:$p$path"
      out="$CAM/rtsp_$(safe "$url").txt"
      timeout 8 ffprobe -v error -show_format -show_streams "$url" > "$out" 2>&1 || true
      artifact "$out" "rtsp_probe" "$url"
      if grep -qiE 'codec_type=video|Video:|codec_name|width=|height=' "$out"; then
        printf 'FOUND\t%s\t%s\n' "$url" "$out" >> "$CAM/rtsp_tests.tsv"
        finding "HIGH" "Camera stream exposed" "$url" "$out"
      else
        printf 'NO_STREAM\t%s\t%s\n' "$url" "$out" >> "$CAM/rtsp_tests.tsv"
      fi
    done
  done
  artifact "$CAM/rtsp_tests.tsv" "rtsp_index" "ffprobe"
  RTSP_FOUND="$(grep -c '^FOUND' "$CAM/rtsp_tests.tsv" || true)"
  [[ "$RTSP_FOUND" -gt 0 ]] && testlog "S3" "NR8-300" "RTSP stream detection" "FAIL" "$RTSP_FOUND RTSP stream paths responded" "$CAM/rtsp_tests.tsv" || testlog "S3" "NR8-300" "RTSP stream detection" "PASS" "No RTSP streams found" "$CAM/rtsp_tests.tsv"
else
  testlog "S3" "NR8-300" "RTSP stream detection" "SKIP" "ffprobe missing" "-"
fi

# ONVIF HTTP probes
: > "$CAM/onvif_inventory.tsv"
ONVIF_PATHS=("/onvif/device_service" "/onvif/Device" "/onvif" "/onvif/device")
for port in 80 8000 8080 8899 8999; do
  for path in "${ONVIF_PATHS[@]}"; do
    url="http://$TARGET_IP:$port$path"
    out="$CAM/onvif_$(safe "$url").txt"
    curl -sS -m 5 -i "$url" > "$out" 2>&1 || true
    artifact "$out" "onvif_probe" "$url"
    if grep -qiE 'onvif|tds:|SOAP|GetDeviceInformation|device_service' "$out"; then
      printf 'FOUND\t%s\t%s\n' "$url" "$out" >> "$CAM/onvif_inventory.tsv"
      finding "MEDIUM" "ONVIF indicator" "$url" "$out"
    fi
  done
done
artifact "$CAM/onvif_inventory.tsv" "onvif_index" "curl"
ONVIF_FOUND="$(grep -c '^FOUND' "$CAM/onvif_inventory.tsv" 2>/dev/null || true)"
[[ "$ONVIF_FOUND" -gt 0 ]] && testlog "S3" "NR8-301" "ONVIF detection" "WARN" "$ONVIF_FOUND ONVIF indicators found" "$CAM/onvif_inventory.tsv" || testlog "S3" "NR8-301" "ONVIF detection" "PASS" "No ONVIF indicators found" "$CAM/onvif_inventory.tsv"

# STAGE 4: CLOUD / ENCRYPTION / TRAFFIC
if have tshark && [[ -s "$PCAP" ]]; then
  run_cmd "S4" "NR8-400" "Protocol hierarchy" "$CLOUD/protocol_hierarchy.txt" tshark -r "$PCAP" -q -z io,phs
  run_cmd "S4" "NR8-401" "Conversations" "$CLOUD/conversations.txt" tshark -r "$PCAP" -q -z conv,tcp -z conv,udp
  run_cmd "S4" "NR8-402" "Flow index" "$CLOUD/flow_index.tsv" tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP" -T fields -e frame.time -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info

  tshark -r "$PCAP" -Y "dns" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.a -e dns.aaaa -e dns.resp.name > "$CLOUD/dns_index.tsv" 2>/dev/null || true
  artifact "$CLOUD/dns_index.tsv" "dns_index" "tshark"

  tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name > "$CLOUD/tls_sni.tsv" 2>/dev/null || true
  artifact "$CLOUD/tls_sni.tsv" "tls_sni" "tshark"

  tshark -r "$PCAP" -Y "tls || ssl || quic || tcp.port==443 || udp.port==443" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info > "$CLOUD/encryption_indicators.tsv" 2>/dev/null || true
  artifact "$CLOUD/encryption_indicators.tsv" "encryption_index" "tshark"

  tshark -r "$PCAP" -Y "http || ftp || telnet || data-text-lines" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info > "$CLOUD/plaintext_indicators.tsv" 2>/dev/null || true
  artifact "$CLOUD/plaintext_indicators.tsv" "plaintext_index" "tshark"

  tshark -r "$PCAP" -Y "ip.src==$TARGET_IP" -T fields -e ip.dst -e ipv6.dst | grep -v '^$' | sort -u > "$CLOUD/remote_destinations.txt" 2>/dev/null || true
  artifact "$CLOUD/remote_destinations.txt" "remote_destinations" "tshark"

  [[ -s "$CLOUD/encryption_indicators.tsv" ]] && finding "INFO" "Encrypted transport observed" "TLS/QUIC/443 indicators found" "$CLOUD/encryption_indicators.tsv"
  [[ -s "$CLOUD/plaintext_indicators.tsv" ]] && finding "HIGH" "Plaintext traffic indicator" "HTTP/FTP/Telnet/text-like traffic found" "$CLOUD/plaintext_indicators.tsv"
  [[ -s "$CLOUD/dns_index.tsv" ]] && finding "INFO" "Cloud/DNS behavior" "DNS behavior captured" "$CLOUD/dns_index.tsv"
else
  testlog "S4" "NR8-400" "Cloud/protocol analysis" "SKIP" "tshark missing or no PCAP" "-"
fi

# STAGE 5: WEB / STORAGE / FIRMWARE ENDPOINT ENUMERATION
cat > "$WEB/paths.txt" <<'EOF'
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
/miio.conf
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
/miio.db
/robots.txt
/sitemap.xml
/.env
/.git/config
EOF

: > "$WEB/http_inventory.tsv"
fetch_url(){
  local url="$1"
  local name h b m code size ctype
  name="$(safe "$url")"
  h="$WEB/${name}.headers"
  b="$WEB/${name}.body"
  m="$WEB/${name}.meta"
  code="$(curl -k -sS -L --max-time 7 --connect-timeout 4 --range "0-$MAX_BYTES" -D "$h" -o "$b" -w "%{http_code}" "$url" 2>/dev/null || true)"
  size="$(wc -c < "$b" 2>/dev/null || echo 0)"
  ctype="$(grep -i '^content-type:' "$h" 2>/dev/null | head -n1 | tr -d '\r' || true)"
  if [[ -s "$h" || -s "$b" ]]; then
    printf 'url=%s\ncode=%s\nbytes=%s\ncontent_type=%s\ntime=%s\n' "$url" "$code" "$size" "$ctype" "$(ts)" > "$m"
    artifact "$h" "http_headers" "$url"
    artifact "$b" "http_body" "$url"
    artifact "$m" "http_meta" "$url"
    printf '%s\t%s\t%s\t%s\t%s\n' "$code" "$size" "$ctype" "$url" "$b" >> "$WEB/http_inventory.tsv"
  fi
}

while read -r path; do
  [[ -z "$path" ]] && continue
  for port in $HTTP_PORTS; do
    fetch_url "http://$TARGET_IP:$port$path"
    [[ "$port" == "443" || "$port" == "8443" ]] && fetch_url "https://$TARGET_IP:$port$path"
  done
done < "$WEB/paths.txt"
artifact "$WEB/http_inventory.tsv" "http_inventory" "curl"

HTTP_OK="$(awk -F'\t' '$1=="200" || $1=="206"{c++} END{print c+0}' "$WEB/http_inventory.tsv")"
[[ "$HTTP_OK" -gt 0 ]] && finding "HIGH" "HTTP exposed objects" "$HTTP_OK HTTP objects accessible" "$WEB/http_inventory.tsv"
[[ "$HTTP_OK" -gt 0 ]] && testlog "S5" "NR8-500" "HTTP/storage endpoint audit" "FAIL" "$HTTP_OK HTTP objects returned 200/206" "$WEB/http_inventory.tsv" || testlog "S5" "NR8-500" "HTTP/storage endpoint audit" "PASS" "No HTTP objects returned 200/206" "$WEB/http_inventory.tsv"

# STAGE 6: SHARES / STORAGE SERVICES
if have smbclient && grep -qE '^(139|445)/tcp[[:space:]]+open' "$SURF/open_tcp.txt" 2>/dev/null; then
  smbclient -L "//$TARGET_IP" -N > "$SHARES/smb_shares.txt" 2>&1 || true
  artifact "$SHARES/smb_shares.txt" "smb" "anonymous"
  awk '/^[[:space:]]*[A-Za-z0-9_$.-]+[[:space:]]+(Disk|IPC)/ {print $1}' "$SHARES/smb_shares.txt" | while read -r share; do
    smbclient "//$TARGET_IP/$share" -N -c "recurse; ls" >> "$SHARES/smb_recursive.txt" 2>&1 || true
  done
  artifact "$SHARES/smb_recursive.txt" "smb_recursive" "anonymous"
else
  testlog "S6" "NR8-600" "SMB anonymous inventory" "SKIP" "SMB closed or smbclient missing" "-"
fi

if grep -qE '^21/tcp[[:space:]]+open' "$SURF/open_tcp.txt" 2>/dev/null; then
  { echo "user anonymous anonymous@"; echo "pwd"; echo "ls -la"; echo "quit"; } | timeout 20 nc "$TARGET_IP" 21 > "$SHARES/ftp_listing.txt" 2>&1 || true
  artifact "$SHARES/ftp_listing.txt" "ftp" "anonymous"
else
  testlog "S6" "NR8-601" "FTP anonymous inventory" "SKIP" "FTP closed" "-"
fi

if have showmount; then
  showmount -e "$TARGET_IP" > "$SHARES/nfs_exports.txt" 2>&1 || true
  artifact "$SHARES/nfs_exports.txt" "nfs_exports" "showmount"
fi

if have snmpwalk; then
  timeout 25 snmpwalk -v2c -c public "$TARGET_IP" 1.3.6.1 > "$SHARES/snmp_public.txt" 2>&1 || true
  artifact "$SHARES/snmp_public.txt" "snmp_public" "snmpwalk"
  [[ -s "$SHARES/snmp_public.txt" ]] && grep -qiE 'sysDescr|sysName|STRING:|INTEGER:' "$SHARES/snmp_public.txt" && finding "HIGH" "SNMP public data" "SNMP public community returned data" "$SHARES/snmp_public.txt"
fi

# STAGE 7: PCAP OBJECT EXTRACTION
if have tshark && [[ -s "$PCAP" ]]; then
  mkdir -p "$OBJ/http" "$OBJ/smb" "$OBJ/tftp" "$OBJ/imf"
  tshark -Q -r "$PCAP" --export-objects "http,$OBJ/http" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "smb,$OBJ/smb" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "tftp,$OBJ/tftp" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "imf,$OBJ/imf" 2>/dev/null || true
  find "$OBJ" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "pcap_exported_object" "tshark export"; done
  testlog "S7" "NR8-700" "PCAP object export" "PASS" "HTTP/SMB/TFTP/IMF object export attempted" "$OBJ"

  tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP && data.data" -T fields -e data.data > "$OBJ/raw_payload_hex.txt" 2>/dev/null || true
  artifact "$OBJ/raw_payload_hex.txt" "raw_payload_hex" "tshark"
  mkdir -p "$OBJ/raw_payloads"
  i=0
  while read -r line; do
    [[ -z "$line" ]] && continue
    echo "$line" | xxd -r -p > "$OBJ/raw_payloads/payload_${i}.bin" 2>/dev/null || true
    artifact "$OBJ/raw_payloads/payload_${i}.bin" "raw_payload_bin" "pcap data"
    i=$((i+1))
  done < "$OBJ/raw_payload_hex.txt"
fi

# STAGE 8: CARVING / FEATURE EXTRACTION
if have foremost && [[ -s "$PCAP" ]]; then
  mkdir -p "$CARVE/foremost_pcap"
  foremost -i "$PCAP" -o "$CARVE/foremost_pcap" > "$LOGS/foremost_pcap.log" 2>&1 || true
  artifact "$LOGS/foremost_pcap.log" "foremost_log" "pcap"
  find "$CARVE/foremost_pcap" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "carved_file" "foremost pcap"; done
fi

if have bulk_extractor && [[ -s "$PCAP" ]]; then
  mkdir -p "$CARVE/bulk_pcap"
  bulk_extractor -o "$CARVE/bulk_pcap" "$PCAP" > "$LOGS/bulk_pcap.log" 2>&1 || true
  artifact "$LOGS/bulk_pcap.log" "bulk_extractor_log" "pcap"
  find "$CARVE/bulk_pcap" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "bulk_feature_file" "bulk_extractor pcap"; done
fi

# STAGE 9: FIRMWARE / STORAGE INPUTS
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
    find "$FW/binwalk_extract" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do artifact "$f" "firmware_extracted_file" "binwalk"; done
  fi
else
  testlog "S9" "NR8-900" "Firmware analysis" "SKIP" "No FIRMWARE_FILE provided" "-"
fi

run_cmd "S9" "NR8-901" "Local block devices" "$STOR/local_block_devices.txt" lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,SERIAL,MOUNTPOINTS

if [[ "$MOUNT_SCAN" == "YES" ]]; then
  run_cmd "S9" "NR8-902" "Mounted filesystems" "$STOR/mounted_filesystems.txt" findmnt
  find /media /mnt -maxdepth 6 -type f 2>/dev/null > "$STOR/media_mnt_file_index.txt" || true
  artifact "$STOR/media_mnt_file_index.txt" "storage_file_index" "/media /mnt"
else
  testlog "S9" "NR8-902" "Mounted media index" "SKIP" "Set MOUNT_SCAN=YES to index mounted SD/USB/SSD media" "-"
fi

if [[ -n "$DISK_IMAGE" && -f "$DISK_IMAGE" ]]; then
  cp "$DISK_IMAGE" "$STOR/input_disk_image.bin"
  artifact "$STOR/input_disk_image.bin" "disk_image" "$DISK_IMAGE"
  have mmls && run_cmd "S9" "NR8-910" "Disk partition map" "$STOR/mmls.txt" mmls "$STOR/input_disk_image.bin"
  have fsstat && run_cmd "S9" "NR8-911" "Filesystem stats" "$STOR/fsstat.txt" fsstat "$STOR/input_disk_image.bin"
  have fls && run_cmd "S9" "NR8-912" "Filesystem listing" "$STOR/fls_recursive.txt" fls -r -p "$STOR/input_disk_image.bin"
fi

if [[ -n "$EXTRA_INPUT_DIR" && -d "$EXTRA_INPUT_DIR" ]]; then
  mkdir -p "$STOR/extra_input_copy"
  cp -a "$EXTRA_INPUT_DIR"/. "$STOR/extra_input_copy/" 2>/dev/null || true
  find "$STOR/extra_input_copy" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "extra_input_file" "$EXTRA_INPUT_DIR"; done
fi

# STAGE 10: DECODE / CLASSIFY EVERYTHING
mkdir -p "$DEC"/{images,text,configs,databases,binaries,archives,certs,keys,unknown}
: > "$DEC/file_type_inventory.tsv"
: > "$DEC/strings_index.txt"
: > "$DEC/secret_hits.txt"
: > "$DEC/firmware_chip_indicators.txt"
: > "$DEC/encryption_compression_indicators.txt"

find "$ROOT" -type f \
  ! -path "$DEC/strings_index.txt" \
  ! -path "$DEC/file_type_inventory.tsv" \
  ! -path "$DEC/secret_hits.txt" \
  -print0 | while IFS= read -r -d '' f; do
    ft="$(file -b "$f" 2>/dev/null || echo unknown)"
    printf '%s\t%s\n' "$f" "$ft" >> "$DEC/file_type_inventory.tsv"
    base="$(safe "$(basename "$f")")"

    if echo "$ft $f" | grep -qiE 'JPEG|PNG|GIF|WebP|BMP|TIFF|image'; then
      cp "$f" "$DEC/images/$base" 2>/dev/null || true
      finding "MEDIUM" "Image artifact" "$f" "$DEC/images/$base"
    elif echo "$ft $f" | grep -qiE 'ASCII|Unicode|UTF-8|HTML|JSON|XML|text|script'; then
      cp "$f" "$DEC/text/$base.txt" 2>/dev/null || true
    elif echo "$ft $f" | grep -qiE 'SQLite|database'; then
      cp "$f" "$DEC/databases/$base" 2>/dev/null || true
      finding "HIGH" "Database artifact" "$f" "$DEC/databases/$base"
    elif echo "$ft $f" | grep -qiE 'Zip|gzip|xz|bzip2|tar|archive|7-zip'; then
      cp "$f" "$DEC/archives/$base" 2>/dev/null || true
    elif echo "$ft $f" | grep -qiE 'ELF|executable|firmware|filesystem|Squashfs|u-boot|kernel|data'; then
      cp "$f" "$DEC/binaries/$base" 2>/dev/null || true
    fi

    if echo "$f $ft" | grep -qiE 'config|conf|settings|json|yaml|yml|xml|ini|env|passwd|shadow|wireless|network'; then
      cp "$f" "$DEC/configs/$base" 2>/dev/null || true
      finding "HIGH" "Config-like artifact" "$f" "$DEC/configs/$base"
    fi

    if echo "$ft $f" | grep -qiE 'certificate|PEM|PGP|public key'; then
      cp "$f" "$DEC/certs/$base" 2>/dev/null || true
    fi

    strings "$f" 2>/dev/null | head -n 300 >> "$DEC/strings_index.txt" || true
    strings "$f" 2>/dev/null | grep -iE 'password|passwd|token|secret|api[_-]?key|credential|ssid|psk|BEGIN RSA|BEGIN OPENSSH|PRIVATE KEY|root:' >> "$DEC/secret_hits.txt" || true
    strings "$f" 2>/dev/null | grep -iE 'hi351|hi355|ingenic|t31|t40|ambarella|novatek|realtek|rtl|xm|xiongmai|grain|hisilicon|mediatek|mt76|busybox|openwrt|linux version|u-boot|squashfs|mips|armv7|aarch64' >> "$DEC/firmware_chip_indicators.txt" || true
    strings "$f" 2>/dev/null | grep -iE 'encrypted|cipher|aes|rsa|ecdsa|tls|ssl|certificate|BEGIN CERTIFICATE|salted|openssl|gzip|xz|lzma|zip|squashfs|quic' >> "$DEC/encryption_compression_indicators.txt" || true
done

artifact "$DEC/file_type_inventory.tsv" "classification" "file"
artifact "$DEC/strings_index.txt" "classification" "strings"
artifact "$DEC/secret_hits.txt" "classification" "secrets"
artifact "$DEC/firmware_chip_indicators.txt" "classification" "firmware_chip"
artifact "$DEC/encryption_compression_indicators.txt" "classification" "crypto_compression"
find "$DEC" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "decoded_artifact" "classification"; done

[[ -s "$DEC/secret_hits.txt" ]] && finding "CRITICAL" "Secret indicators" "Secret-like strings found" "$DEC/secret_hits.txt"
[[ -s "$DEC/firmware_chip_indicators.txt" ]] && finding "INFO" "Firmware/chip indicators" "Chipset/firmware strings found" "$DEC/firmware_chip_indicators.txt"
[[ -s "$DEC/encryption_compression_indicators.txt" ]] && finding "INFO" "Encryption/compression indicators" "Crypto/compression strings found; decryption requires keys" "$DEC/encryption_compression_indicators.txt"

have ent && find "$DEC" -type f -size +1k -exec sh -c 'echo "===== $1 ====="; ent "$1" 2>/dev/null' _ {} \; > "$DEC/entropy_report.txt" || true
[[ -f "$DEC/entropy_report.txt" ]] && artifact "$DEC/entropy_report.txt" "entropy_report" "ent"

have jq && find "$DEC/text" "$DEC/configs" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do jq . "$f" > "$f.pretty.json" 2>/dev/null && artifact "$f.pretty.json" "decoded_json" "$f" || true; done
have exiftool && exiftool -r "$DEC/images" > "$DEC/image_exif_report.txt" 2>/dev/null && artifact "$DEC/image_exif_report.txt" "image_metadata" "exiftool" || true
have sqlite3 && find "$DEC/databases" -type f -print0 2>/dev/null | while IFS= read -r -d '' db; do out="$DEC/sqlite_$(safe "$(basename "$db")").schema.txt"; sqlite3 "$db" ".schema" > "$out" 2>/dev/null && artifact "$out" "sqlite_schema" "$db" || true; done

# FINAL REPORT
PASS="$(awk -F'\t' '$5=="PASS"{c++} END{print c+0}' "$TESTS")"
WARN="$(awk -F'\t' '$5=="WARN"{c++} END{print c+0}' "$TESTS")"
FAIL="$(awk -F'\t' '$5=="FAIL"{c++} END{print c+0}' "$TESTS")"
SKIP="$(awk -F'\t' '$5=="SKIP"{c++} END{print c+0}' "$TESTS")"
CRIT="$(awk -F'\t' '$2=="CRITICAL"{c++} END{print c+0}' "$FINDINGS")"
HIGH="$(awk -F'\t' '$2=="HIGH"{c++} END{print c+0}' "$FINDINGS")"
MED="$(awk -F'\t' '$2=="MEDIUM"{c++} END{print c+0}' "$FINDINGS")"

IMG_COUNT="$(find "$DEC/images" -type f 2>/dev/null | wc -l | tr -d ' ')"
TXT_COUNT="$(find "$DEC/text" -type f 2>/dev/null | wc -l | tr -d ' ')"
CFG_COUNT="$(find "$DEC/configs" -type f 2>/dev/null | wc -l | tr -d ' ')"
DB_COUNT="$(find "$DEC/databases" -type f 2>/dev/null | wc -l | tr -d ' ')"
BIN_COUNT="$(find "$DEC/binaries" -type f 2>/dev/null | wc -l | tr -d ' ')"
RTSP_FOUND="$(grep -c '^FOUND' "$CAM/rtsp_tests.tsv" 2>/dev/null || true)"
DNS_COUNT="$(wc -l < "$CLOUD/dns_index.tsv" 2>/dev/null || echo 0)"
REMOTE_COUNT="$(wc -l < "$CLOUD/remote_destinations.txt" 2>/dev/null || echo 0)"

if (( CRIT > 0 )); then LEVEL="CRITICAL"
elif (( HIGH > 0 )); then LEVEL="WEAK"
elif (( MED > 0 || WARN > 2 )); then LEVEL="MODERATE"
else LEVEL="STRONG"; fi

{
  echo "# GhostRedRecon NR8 Forensic Audit"
  echo
  echo "**Target:** $TARGET_IP"
  echo "**Run ID:** $RUN_ID"
  echo "**Script:** $SCRIPT_NAME"
  echo "**Version:** $VERSION"
  echo "**Level:** $LEVEL"
  echo "**Timestamp UTC:** $(ts)"
  echo
  echo "## What This Answers"
  echo "- Open ports: see \`02_surface/open_tcp.txt\` and \`02_surface/open_udp.txt\`"
  echo "- Data inside / exposed: see \`05_web_storage/\`, \`06_shares/\`, \`07_objects/\`, \`08_carving/\`, \`11_decoded/\`"
  echo "- Firmware: see \`09_firmware/\` if firmware input or exposed firmware was found"
  echo "- Chip indicators: see \`11_decoded/firmware_chip_indicators.txt\`"
  echo "- Streaming/video: see \`03_camera_protocols/rtsp_tests.tsv\`"
  echo "- Storage access: see \`05_web_storage/http_inventory.tsv\`, \`06_shares/\`, \`10_storage/\`"
  echo "- Encryption: see \`04_cloud_behavior/encryption_indicators.tsv\` and \`11_decoded/encryption_compression_indicators.txt\`"
  echo
  echo "## Summary"
  echo "- PASS: $PASS"
  echo "- WARN: $WARN"
  echo "- FAIL: $FAIL"
  echo "- SKIP: $SKIP"
  echo "- CRITICAL findings: $CRIT"
  echo "- HIGH findings: $HIGH"
  echo "- MEDIUM findings: $MED"
  echo "- RTSP streams found: $RTSP_FOUND"
  echo "- DNS rows observed: $DNS_COUNT"
  echo "- Remote destinations observed: $REMOTE_COUNT"
  echo
  echo "## Decoded Evidence Counts"
  echo "- Images: $IMG_COUNT"
  echo "- Text/web files: $TXT_COUNT"
  echo "- Config-like files: $CFG_COUNT"
  echo "- Databases: $DB_COUNT"
  echo "- Binaries/firmware-like files: $BIN_COUNT"
  echo
  echo "## Limitation"
  echo "This script does not bypass authentication, brute-force passwords, or break encryption. Encrypted data is reported as encrypted unless a key is available in collected evidence."
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

python3 - "$VERSION" "$TARGET_IP" "$RUN_ID" "$LEVEL" "$TESTS" "$FINDINGS" "$ARTIFACTS" "$IMG_COUNT" "$TXT_COUNT" "$CFG_COUNT" "$DB_COUNT" "$BIN_COUNT" "$RTSP_FOUND" "$DNS_COUNT" "$REMOTE_COUNT" > "$JSON" <<'PY'
import json, sys
from datetime import datetime, timezone
version,target,run_id,level,tests,findings,artifacts,img,txt,cfg,db,binc,rtsp,dns,remote=sys.argv[1:]

def read(path, keys):
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
  "tool":"GhostRedRecon NR8 Forensic Audit",
  "version":version,
  "target":target,
  "run_id":run_id,
  "level":level,
  "timestamp_utc":datetime.now(timezone.utc).isoformat(),
  "counts":{
    "images":int(img),
    "text_web_files":int(txt),
    "configs":int(cfg),
    "databases":int(db),
    "binaries":int(binc),
    "rtsp_streams_found":int(rtsp),
    "dns_rows":int(dns),
    "remote_destinations":int(remote)
  },
  "tests":read(tests,["time","stage","id","name","status","reason","evidence"]),
  "findings":read(findings,["time","severity","category","item","evidence"]),
  "artifacts":read(artifacts,["time","name","kind","size","sha256","mime","path","source"])
}, indent=2))
PY

artifact "$REPORT" "report" "markdown"
artifact "$JSON" "report" "json"

echo
echo "=== NR8 FORENSIC AUDIT COMPLETE ==="
echo "Level   : $LEVEL"
echo "Report  : $REPORT"
echo "JSON    : $JSON"
echo "Hashes  : $HASHES"
echo "Output  : $ROOT"
