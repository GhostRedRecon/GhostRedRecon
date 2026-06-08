#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "ERROR: run with bash: sudo bash ghost_nr7_camera_audit.sh"
  exit 1
fi

VERSION="NR7-CAMERA-AUDIT-1.0"

TARGET_IP="${TARGET_IP:-192.168.0.29}"
LAN_IFACE="${LAN_IFACE:-wlan0}"
CONFIRM_AUTH="${CONFIRM_AUTH:-NO}"
OUT_BASE="${OUT_BASE:-./evidence}"

CAPTURE_SECONDS="${CAPTURE_SECONDS:-180}"
MAX_BYTES="${MAX_BYTES:-10485760}"
TCP_PORTS="${TCP_PORTS:-1-65535}"
UDP_PORTS="${UDP_PORTS:-53,67,68,123,137,161,1900,5353,5683,54321}"
HTTP_PORTS="${HTTP_PORTS:-80 81 82 83 88 443 554 591 8000 8001 8008 8080 8081 8088 8090 8443 8554 8888 9000 9090 10000}"

FIRMWARE_FILE="${FIRMWARE_FILE:-}"
DISK_IMAGE="${DISK_IMAGE:-}"
EXTRA_INPUT_DIR="${EXTRA_INPUT_DIR:-}"
MOUNT_SCAN="${MOUNT_SCAN:-NO}"

if [[ "$CONFIRM_AUTH" != "YES" ]]; then
  echo "ERROR: Set CONFIRM_AUTH=YES for an owned/authorized device."
  echo "Example: CONFIRM_AUTH=YES TARGET_IP=192.168.0.29 LAN_IFACE=wlan0 sudo bash ghost_nr7_camera_audit.sh"
  exit 1
fi

RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="$OUT_BASE/NR7_CAMERA_${TARGET_IP}_${RUN_ID}"

mkdir -p "$ROOT"/{00_case,01_capture,02_surface,03_protocol,04_cloud,05_web,06_objects,07_carved,08_storage,09_firmware,10_decoded,11_reports,logs}

CASE="$ROOT/00_case"
CAP="$ROOT/01_capture"
SURF="$ROOT/02_surface"
PROTO="$ROOT/03_protocol"
CLOUD="$ROOT/04_cloud"
WEB="$ROOT/05_web"
OBJ="$ROOT/06_objects"
CARVED="$ROOT/07_carved"
STOR="$ROOT/08_storage"
FW="$ROOT/09_firmware"
DEC="$ROOT/10_decoded"
REP="$ROOT/11_reports"
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
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(ts)" "$(basename "$f")" "$kind" "$s" "$h" "$f" "$source" >> "$ARTIFACTS"
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

need=(bash nmap curl nc awk sed grep sha256sum file strings python3 ping xxd openssl)
missing=()
for x in "${need[@]}"; do have "$x" || missing+=("$x"); done
if (( ${#missing[@]} )); then
  echo "Missing required tools: ${missing[*]}"
  exit 1
fi

log "GhostRedRecon $VERSION"
log "Target: $TARGET_IP"
log "Output: $ROOT"

# ---------------- STAGE 0: CASE METADATA ----------------
{
  echo "tool=$VERSION"
  echo "target_ip=$TARGET_IP"
  echo "interface=$LAN_IFACE"
  echo "run_id=$RUN_ID"
  echo "operator=$(whoami)"
  echo "host=$(hostname)"
  echo "start_utc=$(ts)"
  echo "kernel=$(uname -a)"
  echo "scope=authorized IoT camera security audit"
} > "$CASE/case_metadata.txt"
artifact "$CASE/case_metadata.txt" "case_metadata" "system"
testlog "S0" "NR7-000" "Case metadata" "PASS" "Case metadata created" "$CASE/case_metadata.txt"

# ---------------- STAGE 1: BEHAVIOR CAPTURE ----------------
PCAP="$CAP/nr7_behavior_capture.pcap"
if have tcpdump; then
  testlog "S1" "NR7-100" "Behavior PCAP capture" "RUN" "Capture $CAPTURE_SECONDS seconds while camera/app is used" "$PCAP"
  timeout "$CAPTURE_SECONDS" tcpdump -i "$LAN_IFACE" host "$TARGET_IP" -w "$PCAP" > "$LOGS/tcpdump_stdout.log" 2>"$LOGS/tcpdump_stderr.log" || true
  if [[ -s "$PCAP" ]]; then
    artifact "$PCAP" "pcap" "tcpdump"
    testlog "S1" "NR7-100" "Behavior PCAP capture" "PASS" "PCAP captured" "$PCAP"
  else
    testlog "S1" "NR7-100" "Behavior PCAP capture" "WARN" "No packets captured" "$PCAP"
  fi
else
  testlog "S1" "NR7-100" "Behavior PCAP capture" "SKIP" "tcpdump not installed" "-"
fi

# ---------------- STAGE 2: LAN SURFACE ----------------
run_cmd "S2" "NR7-200" "Reachability ping" "$SURF/ping.txt" ping -c 3 -W 2 "$TARGET_IP"

run_cmd "S2" "NR7-210" "TCP full scan" "$SURF/nmap_tcp.txt" nmap -Pn -sT -p "$TCP_PORTS" --reason "$TARGET_IP"
grep -E '^[0-9]+/tcp[[:space:]]+open' "$SURF/nmap_tcp.txt" > "$SURF/open_tcp.txt" || true
artifact "$SURF/open_tcp.txt" "index" "open tcp"

run_cmd "S2" "NR7-220" "UDP selected scan" "$SURF/nmap_udp.txt" nmap -Pn -sU -p "$UDP_PORTS" --reason "$TARGET_IP"
grep -E '^[0-9]+/udp[[:space:]]+(open|open\|filtered)' "$SURF/nmap_udp.txt" > "$SURF/open_udp.txt" || true
artifact "$SURF/open_udp.txt" "index" "open udp"

run_cmd "S2" "NR7-230" "Service/version fingerprint" "$SURF/nmap_services.txt" nmap -Pn -sV --version-all "$TARGET_IP"

TCP_OPEN="$(wc -l < "$SURF/open_tcp.txt" | tr -d ' ')"
UDP_OPEN="$(wc -l < "$SURF/open_udp.txt" | tr -d ' ')"
[[ "$TCP_OPEN" -gt 0 ]] && finding "MEDIUM" "LAN exposure" "$TCP_OPEN open TCP ports" "$SURF/open_tcp.txt"
[[ "$UDP_OPEN" -gt 0 ]] && finding "LOW" "UDP exposure" "$UDP_OPEN UDP open/open-filtered ports" "$SURF/open_udp.txt"

# ---------------- STAGE 3: PROTOCOL + ENCRYPTION ----------------
if have tshark && [[ -s "$PCAP" ]]; then
  run_cmd "S3" "NR7-300" "Protocol hierarchy" "$PROTO/protocol_hierarchy.txt" tshark -r "$PCAP" -q -z io,phs
  run_cmd "S3" "NR7-301" "Conversation map" "$PROTO/conversations.txt" tshark -r "$PCAP" -q -z conv,tcp -z conv,udp
  run_cmd "S3" "NR7-302" "Flow index" "$PROTO/flow_index.tsv" tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP" -T fields -e frame.time -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info

  tshark -r "$PCAP" -Y "tls || ssl || quic || tcp.port==443 || udp.port==443" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info > "$PROTO/encryption_indicators.tsv" 2>/dev/null || true
  artifact "$PROTO/encryption_indicators.tsv" "encryption_index" "tshark"
  if [[ -s "$PROTO/encryption_indicators.tsv" ]]; then
    finding "INFO" "Encryption observed" "TLS/SSL/QUIC/443 traffic seen" "$PROTO/encryption_indicators.tsv"
    testlog "S3" "NR7-303" "Encryption detection" "PASS" "Encrypted transport indicators found" "$PROTO/encryption_indicators.tsv"
  else
    finding "MEDIUM" "Encryption not observed" "No TLS/SSL/QUIC/443 indicators in capture window" "$PROTO/encryption_indicators.tsv"
    testlog "S3" "NR7-303" "Encryption detection" "WARN" "No encrypted transport indicators in this capture" "$PROTO/encryption_indicators.tsv"
  fi

  tshark -r "$PCAP" -Y "http || ftp || telnet || data-text-lines" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info > "$PROTO/plaintext_indicators.tsv" 2>/dev/null || true
  artifact "$PROTO/plaintext_indicators.tsv" "plaintext_index" "tshark"
  [[ -s "$PROTO/plaintext_indicators.tsv" ]] && finding "HIGH" "Plaintext indicator" "HTTP/FTP/Telnet/text-like traffic found" "$PROTO/plaintext_indicators.tsv"

  tshark -r "$PCAP" -Y "dns" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.a -e dns.aaaa -e dns.resp.name > "$CLOUD/dns_index.tsv" 2>/dev/null || true
  artifact "$CLOUD/dns_index.tsv" "dns_index" "tshark"
  if [[ -s "$CLOUD/dns_index.tsv" ]]; then
    finding "INFO" "DNS behavior" "Device-related DNS observed" "$CLOUD/dns_index.tsv"
    testlog "S4" "NR7-400" "DNS/cloud behavior" "PASS" "DNS/cloud index created" "$CLOUD/dns_index.tsv"
  else
    testlog "S4" "NR7-400" "DNS/cloud behavior" "INFO" "No DNS observed in capture window" "$CLOUD/dns_index.tsv"
  fi

  tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP" -T fields -e ip.dst -e ipv6.dst | grep -v '^$' | sort -u > "$CLOUD/remote_ip_index.txt" 2>/dev/null || true
  artifact "$CLOUD/remote_ip_index.txt" "remote_ip_index" "tshark"
  REMOTE_COUNT="$(wc -l < "$CLOUD/remote_ip_index.txt" | tr -d ' ')"
  [[ "$REMOTE_COUNT" -gt 0 ]] && finding "INFO" "Remote communication" "$REMOTE_COUNT unique remote destinations observed" "$CLOUD/remote_ip_index.txt"

  mkdir -p "$OBJ/http" "$OBJ/smb" "$OBJ/tftp" "$OBJ/imf"
  tshark -Q -r "$PCAP" --export-objects "http,$OBJ/http" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "smb,$OBJ/smb" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "tftp,$OBJ/tftp" 2>/dev/null || true
  tshark -Q -r "$PCAP" --export-objects "imf,$OBJ/imf" 2>/dev/null || true
  find "$OBJ" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "pcap_exported_object" "tshark export"; done
  testlog "S3" "NR7-304" "PCAP object export" "PASS" "HTTP/SMB/TFTP/IMF object export attempted" "$OBJ"

  tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP && data.data" -T fields -e data.data > "$PROTO/raw_payload_hex.txt" 2>/dev/null || true
  artifact "$PROTO/raw_payload_hex.txt" "raw_payload_hex" "tshark"
  mkdir -p "$PROTO/raw_payloads"
  i=0
  while read -r line; do
    [[ -z "$line" ]] && continue
    echo "$line" | xxd -r -p > "$PROTO/raw_payloads/payload_${i}.bin" 2>/dev/null || true
    artifact "$PROTO/raw_payloads/payload_${i}.bin" "raw_payload_bin" "pcap data"
    i=$((i+1))
  done < "$PROTO/raw_payload_hex.txt"
else
  testlog "S3" "NR7-300" "Protocol analysis" "SKIP" "tshark missing or no PCAP" "-"
fi

# ---------------- STAGE 5: WEB/LOCAL FILE EXPOSURE ----------------
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
/download
/download/
/backup
/backup/
/backups/
/data
/data/
/logs/
/tmp/
/upload/
/uploads/
/sdcard/
/mnt/
/storage/
/config
/config/
/config.json
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
/proc/mounts
/var/log/messages
/db/
/database/
/sqlite.db
/data.db
/config.db
/users.db
/camera.db
/miio.db
/snapshot.jpg
/image.jpg
/current.jpg
/video
/stream
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
  code="$(curl -k -sS -L --max-time 6 --connect-timeout 4 --range "0-$MAX_BYTES" -D "$h" -o "$b" -w "%{http_code}" "$url" 2>/dev/null || true)"
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

while read -r p; do
  [[ -z "$p" ]] && continue
  for port in $HTTP_PORTS; do
    fetch_url "http://$TARGET_IP:$port$p"
    [[ "$port" == "443" || "$port" == "8443" ]] && fetch_url "https://$TARGET_IP:$port$p"
  done
done < "$WEB/paths.txt"

artifact "$WEB/http_inventory.tsv" "http_inventory" "curl"
HTTP_OK="$(awk -F'\t' '$1=="200" || $1=="206"{c++} END{print c+0}' "$WEB/http_inventory.tsv")"
if [[ "$HTTP_OK" -gt 0 ]]; then
  finding "HIGH" "HTTP exposed objects" "$HTTP_OK HTTP objects accessible" "$WEB/http_inventory.tsv"
  testlog "S5" "NR7-500" "HTTP local file exposure" "FAIL" "$HTTP_OK HTTP objects returned 200/206" "$WEB/http_inventory.tsv"
else
  testlog "S5" "NR7-500" "HTTP local file exposure" "PASS" "No HTTP objects returned 200/206" "$WEB/http_inventory.tsv"
fi

# ---------------- STAGE 6: CARVING ----------------
if have foremost && [[ -s "$PCAP" ]]; then
  mkdir -p "$CARVED/foremost_pcap"
  foremost -i "$PCAP" -o "$CARVED/foremost_pcap" > "$LOGS/foremost_pcap.log" 2>&1 || true
  artifact "$LOGS/foremost_pcap.log" "foremost_log" "pcap"
  find "$CARVED/foremost_pcap" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "carved_file" "foremost pcap"; done
  testlog "S6" "NR7-600" "Foremost PCAP carving" "PASS" "File carving completed" "$CARVED/foremost_pcap"
else
  testlog "S6" "NR7-600" "Foremost PCAP carving" "SKIP" "foremost missing or no PCAP" "-"
fi

if have bulk_extractor && [[ -s "$PCAP" ]]; then
  mkdir -p "$CARVED/bulk_pcap"
  bulk_extractor -o "$CARVED/bulk_pcap" "$PCAP" > "$LOGS/bulk_pcap.log" 2>&1 || true
  artifact "$LOGS/bulk_pcap.log" "bulk_extractor_log" "pcap"
  find "$CARVED/bulk_pcap" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "bulk_feature_file" "bulk_extractor pcap"; done
  testlog "S6" "NR7-610" "bulk_extractor PCAP scan" "PASS" "bulk_extractor completed" "$CARVED/bulk_pcap"
else
  testlog "S6" "NR7-610" "bulk_extractor PCAP scan" "SKIP" "bulk_extractor missing or no PCAP" "-"
fi

# ---------------- STAGE 7: STORAGE / FIRMWARE INPUTS ----------------
run_cmd "S7" "NR7-700" "Local block device inventory" "$STOR/local_block_devices.txt" lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,SERIAL,MOUNTPOINTS

if [[ "$MOUNT_SCAN" == "YES" ]]; then
  run_cmd "S7" "NR7-701" "Mounted filesystem inventory" "$STOR/mounted_filesystems.txt" findmnt
  find /media /mnt -maxdepth 5 -type f 2>/dev/null > "$STOR/media_mnt_file_index.txt" || true
  artifact "$STOR/media_mnt_file_index.txt" "storage_index" "/media /mnt"
  testlog "S7" "NR7-702" "Mounted media file index" "PASS" "Indexed mounted /media and /mnt files" "$STOR/media_mnt_file_index.txt"
else
  testlog "S7" "NR7-702" "Mounted media file index" "SKIP" "Set MOUNT_SCAN=YES to index locally mounted SD/USB/SSD media" "-"
fi

if [[ -n "$DISK_IMAGE" && -f "$DISK_IMAGE" ]]; then
  cp "$DISK_IMAGE" "$STOR/input_disk_image.bin"
  artifact "$STOR/input_disk_image.bin" "disk_image" "$DISK_IMAGE"
  have mmls && run_cmd "S7" "NR7-710" "Disk partition map" "$STOR/mmls.txt" mmls "$STOR/input_disk_image.bin"
  have fsstat && run_cmd "S7" "NR7-711" "Filesystem stats" "$STOR/fsstat.txt" fsstat "$STOR/input_disk_image.bin"
  have fls && run_cmd "S7" "NR7-712" "Filesystem listing" "$STOR/fls_recursive.txt" fls -r -p "$STOR/input_disk_image.bin"
else
  testlog "S7" "NR7-710" "Disk image forensic audit" "SKIP" "No DISK_IMAGE provided" "-"
fi

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
  grep -RInaE 'password|passwd|token|secret|api[_-]?key|credential|ssid|psk|BEGIN RSA|BEGIN OPENSSH|PRIVATE KEY|root:' "$FW" > "$FW/firmware_secret_hits.txt" 2>/dev/null || true
  artifact "$FW/firmware_secret_hits.txt" "firmware_secret_hits" "grep"
  [[ -s "$FW/firmware_secret_hits.txt" ]] && finding "CRITICAL" "Firmware secret indicators" "Secret-like strings found in firmware" "$FW/firmware_secret_hits.txt"
  testlog "S7" "NR7-720" "Firmware audit" "PASS" "Firmware analysis completed" "$FW"
else
  testlog "S7" "NR7-720" "Firmware audit" "SKIP" "No FIRMWARE_FILE provided" "-"
fi

if [[ -n "$EXTRA_INPUT_DIR" && -d "$EXTRA_INPUT_DIR" ]]; then
  mkdir -p "$STOR/extra_input_copy"
  cp -a "$EXTRA_INPUT_DIR"/. "$STOR/extra_input_copy/" 2>/dev/null || true
  find "$STOR/extra_input_copy" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "extra_input_file" "$EXTRA_INPUT_DIR"; done
  testlog "S7" "NR7-730" "Extra input directory" "PASS" "Extra input copied and indexed" "$STOR/extra_input_copy"
else
  testlog "S7" "NR7-730" "Extra input directory" "SKIP" "No EXTRA_INPUT_DIR provided" "-"
fi

# ---------------- STAGE 8: DECODE / CLASSIFY EVERYTHING ----------------
mkdir -p "$DEC"/{images,text,configs,databases,binaries,archives,certs,keys,unknown}
: > "$DEC/file_type_inventory.tsv"
: > "$DEC/strings_index.txt"
: > "$DEC/secret_hits.txt"
: > "$DEC/encryption_or_compression_indicators.txt"

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

    strings "$f" 2>/dev/null | head -n 250 >> "$DEC/strings_index.txt" || true
    strings "$f" 2>/dev/null | grep -iE 'password|passwd|token|secret|api[_-]?key|credential|ssid|psk|BEGIN RSA|BEGIN OPENSSH|PRIVATE KEY|root:' >> "$DEC/secret_hits.txt" || true
    strings "$f" 2>/dev/null | grep -iE 'encrypted|cipher|aes|rsa|ecdsa|tls|ssl|certificate|BEGIN CERTIFICATE|salted|openssl|gzip|xz|lzma|zip|squashfs' >> "$DEC/encryption_or_compression_indicators.txt" || true
done

artifact "$DEC/file_type_inventory.tsv" "classification" "file"
artifact "$DEC/strings_index.txt" "classification" "strings"
artifact "$DEC/secret_hits.txt" "classification" "secrets"
artifact "$DEC/encryption_or_compression_indicators.txt" "classification" "crypto_compression"
find "$DEC" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f" "decoded_artifact" "classification"; done

[[ -s "$DEC/secret_hits.txt" ]] && finding "CRITICAL" "Secret indicators" "Secret-like strings found in decoded evidence" "$DEC/secret_hits.txt"
[[ -s "$DEC/encryption_or_compression_indicators.txt" ]] && finding "INFO" "Encryption/compression indicators" "Crypto/compression indicators found; decryption requires keys" "$DEC/encryption_or_compression_indicators.txt"

have ent && find "$DEC" -type f -size +1k -exec sh -c 'echo "===== $1 ====="; ent "$1" 2>/dev/null' _ {} \; > "$DEC/entropy_report.txt" || true
[[ -f "$DEC/entropy_report.txt" ]] && artifact "$DEC/entropy_report.txt" "entropy_report" "ent"

have jq && find "$DEC/text" "$DEC/configs" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do jq . "$f" > "$f.pretty.json" 2>/dev/null && artifact "$f.pretty.json" "decoded_json" "$f" || true; done
have exiftool && exiftool -r "$DEC/images" > "$DEC/image_exif_report.txt" 2>/dev/null && artifact "$DEC/image_exif_report.txt" "image_metadata" "exiftool" || true
have sqlite3 && find "$DEC/databases" -type f -print0 2>/dev/null | while IFS= read -r -d '' db; do out="$DEC/sqlite_$(safe "$(basename "$db")").schema.txt"; sqlite3 "$db" ".schema" > "$out" 2>/dev/null && artifact "$out" "sqlite_schema" "$db" || true; done

testlog "S8" "NR7-800" "Decode and classify artifacts" "PASS" "All collected artifacts classified" "$DEC"

# ---------------- FINAL REPORT ----------------
PASS="$(awk -F'\t' '$5=="PASS"{c++} END{print c+0}' "$TESTS")"
WARN="$(awk -F'\t' '$5=="WARN"{c++} END{print c+0}' "$TESTS")"
FAIL="$(awk -F'\t' '$5=="FAIL"{c++} END{print c+0}' "$TESTS")"
SKIP="$(awk -F'\t' '$5=="SKIP"{c++} END{print c+0}' "$TESTS")"
CRIT="$(awk -F'\t' '$2=="CRITICAL"{c++} END{print c+0}' "$FINDINGS")"
HIGH="$(awk -F'\t' '$2=="HIGH"{c++} END{print c+0}' "$FINDINGS")"
MED="$(awk -F'\t' '$2=="MEDIUM"{c++} END{print c+0}' "$FINDINGS")"

if (( CRIT > 0 )); then LEVEL="CRITICAL"
elif (( HIGH > 0 )); then LEVEL="WEAK"
elif (( MED > 0 || WARN > 2 )); then LEVEL="MODERATE"
else LEVEL="STRONG"; fi

IMG_COUNT="$(find "$DEC/images" -type f 2>/dev/null | wc -l | tr -d ' ')"
TXT_COUNT="$(find "$DEC/text" -type f 2>/dev/null | wc -l | tr -d ' ')"
CFG_COUNT="$(find "$DEC/configs" -type f 2>/dev/null | wc -l | tr -d ' ')"
DB_COUNT="$(find "$DEC/databases" -type f 2>/dev/null | wc -l | tr -d ' ')"
BIN_COUNT="$(find "$DEC/binaries" -type f 2>/dev/null | wc -l | tr -d ' ')"
DNS_COUNT="$(wc -l < "$CLOUD/dns_index.tsv" 2>/dev/null || echo 0)"
REMOTE_COUNT="$(wc -l < "$CLOUD/remote_ip_index.txt" 2>/dev/null || echo 0)"

{
  echo "# GhostRedRecon NR7 Camera Security Audit"
  echo
  echo "**Target:** $TARGET_IP"
  echo "**Run ID:** $RUN_ID"
  echo "**Version:** $VERSION"
  echo "**Level:** $LEVEL"
  echo "**Timestamp UTC:** $(ts)"
  echo
  echo "## Scope"
  echo "Authorized IoT camera audit for LAN exposure, behavioral/cloud traffic, encryption indicators, exposed files, PCAP objects, carved artifacts, optional storage images, and optional firmware."
  echo
  echo "## Important Limitation"
  echo "Encrypted data can only be decoded when keys are available. This engine detects encryption, exports cleartext objects if present, extracts exposed keys if found, and reports encrypted/no-key conditions."
  echo
  echo "## Summary"
  echo "- PASS: $PASS"
  echo "- WARN: $WARN"
  echo "- FAIL: $FAIL"
  echo "- SKIP: $SKIP"
  echo "- CRITICAL findings: $CRIT"
  echo "- HIGH findings: $HIGH"
  echo "- MEDIUM findings: $MED"
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
  echo "## Tests"
  echo "| Time | Stage | ID | Test | Status | Reason | Evidence |"
  echo "|---|---|---|---|---:|---|---|"
  awk -F'\t' '{printf("| %s | %s | %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7)}' "$TESTS"
  echo
  echo "## Findings"
  echo "| Time | Severity | Category | Item | Evidence |"
  echo "|---|---|---|---|---|"
  awk -F'\t' '{printf("| %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5)}' "$FINDINGS"
  echo
  echo "## Evidence Locations"
  echo "- Case metadata: \`00_case/\`"
  echo "- PCAP: \`01_capture/nr7_behavior_capture.pcap\`"
  echo "- LAN surface: \`02_surface/\`"
  echo "- Protocol/encryption: \`03_protocol/\`"
  echo "- Cloud/DNS behavior: \`04_cloud/\`"
  echo "- Web exposure: \`05_web/\`"
  echo "- Exported PCAP objects: \`06_objects/\`"
  echo "- Carved artifacts: \`07_carved/\`"
  echo "- Storage/firmware inputs: \`08_storage/\`, \`09_firmware/\`"
  echo "- Decoded files: \`10_decoded/\`"
  echo "- SHA256 manifest: \`11_reports/sha256_manifest.txt\`"
} > "$REPORT"

python3 - "$VERSION" "$TARGET_IP" "$RUN_ID" "$LEVEL" "$TESTS" "$FINDINGS" "$ARTIFACTS" "$IMG_COUNT" "$TXT_COUNT" "$CFG_COUNT" "$DB_COUNT" "$BIN_COUNT" > "$JSON" <<'PY'
import json, sys
from datetime import datetime, timezone

version,target,run_id,level,tests,findings,artifacts,img,txt,cfg,db,binc=sys.argv[1:]

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
  "tool":"GhostRedRecon NR7 Camera Audit",
  "version":version,
  "target":target,
  "run_id":run_id,
  "level":level,
  "timestamp_utc":datetime.now(timezone.utc).isoformat(),
  "decoded_counts":{
    "images":int(img),
    "text_web_files":int(txt),
    "configs":int(cfg),
    "databases":int(db),
    "binaries":int(binc)
c  },
  "tests":read(tests,["time","stage","id","name","status","reason","evidence"]),
  "findings":read(findings,["time","severity","category","item","evidence"]),
  "artifacts":read(artifacts,["time","name","kind","size","sha256","path","source"])
}, indent=2))
PY

artifact "$REPORT" "report" "markdown"
artifact "$JSON" "report" "json"

echo
echo "=== NR7 CAMERA AUDIT COMPLETE ==="
echo "Level   : $LEVEL"
echo "Report  : $REPORT"
echo "JSON    : $JSON"
echo "Hashes  : $HASHES"
echo "Output  : $ROOT"
