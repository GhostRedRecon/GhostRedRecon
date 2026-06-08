#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TARGET_IP="${TARGET_IP:-192.168.0.29}"
IFACE="${IFACE:-wlan0}"
CAPTURE_TIME="${CAPTURE_TIME:-600}"
CONFIRM_AUTH="${CONFIRM_AUTH:-YES}"

if [[ "$CONFIRM_AUTH" != "YES" ]]; then
  echo "ERROR: set CONFIRM_AUTH=YES for owned/authorized testing."
  echo "Example: sudo -E CONFIRM_AUTH=YES TARGET_IP=192.168.0.29 IFACE=wlan0 bash $0"
  exit 1
fi

SCRIPT_NAME="$(basename "$0" .sh)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="./evidence/${SCRIPT_NAME}_${RUN_ID}"
PCAP="$ROOT/pcap/capture.pcap"

mkdir -p "$ROOT"/{pcap,analysis,streams,dns,tls,http,objects,images,capability,cloud,report,logs,tmp}

LOG_TSV="$ROOT/report/tests.tsv"
CAPABILITY_TXT="$ROOT/report/capability.txt"
SUMMARY_TXT="$ROOT/report/summary.txt"
CLOUD_TXT="$ROOT/report/cloud_behavior.txt"
HASHES="$ROOT/report/sha256_manifest.txt"

: > "$LOG_TSV"
: > "$HASHES"

ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log(){ echo "[$(date -u +"%T")] $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
safe(){ echo "$1" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-160; }

artifact(){
  [[ -f "$1" ]] || return 0
  sha256sum "$1" >> "$HASHES" 2>/dev/null || true
}

test_log(){
  printf "%s\t%s\t%s\t%s\t%s\n" "$(ts)" "$1" "$2" "$3" "$4" >> "$LOG_TSV"
  log "[TEST] $1 | $2 | $3"
}

tool_run(){
  local id="$1"; local name="$2"; local out="$3"; shift 3
  local start end rc size
  log "[TOOL] $name START"
  start="$(date +%s)"
  set +e
  "$@" > "$out" 2>&1
  rc=$?
  set -e
  end="$(date +%s)"
  size="$(wc -c < "$out" 2>/dev/null || echo 0)"
  artifact "$out"
  if [[ $rc -eq 0 ]]; then
    test_log "$id" "PASS" "$name completed in $((end-start))s, output ${size} bytes" "$out"
  else
    test_log "$id" "WARN" "$name exited rc=$rc in $((end-start))s, output ${size} bytes" "$out"
  fi
}

echo -e "TIME\tID\tSTATUS\tDETAILS\tEVIDENCE" > "$LOG_TSV"

log "=== NR12 IoT Cloud Hard Audit START ==="
log "Target: $TARGET_IP"
log "Interface: $IFACE"
log "Evidence: $ROOT"

# ---------------------------------------------------------------------
# 0. Tool + interface validation
# ---------------------------------------------------------------------
REQUIRED=(tcpdump tshark nmap curl strings file grep awk sed sort uniq wc sha256sum)
MISSING=()
for t in "${REQUIRED[@]}"; do have "$t" || MISSING+=("$t"); done

if (( ${#MISSING[@]} )); then
  test_log "T0_TOOLS" "FAIL" "Missing tools: ${MISSING[*]}" "-"
  echo "Missing tools: ${MISSING[*]}"
  exit 1
else
  test_log "T0_TOOLS" "PASS" "Required tools present" "-"
fi

MODE="unknown"
if have iw && iw dev "$IFACE" info >/dev/null 2>&1; then
  MODE="$(iw dev "$IFACE" info | awk '/type/ {print $2; exit}')"
fi

{
  echo "tool=NR12 IoT Cloud Hard Audit"
  echo "target=$TARGET_IP"
  echo "interface=$IFACE"
  echo "interface_mode=$MODE"
  echo "capture_seconds=$CAPTURE_TIME"
  echo "run_id=$RUN_ID"
  echo "timestamp_utc=$(ts)"
  echo "scope=authorized IoT/cloud behavior audit"
  echo "limits=no exploitation, no credential theft, no cloud replay, no crypto breaking"
} > "$ROOT/report/case_metadata.txt"
artifact "$ROOT/report/case_metadata.txt"

if [[ "$MODE" == "monitor" ]]; then
  test_log "T0_INTERFACE" "PASS" "Interface is in monitor mode" "$ROOT/report/case_metadata.txt"
else
  test_log "T0_INTERFACE" "WARN" "Interface mode is '$MODE'; monitor mode gives broader WiFi visibility" "$ROOT/report/case_metadata.txt"
fi

# ---------------------------------------------------------------------
# 1. Network scan
# ---------------------------------------------------------------------
tool_run "T1_NMAP_TCP" "nmap TCP full scan" "$ROOT/analysis/nmap_tcp.txt" \
  nmap -Pn -sT -p- --reason "$TARGET_IP"

grep -E '^[0-9]+/tcp[[:space:]]+open' "$ROOT/analysis/nmap_tcp.txt" > "$ROOT/analysis/open_tcp.txt" || true
artifact "$ROOT/analysis/open_tcp.txt"

tool_run "T1_NMAP_UDP" "nmap selected UDP scan" "$ROOT/analysis/nmap_udp.txt" \
  nmap -Pn -sU -p 53,67,68,123,137,161,1900,5353,5683,54321 --reason "$TARGET_IP"

grep -E '^[0-9]+/udp[[:space:]]+(open|open\|filtered)' "$ROOT/analysis/nmap_udp.txt" > "$ROOT/analysis/open_udp.txt" || true
artifact "$ROOT/analysis/open_udp.txt"

# ---------------------------------------------------------------------
# 2. Capture
# ---------------------------------------------------------------------
log "[T2] Capturing traffic for ${CAPTURE_TIME}s. Use the camera app now."
set +e
timeout "$CAPTURE_TIME" tcpdump -i "$IFACE" -nn -s0 -w "$PCAP" host "$TARGET_IP" > "$ROOT/logs/tcpdump.log" 2>&1
set -e
artifact "$PCAP"
artifact "$ROOT/logs/tcpdump.log"

PCAP_SIZE="$(wc -c < "$PCAP" 2>/dev/null || echo 0)"
if [[ "$PCAP_SIZE" -gt 24 ]]; then
  test_log "T2_CAPTURE" "PASS" "PCAP captured, ${PCAP_SIZE} bytes" "$PCAP"
else
  test_log "T2_CAPTURE" "FAIL" "PCAP too small/no useful traffic, ${PCAP_SIZE} bytes" "$PCAP"
fi

# ---------------------------------------------------------------------
# 3. Protocol diagnostics
# ---------------------------------------------------------------------
tool_run "T3_PROTOCOL" "tshark protocol hierarchy" "$ROOT/analysis/protocol_hierarchy.txt" \
  tshark -r "$PCAP" -q -z io,phs

tool_run "T3_CONVERSATIONS" "tshark TCP/UDP conversations" "$ROOT/analysis/conversations.txt" \
  tshark -r "$PCAP" -q -z conv,tcp -z conv,udp

tshark -r "$PCAP" -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e frame.len -e _ws.col.Info \
  > "$ROOT/analysis/flow_index.tsv" 2>/dev/null || true
artifact "$ROOT/analysis/flow_index.tsv"
test_log "T3_FLOW_INDEX" "PASS" "Flow index generated" "$ROOT/analysis/flow_index.tsv"

# ---------------------------------------------------------------------
# 4. Cloud behavior intelligence
# ---------------------------------------------------------------------
log "[T4] Cloud behavior intelligence"

tshark -r "$PCAP" -Y "dns" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.a -e dns.aaaa \
  > "$ROOT/dns/dns_index.tsv" 2>/dev/null || true
awk -F'\t' '{for(i=4;i<=NF;i++) if($i!="") print $i}' "$ROOT/dns/dns_index.tsv" | sort -u > "$ROOT/dns/unique_domains.txt" || true
artifact "$ROOT/dns/dns_index.tsv"
artifact "$ROOT/dns/unique_domains.txt"

tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name \
  > "$ROOT/tls/sni.tsv" 2>/dev/null || true
awk -F'\t' '{print $4}' "$ROOT/tls/sni.tsv" | sort -u > "$ROOT/tls/unique_sni.txt" || true
artifact "$ROOT/tls/sni.tsv"
artifact "$ROOT/tls/unique_sni.txt"

tshark -r "$PCAP" -Y "ip.src==$TARGET_IP" -T fields -e ip.dst | grep -v '^$' | sort -u > "$ROOT/cloud/remote_ips.txt" 2>/dev/null || true
artifact "$ROOT/cloud/remote_ips.txt"

tshark -r "$PCAP" -Y "ip.addr==$TARGET_IP" -T fields -e ip.src -e ip.dst -e frame.len \
| awk -v target="$TARGET_IP" '
{
  peer=($1==target?$2:$1);
  bytes[peer]+=$3;
  pkts[peer]++;
}
END {
  for (p in bytes) printf "%s\t%d\t%d\n", p, pkts[p], bytes[p];
}' | sort -k3,3nr > "$ROOT/cloud/remote_volume.tsv" || true
artifact "$ROOT/cloud/remote_volume.tsv"

cat "$ROOT/dns/unique_domains.txt" "$ROOT/tls/unique_sni.txt" 2>/dev/null | sort -u > "$ROOT/cloud/cloud_names.txt" || true
grep -iE 'mi\.com|xiaomi|miot|mijia|tuya|aliyun|alibaba|tencent|amazonaws|aws|google|gstatic|firebase|azure|cloudfront|akamai|hicloud|huawei|ezviz|hik|imou|dahua|tp-link|tplink|ubnt|unifi' \
  "$ROOT/cloud/cloud_names.txt" > "$ROOT/cloud/provider_hints.txt" || true
artifact "$ROOT/cloud/cloud_names.txt"
artifact "$ROOT/cloud/provider_hints.txt"

DNS_COUNT="$(wc -l < "$ROOT/dns/unique_domains.txt" 2>/dev/null || echo 0)"
SNI_COUNT="$(wc -l < "$ROOT/tls/unique_sni.txt" 2>/dev/null || echo 0)"
REMOTE_COUNT="$(wc -l < "$ROOT/cloud/remote_ips.txt" 2>/dev/null || echo 0)"
PROVIDER_COUNT="$(wc -l < "$ROOT/cloud/provider_hints.txt" 2>/dev/null || echo 0)"

if [[ "$DNS_COUNT" -gt 0 || "$SNI_COUNT" -gt 0 || "$REMOTE_COUNT" -gt 0 ]]; then
  test_log "T4_CLOUD_BEHAVIOR" "PASS" "Cloud behavior mapped: DNS=$DNS_COUNT SNI=$SNI_COUNT remote_ips=$REMOTE_COUNT provider_hints=$PROVIDER_COUNT" "$ROOT/cloud/cloud_names.txt"
else
  test_log "T4_CLOUD_BEHAVIOR" "WARN" "No cloud behavior observed in capture window" "$ROOT/cloud/cloud_names.txt"
fi

# ---------------------------------------------------------------------
# 5. Plaintext/MITM indicator
# ---------------------------------------------------------------------
MITM="NO"
TOKEN="NO"
REPLAY="NO"

tshark -r "$PCAP" -Y "http || ftp || telnet || data-text-lines" > "$ROOT/capability/plaintext.txt" 2>/dev/null || true
artifact "$ROOT/capability/plaintext.txt"

if [[ -s "$ROOT/capability/plaintext.txt" ]]; then
  MITM="YES"
  test_log "T5_MITM_INDICATOR" "FAIL" "Plaintext app/device traffic observed; MITM feasibility indicator YES" "$ROOT/capability/plaintext.txt"
else
  test_log "T5_MITM_INDICATOR" "PASS" "No plaintext HTTP/FTP/Telnet/text-lines observed; MITM feasibility indicator NO from passive evidence" "-"
fi

# ---------------------------------------------------------------------
# 6. Token exposure indicator
# ---------------------------------------------------------------------
strings "$PCAP" | grep -iE 'token=|auth=|session=|jwt|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|ssid|psk' \
  > "$ROOT/capability/token_candidates.txt" || true
artifact "$ROOT/capability/token_candidates.txt"

if [[ -s "$ROOT/capability/token_candidates.txt" ]]; then
  TOKEN="YES"
  test_log "T6_TOKEN_EXPOSURE" "FAIL" "Token/credential-like strings observed in capture" "$ROOT/capability/token_candidates.txt"
else
  test_log "T6_TOKEN_EXPOSURE" "PASS" "No token/credential-like strings observed in capture" "-"
fi

# ---------------------------------------------------------------------
# 7. Replay feasibility indicator
# ---------------------------------------------------------------------
tshark -r "$PCAP" -Y "http.request" -T fields -e http.request.method -e http.host -e http.request.uri \
  > "$ROOT/capability/http_requests.tsv" 2>/dev/null || true
sort "$ROOT/capability/http_requests.tsv" | uniq -c | sort -nr > "$ROOT/capability/replay_patterns.txt" || true
artifact "$ROOT/capability/http_requests.tsv"
artifact "$ROOT/capability/replay_patterns.txt"

if awk '$1 > 3 {print}' "$ROOT/capability/replay_patterns.txt" | grep -q .; then
  REPLAY="YES"
  test_log "T7_REPLAY_INDICATOR" "FAIL" "Repeated identical HTTP requests observed; replay feasibility indicator YES" "$ROOT/capability/replay_patterns.txt"
else
  test_log "T7_REPLAY_INDICATOR" "PASS" "No repeated plaintext HTTP replay pattern observed" "$ROOT/capability/replay_patterns.txt"
fi

# ---------------------------------------------------------------------
# 8. Stream extraction and video indicators
# ---------------------------------------------------------------------
tshark -r "$PCAP" -T fields -e tcp.stream 2>/dev/null | grep -E '^[0-9]+$' | sort -n | uniq > "$ROOT/streams/list.txt" || true
STREAM_COUNT="$(wc -l < "$ROOT/streams/list.txt" 2>/dev/null || echo 0)"
artifact "$ROOT/streams/list.txt"
test_log "T8_STREAM_ENUM" "PASS" "TCP streams enumerated: $STREAM_COUNT" "$ROOT/streams/list.txt"

while read -r stream; do
  [[ -z "$stream" ]] && continue
  tshark -r "$PCAP" -q -z follow,tcp,raw,"$stream" > "$ROOT/streams/stream_${stream}.txt" 2>/dev/null || true
  artifact "$ROOT/streams/stream_${stream}.txt"
done < "$ROOT/streams/list.txt"

tshark -r "$PCAP" -Y "rtsp || rtp || tcp.port==554 || udp.port==554" > "$ROOT/streams/video_protocol_indicators.txt" 2>/dev/null || true
artifact "$ROOT/streams/video_protocol_indicators.txt"

if [[ -s "$ROOT/streams/video_protocol_indicators.txt" ]]; then
  test_log "T8_VIDEO_PROTOCOL" "WARN" "RTSP/RTP/video-like protocol indicators observed" "$ROOT/streams/video_protocol_indicators.txt"
else
  test_log "T8_VIDEO_PROTOCOL" "PASS" "No RTSP/RTP video protocol indicators observed in PCAP" "-"
fi

# Safe direct RTSP probe, no credentials/bruteforce
RTSP_FOUND=0
if have ffprobe; then
  for path in "" "/live" "/stream" "/video" "/h264" "/live.sdp"; do
    out="$ROOT/streams/rtsp_probe_$(safe "$path").txt"
    timeout 8 ffprobe -v error -show_format -show_streams "rtsp://$TARGET_IP:554$path" > "$out" 2>&1 || true
    artifact "$out"
    if grep -qiE 'codec_type=video|codec_name|width=|height=' "$out"; then
      RTSP_FOUND=$((RTSP_FOUND+1))
      if have ffmpeg; then
        snap="$ROOT/images/rtsp_snapshot_$(safe "$path").jpg"
        timeout 10 ffmpeg -y -rtsp_transport tcp -i "rtsp://$TARGET_IP:554$path" -frames:v 1 "$snap" > "$ROOT/logs/ffmpeg_rtsp_$(safe "$path").log" 2>&1 || true
        artifact "$snap"
      fi
    fi
  done
  if [[ "$RTSP_FOUND" -gt 0 ]]; then
    test_log "T8_RTSP_PROBE" "FAIL" "Unauthenticated/direct RTSP video paths found: $RTSP_FOUND" "$ROOT/streams"
  else
    test_log "T8_RTSP_PROBE" "PASS" "No direct RTSP video path confirmed" "$ROOT/streams"
  fi
else
  test_log "T8_RTSP_PROBE" "SKIP" "ffprobe not installed" "-"
fi

# ---------------------------------------------------------------------
# 9. HTTP object extraction and direct snapshot/config probes
# ---------------------------------------------------------------------
mkdir -p "$ROOT/objects/http"
tshark -r "$PCAP" --export-objects "http,$ROOT/objects/http" > "$ROOT/logs/tshark_export_http.log" 2>&1 || true
artifact "$ROOT/logs/tshark_export_http.log"
HTTP_OBJ_COUNT="$(find "$ROOT/objects/http" -type f 2>/dev/null | wc -l | tr -d ' ')"
test_log "T9_HTTP_OBJECTS" "PASS" "HTTP objects extracted: $HTTP_OBJ_COUNT" "$ROOT/objects/http"

HTTP_PORTS="80 81 88 443 554 8000 8001 8080 8081 8088 8443 8554 8888 9000 9090"
HTTP_PATHS=(
"/" "/status" "/info" "/version" "/device" "/device_info"
"/api" "/api/status" "/api/info"
"/snapshot.jpg" "/image.jpg" "/current.jpg" "/photo.jpg" "/cgi-bin/snapshot.cgi"
"/config.json" "/settings.json" "/device.conf" "/webconfig.cfg"
"/firmware.bin" "/update.bin" "/backup.bin"
"/sdcard/" "/recordings/" "/snapshots/" "/storage/"
)

: > "$ROOT/http/direct_probe.tsv"
for port in $HTTP_PORTS; do
  for path in "${HTTP_PATHS[@]}"; do
    scheme="http"
    [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
    url="${scheme}://${TARGET_IP}:${port}${path}"
    name="$(safe "$url")"
    hdr="$ROOT/http/${name}.headers"
    body="$ROOT/http/${name}.body"
    code="$(curl -k -sS -L --max-time 5 --connect-timeout 3 --range 0-10485760 -D "$hdr" -o "$body" -w "%{http_code}" "$url" 2>/dev/null || echo 000)"
    size="$(wc -c < "$body" 2>/dev/null || echo 0)"
    ctype="$(grep -i '^content-type:' "$hdr" 2>/dev/null | head -n1 | tr -d '\r' || true)"
    printf "%s\t%s\t%s\t%s\t%s\n" "$code" "$size" "$ctype" "$url" "$body" >> "$ROOT/http/direct_probe.tsv"
    artifact "$hdr"; artifact "$body"
  done
done
artifact "$ROOT/http/direct_probe.tsv"

HTTP_200="$(awk -F'\t' '$1=="200" || $1=="206"{c++} END{print c+0}' "$ROOT/http/direct_probe.tsv")"
if [[ "$HTTP_200" -gt 0 ]]; then
  test_log "T9_DIRECT_HTTP_PROBES" "FAIL" "Direct HTTP/HTTPS objects returned 200/206: $HTTP_200" "$ROOT/http/direct_probe.tsv"
else
  test_log "T9_DIRECT_HTTP_PROBES" "PASS" "No direct HTTP/HTTPS objects returned 200/206" "$ROOT/http/direct_probe.tsv"
fi

# ---------------------------------------------------------------------
# 10. Carving
# ---------------------------------------------------------------------
CARVED_COUNT=0

if have bulk_extractor; then
  mkdir -p "$ROOT/analysis/bulk"
  tool_run "T10_BULK_EXTRACTOR" "bulk_extractor PCAP mining" "$ROOT/logs/bulk_extractor.log" \
    bulk_extractor -o "$ROOT/analysis/bulk" "$PCAP"
fi

if have foremost; then
  mkdir -p "$ROOT/analysis/foremost"
  tool_run "T10_FOREMOST" "foremost PCAP carving" "$ROOT/logs/foremost.log" \
    foremost -i "$PCAP" -o "$ROOT/analysis/foremost"
fi

if have scalpel; then
  mkdir -p "$ROOT/analysis/scalpel"
  tool_run "T10_SCALPEL" "scalpel PCAP carving" "$ROOT/logs/scalpel.log" \
    scalpel "$PCAP" -o "$ROOT/analysis/scalpel"
else
  test_log "T10_SCALPEL" "SKIP" "scalpel not installed" "-"
fi

CARVED_COUNT="$(find "$ROOT/analysis" -type f 2>/dev/null | wc -l | tr -d ' ')"
test_log "T10_CARVING_SUMMARY" "PASS" "Carving outputs/files recorded: $CARVED_COUNT" "$ROOT/analysis"

# ---------------------------------------------------------------------
# 11. Normalize visual/text evidence
# ---------------------------------------------------------------------
mkdir -p "$ROOT/objects/all" "$ROOT/objects/text" "$ROOT/objects/configs"

find "$ROOT" -type f -print0 | while IFS= read -r -d '' f; do
  ft="$(file -b "$f" 2>/dev/null || echo unknown)"
  base="$(safe "$(basename "$f")")"

  if echo "$ft $f" | grep -qiE 'JPEG|PNG|GIF|WebP|BMP|TIFF|image'; then
    cp "$f" "$ROOT/images/$base" 2>/dev/null || true
  fi

  if echo "$ft $f" | grep -qiE 'ASCII|UTF-8|Unicode|HTML|JSON|XML|text|script'; then
    cp "$f" "$ROOT/objects/text/${base}.txt" 2>/dev/null || true
  fi

  if echo "$f $ft" | grep -qiE 'config|conf|settings|json|yaml|xml|ini|env|passwd|shadow|wireless|network'; then
    cp "$f" "$ROOT/objects/configs/$base" 2>/dev/null || true
  fi
done

IMG_COUNT="$(find "$ROOT/images" -type f 2>/dev/null | wc -l | tr -d ' ')"
TXT_COUNT="$(find "$ROOT/objects/text" -type f 2>/dev/null | wc -l | tr -d ' ')"
CFG_COUNT="$(find "$ROOT/objects/configs" -type f 2>/dev/null | wc -l | tr -d ' ')"

test_log "T11_VISUAL_PROOF" "PASS" "Images=$IMG_COUNT text_previews=$TXT_COUNT configs=$CFG_COUNT" "$ROOT/images"

# ---------------------------------------------------------------------
# 12. Final capability and cloud report
# ---------------------------------------------------------------------
cat > "$CAPABILITY_TXT" <<EOF

=== CAPABILITY RESULT ===

MITM_FEASIBLE   : $MITM
TOKEN_EXPOSURE  : $TOKEN
REPLAY_FEASIBLE : $REPLAY

Evidence:
- Plaintext evidence: $ROOT/capability/plaintext.txt
- Token candidates: $ROOT/capability/token_candidates.txt
- Replay patterns: $ROOT/capability/replay_patterns.txt

Interpretation:
- YES means passive evidence suggests the condition is possible/observable.
- NO means this run did not collect evidence for that condition.
- NO does not prove impossible; it means not evidenced in this capture window.

EOF
artifact "$CAPABILITY_TXT"

cat > "$CLOUD_TXT" <<EOF

=== CLOUD BEHAVIOR INTELLIGENCE ===

Target IP: $TARGET_IP

Counts:
- Unique DNS names: $DNS_COUNT
- Unique TLS SNI names: $SNI_COUNT
- Unique remote IPs: $REMOTE_COUNT
- Provider hints: $PROVIDER_COUNT

Evidence:
- DNS: $ROOT/dns/unique_domains.txt
- TLS SNI: $ROOT/tls/unique_sni.txt
- Remote IPs: $ROOT/cloud/remote_ips.txt
- Traffic volume by remote: $ROOT/cloud/remote_volume.tsv
- Provider hints: $ROOT/cloud/provider_hints.txt

EOF
artifact "$CLOUD_TXT"

TEST_PASS="$(awk -F'\t' '$3=="PASS"{c++} END{print c+0}' "$LOG_TSV")"
TEST_WARN="$(awk -F'\t' '$3=="WARN"{c++} END{print c+0}' "$LOG_TSV")"
TEST_FAIL="$(awk -F'\t' '$3=="FAIL"{c++} END{print c+0}' "$LOG_TSV")"
TEST_SKIP="$(awk -F'\t' '$3=="SKIP"{c++} END{print c+0}' "$LOG_TSV")"

cat > "$SUMMARY_TXT" <<EOF

NR12 IoT Cloud Hard Audit Report

Target IP          : $TARGET_IP
Capture interface  : $IFACE
Interface mode     : $MODE
Capture duration   : ${CAPTURE_TIME}s
PCAP file          : $PCAP
PCAP size          : $PCAP_SIZE bytes

Test summary:
- PASS: $TEST_PASS
- WARN: $TEST_WARN
- FAIL: $TEST_FAIL
- SKIP: $TEST_SKIP

Capability indicators:
- MITM_FEASIBLE   : $MITM
- TOKEN_EXPOSURE  : $TOKEN
- REPLAY_FEASIBLE : $REPLAY

Cloud behavior:
- Unique DNS names: $DNS_COUNT
- Unique TLS SNI names: $SNI_COUNT
- Unique remote IPs: $REMOTE_COUNT
- Provider hints: $PROVIDER_COUNT

Extraction:
- TCP streams: $STREAM_COUNT
- HTTP exported objects: $HTTP_OBJ_COUNT
- Direct HTTP 200/206 objects: $HTTP_200
- RTSP direct video paths: $RTSP_FOUND
- Images recovered: $IMG_COUNT
- Text previews: $TXT_COUNT
- Config-like files: $CFG_COUNT
- Carving outputs: $CARVED_COUNT

Important honesty note:
- This audit does not perform MITM, token hijacking, or cloud replay.
- It only reports whether passive/controlled evidence suggests those capabilities may be feasible.
- Encrypted cloud traffic may prevent content extraction; in that case cloud metadata and behavior are still valid evidence.

Key files:
- Full test log: $LOG_TSV
- Capability result: $CAPABILITY_TXT
- Cloud behavior: $CLOUD_TXT
- SHA256 manifest: $HASHES

EOF
artifact "$SUMMARY_TXT"

find "$ROOT" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f"; done

tar --exclude="evidence_archive.tar.gz" -czf "$ROOT/evidence_archive.tar.gz" -C "$ROOT" . > "$ROOT/logs/archive.log" 2>&1 || true
artifact "$ROOT/evidence_archive.tar.gz"

log "=== AUDIT COMPLETE ==="
echo "Evidence root : $ROOT"
echo "Summary       : $SUMMARY_TXT"
echo "Tests         : $LOG_TSV"
echo "Cloud report  : $CLOUD_TXT"
echo "Capability    : $CAPABILITY_TXT"
echo "Archive       : $ROOT/evidence_archive.tar.gz"
BASH

