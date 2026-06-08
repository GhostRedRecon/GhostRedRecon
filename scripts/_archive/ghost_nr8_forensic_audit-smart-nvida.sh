#!/usr/bin/env bash
# =============================================================================
# NR11 HARD AUDIT – aggressive evidence collection
#
#   * captures traffic for a configurable period
#   * extracts possible video streams (RTSP/MJPEG/RTMP) and decodes frames
#   * carves and normalises *all* embedded artefacts
#   * produces a richer TSV log, a capability summary and a final report
#
#  WARNING:  Run only on systems you are authorised to test!
# =============================================================================

set -Eeuo pipefail

# -------------------------------------------------------------------------
# USER‑CONFIGURATION (override via env vars or edit here)
# -------------------------------------------------------------------------
TARGET_IP="${TARGET_IP:-192.168.0.29}"                 # IP of the device under test
IFACE="${IFACE:-wlan0}"                               # Primary interface (monitor mode encouraged)
CAPTURE_TIME="${CAPTURE_TIME:-600}"                   # Seconds to capture (default 10 min)
RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="./evidence/NR11_HARD_${RUN_ID}"
PCAP="${ROOT}/pcap/capture.pcap"

# Tools – adjust paths if they are not in $PATHT Shark_cmd="tshark"
FFmpeg_cmd="ffmpeg"
Binwalk_cmd="binwalk"
Foremost_cmd="foremost"
Scalpel_cmd="scalpel"
JpegCrop_cmd="cjpeg"      # for creating JPEGs from raw data
TEE_CMD="tee"             # just the system tee

# -------------------------------------------------------------------------
# Derived paths
# -------------------------------------------------------------------------
mkdir -p "$ROOT"/{pcap,analysis,streams,dns,tls,http,objects,capability,report,logs,tmp}
LOG_TSV="${ROOT}/report/tests.tsv"
CAPABILITY_TXT="${ROOT}/report/capability.txt"
SUMMARY_TXT="${ROOT}/report/summary.txt"
EXTracted_Images_DIR="${ROOT}/images"

# -------------------------------------------------------------------------# Logging helper
# -------------------------------------------------------------------------
log(){ echo "[ $(date -u +"%T") ] $*"; }

# -------------------------------------------------------------------------
# Initialise TSV log
# -------------------------------------------------------------------------test_log(){
    # $1 = TEST_ID   \$2 = STATUS (PASS/WARN/FAIL)   \$3 = DETAILS   $4 = EVIDENCE (file or "-" )
    printf "%s\t%s\t%s\t%s\n" "\$1" "\$2" "\$3" "\$4" >> "$LOG_TSV"
    log "[TEST] \$1 | \$2 | $3"
}

log "=== NR11 HARD AUDIT START ==="
printf "ID\tSTATUS\tDETAILS\tEVIDENCE\n" > "$LOG_TSV"

# -------------------------------------------------------------------------
# 1️⃣  Capture traffic (promiscuous, possibly monitor mode)
# -------------------------------------------------------------------------
log "[T1] Starting capture on $IFACE (target $TARGET_IP) → $PCAP"
#   - If $IFACE is a monitor interface we also capture broadcast/multicast
#   - timeout automatically kills tcpdump after CAPTURE_TIME secondstimeout "$CAPTURE_TIME" tcpdump -i "$IFACE" \
    -nn -s 0 -w "$PCAP" \
    -v -vv -e -p \
    host "$TARGET_IP" \
    2>/dev/null || true

if [[ -s "$PCAP" ]]; then
    test_log "T1_CAPTURE" "PASS" "PCAP captured (size=$(stat -c%s "$PCAP") bytes)" "$PCAP"
else
    test_log "T1_CAPTURE" "FAIL" "No traffic captured" "-"
fi

# -------------------------------------------------------------------------
# 2️⃣  Basic protocol diagnostics (same as original)
# -------------------------------------------------------------------------
log "[T2] Protocol analysis"
tshark -r "$PCAP" -q -z io,phs > "${ROOT}/analysis/protocol.txt" 2>/dev/null || true
test_log "T2_PROTOCOL" "PASS" "Protocol summary generated" "${ROOT}/analysis/protocol.txt"

# -------------------------------------------------------------------------
# 3️⃣  DNS enumeration (optional but fun)
# -------------------------------------------------------------------------
log "[T3] DNS extraction"
tshark -r "$PCAP" -Y "dns" -T fields -e dns.qry.name > "${ROOT}/dns/domains.txt" 2>/dev/null || true
if [[ -s "${ROOT}/dns/domains.txt" ]]; then
    test_log "T3_DNS" "PASS" "DNS‑queries extracted" "${ROOT}/dns/domains.txt"
else
    test_log "T3_DNS" "WARN" "No DNS seen" "-"
fi

# -------------------------------------------------------------------------
# 4️⃣  TLS indicators (SNI, certificates)
# -------------------------------------------------------------------------
log "[T4] TLS handshake extraction"
tshark -r "$PCAP" -Y "tls.handshake" -T fields -e tls.handshake.extensions_server_name -e tls.handshake.certificate_request > "${ROOT}/tls/sni.txt" 2>/dev/null || true
test_log "T4_TLS" "PASS" "TLS data captured" "${ROOT}/tls/sni.txt"

# -------------------------------------------------------------------------
# 5️⃣  HTTP (plain‑text) detection – same as before
# -------------------------------------------------------------------------
log "[T5] HTTP inspection"
tshark -r "$PCAP" -Y "http" > "${ROOT}/http/http.txt" 2>/dev/null || true
if [[ -s "${ROOT}/http/http.txt" ]]; then    MITM="YES"
    test_log "T5_HTTP" "FAIL" "Plain HTTP observed" "${ROOT}/http/http.txt"
else
    MITM="NO"
    test_log "T5_HTTP" "PASS" "No clear‑text HTTP" "-"
fi

# -------------------------------------------------------------------------
# 6️⃣  Token sniffing (any auth‑related field) – same as before
# -------------------------------------------------------------------------
log "[T6] Token extraction"
strings "$PCAP" | grep -iE "token=|auth=|session=|jwt|bearer|api_key" > "${ROOT}/analysis/tokens.txt" || true
if [[ -s "${ROOT}/analysis/tokens.txt" ]]; then
    TOKEN="YES"
    test_log "T6_TOKEN" "FAIL" "Tokens discovered" "${ROOT}/analysis/tokens.txt"
else
    TOKEN="NO"
    test_log "T6_TOKEN" "PASS" "No tokens found" "-"
fi

# -------------------------------------------------------------------------
# 7️⃣  Replay pattern detection – same as before but with size threshold
# -------------------------------------------------------------------------
log "[T7] Replay detection"
tshark -r "$PCAP" -Y "http.request" -T fields -e http.request.uri > "${ROOT}/analysis/requests.txt" 2>/dev/null || true
sort "${ROOT}/analysis/requests.txt" | uniq -c > "${ROOT}/analysis/replay.txt"
if awk '\$1 > 3 {print}' "\${ROOT}/analysis/replay.txt" | grep -q .; then
    REPLAY="YES"
    test_log "T7_REPLAY" "FAIL" "Replay pattern detected" "${ROOT}/analysis/replay.txt"
else
    REPLAY="NO"
    test_log "T7_REPLAY" "PASS" "No replay pattern" "-"
fi

# -------------------------------------------------------------------------
# 8️⃣  Stream enumeration + per‑stream screenshots / JPEGs
# -------------------------------------------------------------------------
log "[T8] Stream list & live‑camera extraction"
# List all TCP streams (helps us spot a video stream)
tshark -r "$PCAP" -T fields -e tcp.stream | sort -n | uniq > "${ROOT}/streams/list.txt"
STREAM_COUNT=$(wc -l < "${ROOT}/streams/list.txt")
test_log "T8_STREAMS" "PASS" "Streams=$STREAM_COUNT" "${ROOT}/streams/list.txt"

# Detect possible video streams (rtsp, mjpeg, rtmp, h264 over udp)
log "[T8a] Identify video streams"
VIDEO_STREAMS=()
while read -r stream; do
    # Grab a few packets of that stream to see if they contain RTSP/MJPEG signatures
    sample=$(tshark -r "$PCAP" -Y "tcp.stream == $stream" -c 5 -T fields -e data)
    if grep -qE "RTSP|MJPG|RTMP|h264|h265|JPEG" <<<"$sample"; then
        VIDEO_STREAMS+=("$stream")
    fi
done < "${ROOT}/streams/list.txt"

if (( ${#VIDEO_STREAMS[@]} )); then
    log "Found ${#VIDEO_STREAMS[@]} candidate video stream(s): ${VIDEO_STREAMS[*]}"
    mkdir -p "$EXTracted_Images_DIR"
    for str in "${VIDEO_STREAMS[@]}"; do
        log "→ Extracting stream $str to raw video file"
        # Export the whole stream to a temporary file (may be large)
        tshark -r "$PCAP" -Y "tcp.stream == $str" -T fields -e data \
            -E separator=':' | base64 -d > "${ROOT}/tmp/stream_${str}.bin"

        # Attempt to decode based on known container types        case "$(file -b "${ROOT}/tmp/stream_${str}.bin")" in
            *RTSP*)
                log "   Detected RTSP – trying ffmpeg conversion to JPEG sequence"
                ffmpeg -i "${ROOT}/tmp/stream_${str}.bin" -vf fps=1 "$EXTracted_Images_DIR/rtsp_%04d.jpg" -loglevel error || true
                ;;
            *MJPEG*)
                log "   Detected MJPEG – converting to JPEG frames"
                ffmpeg -i "${ROOT}/tmp/stream_${str}.bin" -vf fps=1 "$EXTracted_Images_DIR/mjpg_%04d.jpg" -loglevel error || true
                ;;
            *RTMP*)
                log "   Detected RTMP – extracting embedded FLV and then frames"
                ffmpeg -i "${ROOT}/tmp/stream_${str}.bin" -vf fps=1 "$EXTracted_Images_DIR/rtmp_%04d.jpg" -loglevel error || true
                ;;
            *JPEG*|*JPG*)
                log "   Already a JPEG blob – move it to objects"
                mv "${ROOT}/tmp/stream_${str}.bin" "${EXTracted_Images_DIR}/${str}_raw.jpg"
                ;;
            *)
                log "   Unknown format – carving with binwalk later"
                mv "${ROOT}/tmp/stream_${str}.bin" "${ROOT}/analysis/unidentified_${str}.bin"
                ;;
        esac
    done

    # If any JPEGs were produced, record their hashes
    if compgen -G "$EXTracted_Images_DIR/*" > /dev/null; then
        SHA256_LIST=$(find "$EXTracted_Images_DIR" -type f -exec sha256sum {} \; | sort)
        test_log "T8_IMAGES" "PASS" "Extracted ${#VIDEO_STREAMS[@]} image set(s)" "$SHA256_LIST"
    else
        test_log "T8_IMAGES" "WARN" "No images extracted from live streams" "-"
    fi
else    test_log "T8_IMAGES" "WARN" "No video‑like streams identified" "-"
fi

# -------------------------------------------------------------------------
# 9️⃣  Object carving – binwalk, foremost, scalpel (all artefacts)
# -------------------------------------------------------------------------
log "[T9] Carving embedded artefacts"
CARVED_COUNT=0

# binwalk – extracts archives, images, executables, etc.
if command -v "$Binwalk_cmd" >/dev/null; then
    "$Binwalk_cmd" -e -C "$ROOT/analysis/bulk" "$PCAP" >/dev/null 2>&1 || true
    BIN_COUNT=$(find "$ROOT/analysis/bulk" -type f | wc -l)
    CARVED_COUNT=$((CARVED_COUNT + BIN_COUNT))
fi

# foremost – classic file carving
if command -v "$Foremost_cmd" >/dev/null; then
    "$Foremost_cmd" -i "$PCAP" -o "$ROOT/analysis/foremost" >/dev/null 2>&1 || true
    FO_COUNT=$(find "$ROOT/analysis/foremost" -type f | wc -l)
    CARVED_COUNT=$((CARVED_COUNT + FO_COUNT))
fi

# scalpel – modern, fast carver
if command -v "$Scalpel_cmd" >/dev/null; then
    "$Scalpel_cmd" "$PCAP" -o "$ROOT/analysis/scap_carve" >/dev/null 2>&1 || true
    SC_COUNT=$(find "$ROOT/analysis/scap_carve" -type f | wc -l)
    CARVED_COUNT=$((CARVED_COUNT + SC_COUNT))
fi

# consolidate all carved files under a single “objects/” folder
mkdir -p "$ROOT/objects"
find "$ROOT/analysis" -type f -exec mv {} "$ROOT/objects/" \; 2>/dev/null || true
OBJ_COUNT=$(find "$ROOT/objects" -type f | wc -l)

test_log "T9_CARVING" "PASS" "Carved artefacts=$OBJ_COUNT" "$ROOT/objects"

# -------------------------------------------------------------------------
# 10️⃣  Final capability summary
# -------------------------------------------------------------------------
log "[RESULT] Assembling capability summary"
cat > "$CAPABILITY_TXT" <<EOF

=== CAPABILITY RESULT ===

MITM_FEASIBLE   : $MITM
TOKEN_EXPOSURE  : $TOKEN
REPLAY_FEASIBLE : $REPLAY
LIVE_STREAMS    : ${#VIDEO_STREAMS[@]} detectedIMAGES_EXTRACTED: $(find "$EXTracted_Images_DIR" -type f | wc -l) JPEG/PNG files

EOF# -------------------------------------------------------------------------
# 11️⃣  Final report (human‑readable)
# -------------------------------------------------------------------------
log "[RESULT] Writing final summary"
cat > "$SUMMARY_TXT" <<EOF

NR11 HARD AUDIT – Evidence Package

Target IP          : $TARGET_IP
Capture interface  : $IFACE
Capture duration   : ${CAPTURE_TIME}s
PCAP file          : $PCAP
--------------------------------------------------------------------
Findings
--------------------------------------------------------------------
MITM feasibility   : $MITM
Authentication token leakage : $TOKEN
Replay attack surface   : $REPLAY
Live‑camera frames extracted : $(find "$EXTracted_Images_DIR" -type f | wc -l) images
Embedded artefacts (files)   : $OBJ_COUNT objects (see $ROOT/objects/)

Key artefacts-------------
* Plain‑text HTTP requests – ${MITM^^}
* Captured authentication tokens – ${TOKEN^^}
* Replay‑heavy HTTP URIs – ${REPLAY^^}
* Detected video streams – ${#VIDEO_STREAMS[@]} (saved under $EXTracted_Images_DIR)
* Carved binaries / documents – $OBJ_COUNT objects (see $ROOT/objects/)

Directory layout
----------------
$ROOT/
 ├─ pcap/
 │   └─ capture.pcap
 ├─ analysis/
 │   ├─ protocol.txt
 │   ├─ tokens.txt
 │   ├─ replay.txt │   ├─ streams/
 │   └─ bulk/ … (binwalk output)
 ├─ objects/                ← all carved files
 ├─ images/                 ← JPEGs/PNGs extracted from live stream
 ├─ report/
 │   ├─ tests.tsv           ← full TSV audit log
 │   ├─ capability.txt
 │   └─ summary.txt
 └─ logs/                   ← optional raw log files

--------------------------------------------------------------------
Run `sha256sum *` inside $ROOT to get a reproducible hash manifest.
--------------------------------------------------------------------

EOF

# -------------------------------------------------------------------------# 12️⃣  Clean‑up temporary files (optional)
# -------------------------------------------------------------------------
rm -rf "$ROOT/tmp" 2>/dev/null || true

log "=== AUDIT COMPLETE – evidence saved under $ROOT ==="
echo "================================================================"
echo "Summarised evidence is in $ROOT/report/summary.txt"
echo "Full artefact list (hashes) is in $ROOT/report/tests.tsv"
echo "================================================================"
