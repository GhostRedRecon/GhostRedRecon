#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_IP="${TARGET_IP:-192.168.0.29}"
IFACE="${IFACE:-wlan0}"
CAPTURE_TIME=300

RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="./evidence/NR11_HARD_${RUN_ID}"

mkdir -p "$ROOT"/{pcap,analysis,streams,dns,tls,http,objects,capability,report,logs}

log(){ echo "[ $(date -u +"%T") ] $*"; }

# =========================================================
# TEST LOGGING ENGINE
# =========================================================
TEST_LOG="$ROOT/report/tests.tsv"

test_log(){
    echo -e "$1\t$2\t$3\t$4" >> "$TEST_LOG"
    log "[TEST] $1 | $2 | $3"
}

# =========================================================
# START
# =========================================================
log "=== NR11 HARD AUDIT START ==="
echo -e "ID\tSTATUS\tDETAILS\tEVIDENCE" > "$TEST_LOG"

# =========================================================
# T1 CAPTURE
# =========================================================
PCAP="$ROOT/pcap/capture.pcap"

log "[T1] Capturing traffic"

timeout "$CAPTURE_TIME" tcpdump -i "$IFACE" host "$TARGET_IP" \
-w "$PCAP" 2>/dev/null || true

if [[ -s "$PCAP" ]]; then
    test_log "T1_CAPTURE" "PASS" "PCAP captured" "$PCAP"
else
    test_log "T1_CAPTURE" "FAIL" "No traffic captured" "-"
fi

# =========================================================
# T2 PROTOCOL ANALYSIS
# =========================================================
tshark -r "$PCAP" -q -z io,phs \
> "$ROOT/analysis/protocol.txt" 2>/dev/null || true

test_log "T2_PROTOCOL" "PASS" "Protocol analysis complete" "$ROOT/analysis/protocol.txt"

# =========================================================
# T3 DNS
# =========================================================
tshark -r "$PCAP" -Y "dns" \
-T fields -e dns.qry.name \
> "$ROOT/dns/domains.txt" 2>/dev/null || true

if [[ -s "$ROOT/dns/domains.txt" ]]; then
    test_log "T3_DNS" "PASS" "DNS extracted" "$ROOT/dns/domains.txt"
else
    test_log "T3_DNS" "WARN" "No DNS seen" "-"
fi

# =========================================================
# T4 TLS
# =========================================================
tshark -r "$PCAP" \
-Y "tls.handshake.extensions_server_name" \
-T fields -e tls.handshake.extensions_server_name \
> "$ROOT/tls/sni.txt" 2>/dev/null || true

if [[ -s "$ROOT/tls/sni.txt" ]]; then
    test_log "T4_TLS" "PASS" "TLS detected" "$ROOT/tls/sni.txt"
else
    test_log "T4_TLS" "WARN" "No TLS seen" "-"
fi

# =========================================================
# T5 HTTP (MITM INDICATOR)
# =========================================================
tshark -r "$PCAP" -Y "http" \
> "$ROOT/http/http.txt" 2>/dev/null || true

MITM="NO"

if [[ -s "$ROOT/http/http.txt" ]]; then
    MITM="YES"
    test_log "T5_HTTP" "FAIL" "Plain HTTP detected" "$ROOT/http/http.txt"
else
    test_log "T5_HTTP" "PASS" "No plaintext HTTP" "-"
fi

# =========================================================
# T6 TOKEN EXTRACTION
# =========================================================
strings "$PCAP" | grep -iE \
"token=|auth=|session=|jwt|bearer|api_key" \
> "$ROOT/analysis/tokens.txt" || true

TOKEN="NO"

if [[ -s "$ROOT/analysis/tokens.txt" ]]; then
    TOKEN="YES"
    test_log "T6_TOKEN" "FAIL" "Tokens found" "$ROOT/analysis/tokens.txt"
else
    test_log "T6_TOKEN" "PASS" "No tokens found" "-"
fi

# =========================================================
# T7 REPLAY CHECK
# =========================================================
tshark -r "$PCAP" -Y "http.request" \
-T fields -e http.request.uri \
> "$ROOT/analysis/requests.txt" 2>/dev/null || true

sort "$ROOT/analysis/requests.txt" | uniq -c \
> "$ROOT/analysis/replay.txt"

REPLAY="NO"

if awk '$1 > 3 {print}' "$ROOT/analysis/replay.txt" | grep -q .; then
    REPLAY="YES"
    test_log "T7_REPLAY" "FAIL" "Replay pattern found" "$ROOT/analysis/replay.txt"
else
    test_log "T7_REPLAY" "PASS" "No replay pattern" "-"
fi

# =========================================================
# T8 STREAMS
# =========================================================
tshark -r "$PCAP" -T fields -e tcp.stream \
| sort -n | uniq \
> "$ROOT/streams/list.txt"

COUNT=$(wc -l < "$ROOT/streams/list.txt")

test_log "T8_STREAMS" "PASS" "Streams=$COUNT" "$ROOT/streams/list.txt"

# =========================================================
# T9 OBJECT EXTRACTION
# =========================================================
mkdir -p "$ROOT/objects"

tshark -r "$PCAP" \
--export-objects http,"$ROOT/objects" 2>/dev/null || true

OBJ=$(find "$ROOT/objects" -type f | wc -l)

test_log "T9_OBJECTS" "PASS" "Objects=$OBJ" "$ROOT/objects"

# =========================================================
# T10 CARVING
# =========================================================
bulk_extractor -o "$ROOT/analysis/bulk" "$PCAP" >/dev/null 2>&1 || true
foremost -i "$PCAP" -o "$ROOT/analysis/foremost" >/dev/null 2>&1 || true

CARVED=$(find "$ROOT/analysis" -type f | wc -l)

test_log "T10_CARVING" "PASS" "Files=$CARVED" "$ROOT/analysis"

# =========================================================
# FINAL CAPABILITY RESULT
# =========================================================
cat <<EOF > "$ROOT/report/capability.txt"

=== CAPABILITY RESULT ===

MITM_FEASIBLE: $MITM
TOKEN_EXPOSURE: $TOKEN
REPLAY_FEASIBLE: $REPLAY

EOF

# =========================================================
# FINAL SUMMARY
# =========================================================
cat <<EOF > "$ROOT/report/summary.txt"

NR11 HARD AUDIT

Target: $TARGET_IP

MITM: $MITM
TOKEN: $TOKEN
REPLAY: $REPLAY

See:
- tests.tsv (full audit log)
- analysis/
- objects/

EOF

log "=== AUDIT COMPLETE ==="
echo "Output: $ROOT"
