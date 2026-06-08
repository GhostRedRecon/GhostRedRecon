#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET_IP:-192.168.0.29}"
OUT="deep_audit_$(date +%s)"
mkdir -p "$OUT"

echo "[+] Deep Device Introspection Starting..."

# -------------------------
# 1. RTSP / Camera Streams
# -------------------------
echo "[+] Testing RTSP streams..."

RTSP_PORTS=(554 8554 10554)
RTSP_PATHS=(
"/live"
"/live.sdp"
"/stream"
"/h264"
"/video"
"/cam/realmonitor"
"/onvif1"
)

for p in "${RTSP_PORTS[@]}"; do
  for path in "${RTSP_PATHS[@]}"; do
    URL="rtsp://$TARGET:$p$path"
    timeout 3 ffprobe "$URL" &>> "$OUT/rtsp_results.txt" && \
    echo "[FOUND] $URL" >> "$OUT/rtsp_hits.txt"
  done
done

# -------------------------
# 2. ONVIF Detection
# -------------------------
echo "[+] Testing ONVIF..."

curl -s "http://$TARGET/onvif/device_service" > "$OUT/onvif.xml" || true

# -------------------------
# 3. Hidden API Discovery
# -------------------------
echo "[+] Testing hidden APIs..."

API_PATHS=(
"/api"
"/api/v1"
"/api/status"
"/device"
"/system"
"/config"
"/settings"
"/web"
"/webui"
"/admin"
"/hidden"
"/debug"
"/mnt"
"/sdcard"
"/storage"
"/files"
"/download"
"/backup"
"/recordings"
"/snapshots"
)

for path in "${API_PATHS[@]}"; do
  curl -s -m 3 "http://$TARGET$path" \
    -o "$OUT/api_$(echo $path | tr '/' '_').txt"
done

# -------------------------
# 4. SSD / SD Card Detection
# -------------------------
echo "[+] Checking storage endpoints..."

STORAGE_PATHS=(
"/sdcard"
"/mnt"
"/storage"
"/usb"
"/media"
"/recordings"
"/video"
)

for path in "${STORAGE_PATHS[@]}"; do
  curl -s "http://$TARGET$path" >> "$OUT/storage_scan.txt"
done

# -------------------------
# 5. Device Fingerprinting
# -------------------------
echo "[+] Fingerprinting device..."

nmap -O -Pn "$TARGET" > "$OUT/os_fingerprint.txt" 2>&1 || true

# -------------------------
# 6. UDP Behavior
# -------------------------
echo "[+] Checking UDP behavior..."

nc -u -w1 "$TARGET" 54321 < /dev/null > "$OUT/udp_test.txt" 2>&1 || true

# -------------------------
# 7. Cloud / DNS Extraction
# -------------------------
echo "[+] Extracting DNS from PCAP..."

tshark -r evidence/*/01_capture/*.pcap \
  -Y dns -T fields -e dns.qry.name \
  | sort -u > "$OUT/domains.txt"

# -------------------------
# 8. Traffic Pattern Analysis
# -------------------------
echo "[+] Analyzing behavior..."

tshark -r evidence/*/01_capture/*.pcap \
  -T fields -e ip.dst \
  | sort | uniq -c | sort -nr > "$OUT/traffic_pattern.txt"

# -------------------------
# 9. Secret Detection
# -------------------------
echo "[+] Searching for secrets..."

grep -RiE "password|token|secret|key" "$OUT" > "$OUT/secrets.txt"

# -------------------------
# 10. FINAL REPORT
# -------------------------
echo "================================="
echo " DEEP DEVICE FORENSIC REPORT"
echo "================================="

echo "RTSP streams found:"
cat "$OUT/rtsp_hits.txt" 2>/dev/null || echo "None"

echo ""
echo "Domains contacted:"
cat "$OUT/domains.txt"

echo ""
echo "Traffic pattern:"
head "$OUT/traffic_pattern.txt"

echo ""
echo "Secrets:"
cat "$OUT/secrets.txt"

echo ""
echo "Output folder: $OUT"
