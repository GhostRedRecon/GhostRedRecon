#!/usr/bin/env bash
set -euo pipefail

# =========================
# CONFIG
# =========================
IFACE="wlan1"
DURATION=90
OUTDIR="$HOME/ghostrecon_smart_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[+] Output: $OUTDIR"

# =========================
# 1. FORCE MONITOR MODE
# =========================
echo "[1] Setting monitor mode..."

sudo ip link set $IFACE down
sudo iw dev $IFACE set type monitor
sudo ip link set $IFACE up

MON_IFACE="$IFACE"

# =========================
# 2. CAPTURE TRAFFIC
# =========================
echo "[2] Capturing packets..."
echo ">>> Open camera app NOW <<<"

timeout $DURATION dumpcap -i $MON_IFACE -w "$OUTDIR/capture.pcapng"

if [ ! -f "$OUTDIR/capture.pcapng" ]; then
    echo "[!] Capture failed"
    exit 1
fi

# =========================
# 3. EXTRACT FEATURES
# =========================
echo "[3] Extracting packet features..."

tshark -r "$OUTDIR/capture.pcapng" \
  -T fields \
  -e wlan.sa \
  -e wlan.da \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e tls.handshake.extensions_server_name \
  -e http.host \
  -e http.request.uri \
  -e rtsp.url \
  > "$OUTDIR/features.txt"

# =========================
# 4. SMART DETECTION ENGINE
# =========================
echo "[4] Running smart detection..."

python3 - <<EOF
import collections, sys, json

features_file = "$OUTDIR/features.txt"

profiles = collections.defaultdict(lambda: {
    "score": 0,
    "dns": set(),
    "sni": set(),
    "http": set(),
    "rtsp": set(),
    "count": 0
})

CAMERA_KEYWORDS = ["camera","onvif","rtsp","snapshot","mjpeg","ipcam","doorbell","mi","xiaomi"]

with open(features_file, "r", errors="ignore") as f:
    for line in f:
        parts = line.strip().split("\t")
        if len(parts) < 9:
            continue

        mac = parts[0] or parts[1]
        dns = parts[4]
        sni = parts[5]
        http = parts[6] + parts[7]
        rtsp = parts[8]

        p = profiles[mac]
        p["count"] += 1

        if dns:
            p["dns"].add(dns.lower())
        if sni:
            p["sni"].add(sni.lower())
        if http:
            p["http"].add(http.lower())
        if rtsp:
            p["rtsp"].add(rtsp.lower())

        combined = " ".join([dns, sni, http, rtsp]).lower()

        for k in CAMERA_KEYWORDS:
            if k in combined:
                p["score"] += 5

        if rtsp:
            p["score"] += 30

        if "snapshot" in combined or "onvif" in combined:
            p["score"] += 20

        if p["count"] > 500:
            p["score"] += 10

results = []

for mac, p in profiles.items():
    verdict = "unknown"

    if p["rtsp"]:
        verdict = "LOCAL CAMERA (RTSP)"
    elif p["score"] > 40 and p["sni"]:
        verdict = "ENCRYPTED CLOUD CAMERA"
    elif p["score"] > 20:
        verdict = "CAMERA-LIKE DEVICE"

    results.append({
        "mac": mac,
        "score": p["score"],
        "verdict": verdict,
        "packets": p["count"]
    })

results.sort(key=lambda x: x["score"], reverse=True)

with open("$OUTDIR/targets.json", "w") as f:
    json.dump(results, f, indent=2)

if results:
    print(results[0]["mac"])
else:
    print("")
EOF > "$OUTDIR/top_mac.txt"

TOP_MAC=$(cat "$OUTDIR/top_mac.txt")

echo "[+] Top detected device: $TOP_MAC"

# =========================
# 5. FILTER TARGET
# =========================
echo "[5] Filtering target traffic..."

if [ -n "$TOP_MAC" ]; then
    tshark -r "$OUTDIR/capture.pcapng" \
      -Y "wlan.addr == $TOP_MAC" \
      -w "$OUTDIR/filtered.pcapng"
else
    cp "$OUTDIR/capture.pcapng" "$OUTDIR/filtered.pcapng"
fi

# =========================
# 6. ANALYSIS
# =========================
echo "[6] Deep analysis..."

tshark -r "$OUTDIR/filtered.pcapng" \
  -Y "dns || tls || http || rtsp" \
  > "$OUTDIR/analysis.txt"

# =========================
# 7. EXTRACT DATA
# =========================
echo "[7] Extracting artifacts..."

mkdir -p "$OUTDIR/http"
tshark -r "$OUTDIR/filtered.pcapng" \
  --export-objects http,"$OUTDIR/http" > /dev/null 2>&1

mkdir -p "$OUTDIR/carved"
foremost -i "$OUTDIR/filtered.pcapng" -o "$OUTDIR/carved" > /dev/null 2>&1

mkdir -p "$OUTDIR/images"
find "$OUTDIR/http" -type f \( -iname "*.jpg" -o -iname "*.png" \) -exec cp {} "$OUTDIR/images/" \;
find "$OUTDIR/carved" -type f \( -iname "*.jpg" -o -iname "*.png" \) -exec cp {} "$OUTDIR/images/" \;

IMG_COUNT=$(ls "$OUTDIR/images" 2>/dev/null | wc -l)

# =========================
# 8. FINAL VERDICT
# =========================
echo "[8] Generating final verdict..."

if [ $IMG_COUNT -gt 0 ]; then
    VERDICT="LOCAL CAMERA (IMAGE CAPTURED)"
else
    VERDICT=$(jq -r '.[0].verdict' "$OUTDIR/targets.json")
fi

echo "========== RESULT =========="
echo "Top Device: $TOP_MAC"
echo "Images: $IMG_COUNT"
echo "Verdict: $VERDICT"
echo "Output: $OUTDIR"
echo "============================"
