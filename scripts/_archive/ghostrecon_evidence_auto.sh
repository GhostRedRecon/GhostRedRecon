#!/usr/bin/env bash
set -euo pipefail

# =========================
# CONFIG
# =========================
IFACE="${IFACE:-wlan1}"
DURATION="${DURATION:-90}"
SCAN_TIME="${SCAN_TIME:-15}"
OUTROOT="${OUTROOT:-$HOME}"
RUN_ID="ghostrecon_auto_$(date +%Y%m%d_%H%M%S)"
OUTDIR="$OUTROOT/$RUN_ID"
MON_IFACE="${IFACE}mon"

mkdir -p "$OUTDIR"
mkdir -p "$OUTDIR/http_objects" "$OUTDIR/carved" "$OUTDIR/images"

log() {
  echo "[ghostrecon-auto] $*" | tee -a "$OUTDIR/run.log"
}

need_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1"
    exit 1
  }
}

# =========================
# TOOL CHECKS
# =========================
for t in airmon-ng airodump-ng dumpcap tshark awk sed grep sort uniq head tail; do
  need_tool "$t"
done

if ! command -v foremost >/dev/null 2>&1; then
  log "foremost not found; carving will be skipped"
fi

# =========================
# CLEANUP
# =========================
cleanup() {
  set +e
  log "Cleaning up"
  sudo airmon-ng stop "$MON_IFACE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# =========================
# 1. ENABLE MONITOR MODE
# =========================
log "Enabling monitor mode on $IFACE"
sudo airmon-ng start "$IFACE" > "$OUTDIR/airmon_start.txt" 2>&1 || true

if ! ip link show "$MON_IFACE" >/dev/null 2>&1; then
  log "Monitor interface $MON_IFACE not found; trying to continue with $IFACE"
  MON_IFACE="$IFACE"
fi

# =========================
# 2. INITIAL SCAN
# =========================
log "Scanning for nearby Wi-Fi targets for ${SCAN_TIME}s"
timeout "${SCAN_TIME}s" airodump-ng "$MON_IFACE" \
  --write "$OUTDIR/scan" \
  --output-format csv >/dev/null 2>&1 || true

SCAN_CSV="$OUTDIR/scan-01.csv"
if [[ ! -f "$SCAN_CSV" ]]; then
  log "Scan CSV was not created. Falling back to broad capture without pre-ranking."
fi

# =========================
# 3. BROAD CAPTURE
# =========================
log "Starting broad capture for ${DURATION}s"
timeout "${DURATION}s" dumpcap -i "$MON_IFACE" -w "$OUTDIR/capture.pcapng" \
  > "$OUTDIR/dumpcap_stdout.txt" 2> "$OUTDIR/dumpcap_stderr.txt" || true

if [[ ! -f "$OUTDIR/capture.pcapng" ]]; then
  log "Capture failed"
  exit 1
fi

# =========================
# 4. EXTRACT FIELDS
# =========================
log "Decoding packet fields"
tshark -r "$OUTDIR/capture.pcapng" \
  -T fields \
  -E header=y \
  -E separator=, \
  -E quote=d \
  -e frame.number \
  -e frame.time_epoch \
  -e frame.protocols \
  -e wlan.sa \
  -e wlan.da \
  -e wlan.bssid \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e dns.resp.name \
  -e tls.handshake.extensions_server_name \
  -e http.host \
  -e http.request.uri \
  -e http.server \
  -e http.user_agent \
  -e rtsp.url \
  -e udp.port \
  > "$OUTDIR/fields.csv" 2> "$OUTDIR/tshark_fields_err.txt" || true

# =========================
# 5. AUTO-DETECTION + SCORING
# =========================
log "Scoring likely camera devices"
python3 - "$OUTDIR/fields.csv" "$OUTDIR/scores.json" "$OUTDIR/top_mac.txt" <<'PY'
import csv, json, sys
from collections import defaultdict

fields_csv = sys.argv[1]
scores_json = sys.argv[2]
top_mac_txt = sys.argv[3]

CAMERA_KEYWORDS = (
    "camera", "ipcam", "onvif", "rtsp", "snapshot", "mjpeg", "mjpg",
    "hikvision", "dahua", "reolink", "tapo", "arlo", "ring", "eufy",
    "doorbell", "isapi", "cgi-bin", "xiaomi", "mi.com", "mijia"
)

IMAGING_HOST_HINTS = (
    "camera", "doorbell", "video", "stream", "mihome", "mi"
)

profiles = defaultdict(lambda: {
    "score": 0,
    "dns": set(),
    "sni": set(),
    "http_hosts": set(),
    "http_uris": set(),
    "rtsp": set(),
    "protocols": set(),
    "reasons": [],
    "packet_count": 0,
})

def add_reason(p, reason, points):
    p["score"] += points
    if reason not in p["reasons"]:
        p["reasons"].append(reason)

try:
    with open(fields_csv, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            macs = set()
            for key in ("wlan.sa", "wlan.da", "wlan.bssid"):
                v = (row.get(key) or "").strip().lower()
                if v:
                    macs.add(v)

            if not macs:
                continue

            protocols = (row.get("frame.protocols") or "").lower()
            dns_q = (row.get("dns.qry.name") or "").strip().lower()
            dns_r = (row.get("dns.resp.name") or "").strip().lower()
            sni = (row.get("tls.handshake.extensions_server_name") or "").strip().lower()
            http_host = (row.get("http.host") or "").strip().lower()
            http_uri = (row.get("http.request.uri") or "").strip().lower()
            http_server = (row.get("http.server") or "").strip().lower()
            http_ua = (row.get("http.user_agent") or "").strip().lower()
            rtsp = (row.get("rtsp.url") or "").strip().lower()
            udp_port = (row.get("udp.port") or "").strip()

            for mac in macs:
                p = profiles[mac]
                p["packet_count"] += 1
                if protocols:
                    p["protocols"].add(protocols)
                if dns_q:
                    p["dns"].add(dns_q)
                if dns_r:
                    p["dns"].add(dns_r)
                if sni:
                    p["sni"].add(sni)
                if http_host:
                    p["http_hosts"].add(http_host)
                if http_uri:
                    p["http_uris"].add(http_uri)
                if rtsp:
                    p["rtsp"].add(rtsp)

                combined = " ".join([dns_q, dns_r, sni, http_host, http_uri, http_server, http_ua, rtsp])
                for kw in CAMERA_KEYWORDS:
                    if kw in combined:
                        add_reason(p, f"keyword:{kw}", 6)

                if rtsp:
                    add_reason(p, "rtsp_seen", 25)

                if any(x in http_uri for x in ("snapshot", "onvif", "isapi", "mjpeg", "cgi-bin")):
                    add_reason(p, "camera_http_surface", 18)

                if any(x in http_server for x in ("camera", "onvif", "hikvision", "dahua", "reolink")):
                    add_reason(p, "camera_server_banner", 12)

                if any(x in http_ua for x in ("camera", "onvif", "ipcam")):
                    add_reason(p, "camera_user_agent", 10)

                if udp_port == "3702":
                    add_reason(p, "ws_discovery", 12)

                if udp_port == "1900":
                    add_reason(p, "ssdp", 8)

                if any(x in combined for x in IMAGING_HOST_HINTS):
                    add_reason(p, "imaging_hint", 5)

    ranked = []
    for mac, p in profiles.items():
        verdict = "unknown"
        if p["rtsp"] or any(any(x in u for x in ("snapshot", "onvif", "isapi", "mjpeg")) for u in p["http_uris"]):
            verdict = "camera-like with local extractable surface"
        elif p["sni"] and (p["dns"] or p["http_hosts"]) and p["score"] >= 15:
            verdict = "camera-like but encrypted/cloud-mediated"
        elif p["score"] >= 12:
            verdict = "camera-like indicators observed"

        ranked.append({
            "mac": mac,
            "score": p["score"],
            "verdict": verdict,
            "packet_count": p["packet_count"],
            "reasons": p["reasons"][:12],
            "dns": sorted(p["dns"])[:15],
            "sni": sorted(p["sni"])[:15],
            "http_hosts": sorted(p["http_hosts"])[:15],
            "http_uris": sorted(p["http_uris"])[:15],
            "rtsp": sorted(p["rtsp"])[:15],
        })

    ranked.sort(key=lambda x: (x["score"], x["packet_count"]), reverse=True)

    with open(scores_json, "w", encoding="utf-8") as f:
        json.dump({"targets": ranked}, f, indent=2)

    top_mac = ranked[0]["mac"] if ranked else ""
    with open(top_mac_txt, "w", encoding="utf-8") as f:
        f.write(top_mac)

except FileNotFoundError:
    with open(scores_json, "w", encoding="utf-8") as f:
        json.dump({"targets": []}, f, indent=2)
    with open(top_mac_txt, "w", encoding="utf-8") as f:
        f.write("")
PY

TOP_MAC="$(cat "$OUTDIR/top_mac.txt" 2>/dev/null || true)"
if [[ -n "$TOP_MAC" ]]; then
  log "Top detected MAC: $TOP_MAC"
else
  log "No strong MAC candidate found; keeping full capture as evidence"
fi

# =========================
# 6. FILTER TO TOP TARGET
# =========================
if [[ -n "$TOP_MAC" ]]; then
  log "Writing filtered PCAP for top MAC"
  tshark -r "$OUTDIR/capture.pcapng" \
    -Y "wlan.addr == $TOP_MAC" \
    -w "$OUTDIR/filtered_top_target.pcapng" \
    > "$OUTDIR/filter_stdout.txt" 2> "$OUTDIR/filter_stderr.txt" || true
else
  cp "$OUTDIR/capture.pcapng" "$OUTDIR/filtered_top_target.pcapng"
fi

# =========================
# 7. HUMAN-READABLE ANALYSIS
# =========================
log "Writing human-readable analysis"
tshark -r "$OUTDIR/filtered_top_target.pcapng" \
  -Y "dns || tls.handshake.extensions_server_name || http || rtsp" \
  > "$OUTDIR/analysis.txt" 2> "$OUTDIR/analysis_err.txt" || true

# =========================
# 8. EXPORT HTTP OBJECTS
# =========================
log "Exporting HTTP objects"
tshark -r "$OUTDIR/filtered_top_target.pcapng" \
  --export-objects http,"$OUTDIR/http_objects" \
  > "$OUTDIR/http_export_stdout.txt" 2> "$OUTDIR/http_export_stderr.txt" || true

# =========================
# 9. CARVE FILES
# =========================
if command -v foremost >/dev/null 2>&1; then
  log "Carving files with foremost"
  foremost -i "$OUTDIR/filtered_top_target.pcapng" -o "$OUTDIR/carved" \
    > "$OUTDIR/foremost_stdout.txt" 2> "$OUTDIR/foremost_stderr.txt" || true
fi

# =========================
# 10. COLLECT IMAGES
# =========================
log "Collecting extracted images"
find "$OUTDIR/http_objects" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.bmp" -o -iname "*.gif" -o -iname "*.webp" \) -exec cp {} "$OUTDIR/images/" \; 2>/dev/null || true
find "$OUTDIR/carved" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.bmp" -o -iname "*.gif" -o -iname "*.webp" \) -exec cp {} "$OUTDIR/images/" \; 2>/dev/null || true

# =========================
# 11. BUILD SUMMARY
# =========================
TLS_COUNT=$(tshark -r "$OUTDIR/filtered_top_target.pcapng" -Y "tls" 2>/dev/null | wc -l | tr -d ' ')
HTTP_COUNT=$(tshark -r "$OUTDIR/filtered_top_target.pcapng" -Y "http" 2>/dev/null | wc -l | tr -d ' ')
RTSP_COUNT=$(tshark -r "$OUTDIR/filtered_top_target.pcapng" -Y "rtsp" 2>/dev/null | wc -l | tr -d ' ')
DNS_COUNT=$(tshark -r "$OUTDIR/filtered_top_target.pcapng" -Y "dns" 2>/dev/null | wc -l | tr -d ' ')
IMG_COUNT=$(find "$OUTDIR/images" -type f 2>/dev/null | wc -l | tr -d ' ')

VERDICT="NO STRONG CAMERA EVIDENCE"
if [[ "$IMG_COUNT" -gt 0 ]]; then
  VERDICT="LOCAL CAMERA (IMAGE EXTRACTED)"
elif [[ "$RTSP_COUNT" -gt 0 ]]; then
  VERDICT="RTSP CAMERA (LOCAL STREAM OBSERVED)"
elif [[ "$TLS_COUNT" -gt 20 && "$HTTP_COUNT" -eq 0 && "$DNS_COUNT" -gt 0 ]]; then
  VERDICT="CAMERA-LIKE BUT ENCRYPTED/CLOUD-MEDIATED"
elif [[ -f "$OUTDIR/scores.json" ]]; then
  TOP_VERDICT=$(python3 - "$OUTDIR/scores.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1], "r", encoding="utf-8"))
targets = p.get("targets") or []
print(targets[0].get("verdict", "") if targets else "")
PY
)
  if [[ -n "$TOP_VERDICT" && "$TOP_VERDICT" != "unknown" ]]; then
    VERDICT="$TOP_VERDICT"
  fi
fi

cat > "$OUTDIR/report.txt" <<EOF
====== GHOSTRECON AUTO REPORT ======
Run directory: $OUTDIR
Interface: $IFACE
Monitor interface: $MON_IFACE
Capture: $OUTDIR/capture.pcapng
Filtered target PCAP: $OUTDIR/filtered_top_target.pcapng
Top MAC: ${TOP_MAC:-none}

Counts:
  TLS packets: $TLS_COUNT
  HTTP packets: $HTTP_COUNT
  RTSP packets: $RTSP_COUNT
  DNS packets: $DNS_COUNT
  Images found: $IMG_COUNT

VERDICT:
  $VERDICT

Artifacts:
  Analysis: $OUTDIR/analysis.txt
  Scores: $OUTDIR/scores.json
  HTTP objects: $OUTDIR/http_objects
  Carved files: $OUTDIR/carved
  Images: $OUTDIR/images
===================================
EOF

# =========================
# 12. FINAL OUTPUT
# =========================
log "Done"
echo
cat "$OUTDIR/report.txt"
echo
echo "Top scored targets:"
cat "$OUTDIR/scores.json" 
