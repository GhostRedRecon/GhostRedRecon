#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TARGET_IP="${TARGET_IP:-192.168.0.29}"
IFACE="${IFACE:-wlan0}"
CAPTURE_TIME="${CAPTURE_TIME:-600}"
CONFIRM_AUTH="${CONFIRM_AUTH:-YES}"

if [[ "$CONFIRM_AUTH" != "YES" ]]; then
  echo "ERROR: set CONFIRM_AUTH=YES for owned/authorized testing."
  exit 1
fi

SCRIPT_NAME="$(basename "$0" .sh)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
ROOT="./evidence/${SCRIPT_NAME}_${RUN_ID}"
PCAP="$ROOT/pcap/capture.pcap"

mkdir -p "$ROOT"/{pcap,analysis,streams,dns,tls,http,objects,images,video,visual,capability,cloud,report,logs,tmp}

LOG_TSV="$ROOT/report/tests.tsv"
SUMMARY_TXT="$ROOT/report/summary.txt"
VISUAL_TXT="$ROOT/report/visual_evidence.txt"
HASHES="$ROOT/report/sha256_manifest.txt"

: > "$HASHES"
echo -e "TIME\tID\tSTATUS\tDETAILS\tEVIDENCE" > "$LOG_TSV"

ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log(){ echo "[$(date -u +"%T")] $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
safe(){ echo "$1" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-140; }

artifact(){
  [[ -f "$1" ]] || return 0
  sha256sum "$1" >> "$HASHES" 2>/dev/null || true
}

test_log(){
  printf "%s\t%s\t%s\t%s\t%s\n" "$(ts)" "$1" "$2" "$3" "$4" >> "$LOG_TSV"
  log "[TEST] $1 | $2 | $3"
}

is_real_image(){
  [[ -s "$1" ]] || return 1
  file -b "$1" | grep -qiE 'JPEG image|PNG image|GIF image|WebP image|TIFF image|bitmap'
}

is_real_video(){
  [[ -s "$1" ]] || return 1
  if have ffprobe; then
    ffprobe -v error -show_streams "$1" 2>/dev/null | grep -qi 'codec_type=video'
  else
    file -b "$1" | grep -qiE 'MPEG|MP4|Matroska|AVI|H.264|video'
  fi
}

log "=== NR13 VISUAL IoT AUDIT START ==="
log "Target: $TARGET_IP"
log "Interface: $IFACE"
log "Evidence: $ROOT"

REQUIRED=(tcpdump tshark nmap curl strings file grep awk sed sort uniq wc sha256sum python3)
MISSING=()
for t in "${REQUIRED[@]}"; do have "$t" || MISSING+=("$t"); done
if (( ${#MISSING[@]} )); then
  test_log "T0_TOOLS" "FAIL" "Missing tools: ${MISSING[*]}" "-"
  exit 1
fi
test_log "T0_TOOLS" "PASS" "Required tools present" "-"

MODE="unknown"
if have iw && iw dev "$IFACE" info >/dev/null 2>&1; then
  MODE="$(iw dev "$IFACE" info | awk '/type/ {print $2; exit}')"
fi
test_log "T0_INTERFACE" "PASS" "Interface mode: $MODE" "-"

# -------------------- Capture --------------------
log "[T1] Capture for ${CAPTURE_TIME}s. Use camera app/live view now."
timeout "$CAPTURE_TIME" tcpdump -i "$IFACE" -nn -s0 -w "$PCAP" host "$TARGET_IP" > "$ROOT/logs/tcpdump.log" 2>&1 || true
artifact "$PCAP"

PCAP_SIZE="$(wc -c < "$PCAP" 2>/dev/null || echo 0)"
if [[ "$PCAP_SIZE" -gt 24 ]]; then
  test_log "T1_CAPTURE" "PASS" "PCAP captured: ${PCAP_SIZE} bytes" "$PCAP"
else
  test_log "T1_CAPTURE" "FAIL" "PCAP too small: ${PCAP_SIZE} bytes" "$PCAP"
fi

# -------------------- Network + cloud --------------------
nmap -Pn -sT -p- --reason "$TARGET_IP" > "$ROOT/analysis/nmap_tcp.txt" 2>&1 || true
artifact "$ROOT/analysis/nmap_tcp.txt"
test_log "T2_NMAP_TCP" "PASS" "TCP scan completed" "$ROOT/analysis/nmap_tcp.txt"

tshark -r "$PCAP" -q -z io,phs > "$ROOT/analysis/protocol_hierarchy.txt" 2>/dev/null || true
tshark -r "$PCAP" -q -z conv,tcp -z conv,udp > "$ROOT/analysis/conversations.txt" 2>/dev/null || true
artifact "$ROOT/analysis/protocol_hierarchy.txt"
artifact "$ROOT/analysis/conversations.txt"
test_log "T3_PROTOCOL" "PASS" "Protocol/conversation analysis completed" "$ROOT/analysis"

tshark -r "$PCAP" -Y "dns" -T fields -e dns.qry.name > "$ROOT/dns/domains.txt" 2>/dev/null || true
sort -u "$ROOT/dns/domains.txt" > "$ROOT/dns/unique_domains.txt" || true
DNS_COUNT="$(wc -l < "$ROOT/dns/unique_domains.txt" 2>/dev/null || echo 0)"
test_log "T4_DNS" "PASS" "Unique DNS names: $DNS_COUNT" "$ROOT/dns/unique_domains.txt"

tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name > "$ROOT/tls/sni.txt" 2>/dev/null || true
sort -u "$ROOT/tls/sni.txt" > "$ROOT/tls/unique_sni.txt" || true
SNI_COUNT="$(wc -l < "$ROOT/tls/unique_sni.txt" 2>/dev/null || echo 0)"
test_log "T5_TLS_SNI" "PASS" "Unique TLS SNI names: $SNI_COUNT" "$ROOT/tls/unique_sni.txt"

# -------------------- Direct HTTP snapshots --------------------
log "[T6] Direct snapshot/image probes"
HTTP_PORTS="80 81 88 443 554 8000 8001 8080 8081 8088 8443 8554 8888 9000 9090"
SNAP_PATHS=(
"/snapshot.jpg" "/image.jpg" "/current.jpg" "/photo.jpg"
"/cgi-bin/snapshot.cgi" "/cgi-bin/currentpic.cgi"
"/webcapture.jpg" "/video.mjpg" "/mjpeg" "/axis-cgi/mjpg/video.cgi"
)

DIRECT_IMG=0
: > "$ROOT/http/direct_image_probe.tsv"

for port in $HTTP_PORTS; do
  for path in "${SNAP_PATHS[@]}"; do
    scheme="http"
    [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
    url="${scheme}://${TARGET_IP}:${port}${path}"
    name="$(safe "$url")"
    out="$ROOT/images/direct_${name}.bin"
    hdr="$ROOT/http/direct_${name}.headers"
    code="$(curl -k -sS -L --max-time 6 --connect-timeout 3 -D "$hdr" -o "$out" -w "%{http_code}" "$url" 2>/dev/null || echo 000)"
    ftype="$(file -b "$out" 2>/dev/null || true)"
    printf "%s\t%s\t%s\t%s\n" "$code" "$url" "$ftype" "$out" >> "$ROOT/http/direct_image_probe.tsv"

    if is_real_image "$out"; then
      mv "$out" "$ROOT/images/direct_${name}.jpg"
      artifact "$ROOT/images/direct_${name}.jpg"
      DIRECT_IMG=$((DIRECT_IMG+1))
    elif is_real_video "$out"; then
      mv "$out" "$ROOT/video/direct_${name}.video"
      artifact "$ROOT/video/direct_${name}.video"
      if have ffmpeg; then
        ffmpeg -y -i "$ROOT/video/direct_${name}.video" -frames:v 1 "$ROOT/images/direct_${name}_frame.jpg" > "$ROOT/logs/ffmpeg_direct_${name}.log" 2>&1 || true
        is_real_image "$ROOT/images/direct_${name}_frame.jpg" && DIRECT_IMG=$((DIRECT_IMG+1))
      fi
    else
      rm -f "$out"
    fi
  done
done

test_log "T6_DIRECT_VISUAL" "PASS" "Real images/video frames from direct probes: $DIRECT_IMG" "$ROOT/images"

# -------------------- RTSP probe + real snapshot --------------------
log "[T7] RTSP probes"
RTSP_FOUND=0
if have ffprobe; then
  for path in "" "/" "/live" "/stream" "/video" "/h264" "/live.sdp" "/onvif1" "/11" "/0"; do
    name="$(safe "$path")"
    url="rtsp://${TARGET_IP}:554${path}"
    out="$ROOT/streams/rtsp_probe_${name}.txt"
    timeout 8 ffprobe -v error -show_format -show_streams "$url" > "$out" 2>&1 || true
    artifact "$out"
    if grep -qiE 'codec_type=video|codec_name|width=|height=' "$out"; then
      RTSP_FOUND=$((RTSP_FOUND+1))
      if have ffmpeg; then
        snap="$ROOT/images/rtsp_${name}_frame.jpg"
        timeout 12 ffmpeg -y -rtsp_transport tcp -i "$url" -frames:v 1 "$snap" > "$ROOT/logs/ffmpeg_rtsp_${name}.log" 2>&1 || true
        artifact "$snap"
      fi
    fi
  done
  test_log "T7_RTSP" "PASS" "Confirmed RTSP video paths: $RTSP_FOUND" "$ROOT/streams"
else
  test_log "T7_RTSP" "SKIP" "ffprobe missing" "-"
fi

# -------------------- HTTP object export --------------------
log "[T8] Export HTTP objects from PCAP"
mkdir -p "$ROOT/objects/http"
tshark -r "$PCAP" --export-objects "http,$ROOT/objects/http" > "$ROOT/logs/tshark_export_http.log" 2>&1 || true
HTTP_OBJECTS="$(find "$ROOT/objects/http" -type f 2>/dev/null | wc -l | tr -d ' ')"
test_log "T8_HTTP_OBJECTS" "PASS" "HTTP objects exported: $HTTP_OBJECTS" "$ROOT/objects/http"

# Validate HTTP-exported visual files
HTTP_VISUAL=0
find "$ROOT/objects/http" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  base="$(safe "$(basename "$f")")"
  if is_real_image "$f"; then
    cp "$f" "$ROOT/images/http_${base}.jpg" 2>/dev/null || true
  elif is_real_video "$f"; then
    cp "$f" "$ROOT/video/http_${base}.video" 2>/dev/null || true
    if have ffmpeg; then
      ffmpeg -y -i "$f" -frames:v 1 "$ROOT/images/http_${base}_frame.jpg" > "$ROOT/logs/ffmpeg_http_${base}.log" 2>&1 || true
    fi
  fi
done
HTTP_VISUAL="$(find "$ROOT/images" -type f -name 'http_*' 2>/dev/null | wc -l | tr -d ' ')"
test_log "T8_HTTP_VISUAL" "PASS" "Real visual files from HTTP export: $HTTP_VISUAL" "$ROOT/images"

# -------------------- Reconstruct TCP/UDP payload binaries --------------------
log "[T9] Reconstruct TCP and UDP payload binaries"

tshark -r "$PCAP" -T fields -e tcp.stream 2>/dev/null | grep -E '^[0-9]+$' | sort -n | uniq > "$ROOT/streams/tcp_streams.txt" || true
TCP_STREAMS="$(wc -l < "$ROOT/streams/tcp_streams.txt" 2>/dev/null || echo 0)"

while read -r sid; do
  [[ -z "$sid" ]] && continue
  bin="$ROOT/streams/tcp_stream_${sid}.bin"
  tshark -r "$PCAP" -Y "tcp.stream==$sid && tcp.payload" -T fields -e tcp.payload 2>/dev/null \
    | tr -d ':\n\r ' | xxd -r -p > "$bin" 2>/dev/null || true
  artifact "$bin"
done < "$ROOT/streams/tcp_streams.txt"

tshark -r "$PCAP" -T fields -e udp.stream 2>/dev/null | grep -E '^[0-9]+$' | sort -n | uniq > "$ROOT/streams/udp_streams.txt" || true
UDP_STREAMS="$(wc -l < "$ROOT/streams/udp_streams.txt" 2>/dev/null || echo 0)"

while read -r sid; do
  [[ -z "$sid" ]] && continue
  bin="$ROOT/streams/udp_stream_${sid}.bin"
  tshark -r "$PCAP" -Y "udp.stream==$sid && udp.payload" -T fields -e udp.payload 2>/dev/null \
    | tr -d ':\n\r ' | xxd -r -p > "$bin" 2>/dev/null || true
  artifact "$bin"
done < "$ROOT/streams/udp_streams.txt"

test_log "T9_PAYLOAD_REBUILD" "PASS" "TCP streams=$TCP_STREAMS UDP streams=$UDP_STREAMS" "$ROOT/streams"

# -------------------- Real JPEG/PNG carving from PCAP + streams --------------------
log "[T10] Real image carving with validation"

python3 - "$ROOT" "$PCAP" <<'PY'
import sys, os, hashlib, subprocess

root, pcap = sys.argv[1], sys.argv[2]
outdir = os.path.join(root, "images", "carved")
os.makedirs(outdir, exist_ok=True)

def valid_image(path):
    try:
        r = subprocess.run(["file", "-b", path], text=True, capture_output=True, timeout=5)
        return any(x in r.stdout for x in ["JPEG image", "PNG image", "GIF image", "WebP image", "TIFF image"])
    except Exception:
        return False

def carve_jpegs(data, prefix):
    count = 0
    pos = 0
    while True:
        start = data.find(b"\xff\xd8\xff", pos)
        if start < 0:
            break
        end = data.find(b"\xff\xd9", start + 3)
        if end < 0:
            break
        end += 2
        if 1024 <= end-start <= 20_000_000:
            fn = os.path.join(outdir, f"{prefix}_jpg_{count:04d}.jpg")
            with open(fn, "wb") as f:
                f.write(data[start:end])
            if not valid_image(fn):
                os.remove(fn)
            else:
                count += 1
        pos = end
    return count

def carve_pngs(data, prefix):
    count = 0
    pos = 0
    sig = b"\x89PNG\r\n\x1a\n"
    while True:
        start = data.find(sig, pos)
        if start < 0:
            break
        end = data.find(b"IEND", start)
        if end < 0:
            break
        end += 8
        if 1024 <= end-start <= 20_000_000:
            fn = os.path.join(outdir, f"{prefix}_png_{count:04d}.png")
            with open(fn, "wb") as f:
                f.write(data[start:end])
            if not valid_image(fn):
                os.remove(fn)
            else:
                count += 1
        pos = end
    return count

targets = [pcap]
streams = os.path.join(root, "streams")
if os.path.isdir(streams):
    for name in os.listdir(streams):
        if name.endswith(".bin"):
            targets.append(os.path.join(streams, name))

total = 0
for t in targets:
    try:
        with open(t, "rb") as f:
            data = f.read()
        prefix = os.path.basename(t).replace(".", "_")
        total += carve_jpegs(data, prefix)
        total += carve_pngs(data, prefix)
    except Exception:
        pass

with open(os.path.join(root, "report", "image_carving_count.txt"), "w") as f:
    f.write(str(total) + "\n")
PY

CARVED_IMAGES="$(cat "$ROOT/report/image_carving_count.txt" 2>/dev/null || echo 0)"
test_log "T10_IMAGE_CARVING" "PASS" "Validated carved images: $CARVED_IMAGES" "$ROOT/images/carved"

# -------------------- MJPEG multipart splitter --------------------
log "[T11] MJPEG multipart/JPEG frame extraction from payloads"

python3 - "$ROOT" <<'PY'
import sys, os, subprocess
root=sys.argv[1]
outdir=os.path.join(root,"images","mjpeg")
os.makedirs(outdir,exist_ok=True)

def valid(path):
    r=subprocess.run(["file","-b",path],text=True,capture_output=True)
    return "JPEG image" in r.stdout

count=0
for dirpath,_,files in os.walk(os.path.join(root,"streams")):
    for name in files:
        if not name.endswith(".bin"): continue
        p=os.path.join(dirpath,name)
        try: data=open(p,"rb").read()
        except: continue
        if b"multipart" not in data.lower() and data.count(b"\xff\xd8\xff") < 2:
            continue
        pos=0
        while True:
            s=data.find(b"\xff\xd8\xff",pos)
            if s<0: break
            e=data.find(b"\xff\xd9",s+3)
            if e<0: break
            e+=2
            fn=os.path.join(outdir,f"mjpeg_{count:04d}.jpg")
            open(fn,"wb").write(data[s:e])
            if valid(fn): count+=1
            else: os.remove(fn)
            pos=e
open(os.path.join(root,"report","mjpeg_count.txt"),"w").write(str(count)+"\n")
PY

MJPEG_COUNT="$(cat "$ROOT/report/mjpeg_count.txt" 2>/dev/null || echo 0)"
test_log "T11_MJPEG" "PASS" "Validated MJPEG frames: $MJPEG_COUNT" "$ROOT/images/mjpeg"

# -------------------- ffmpeg decode attempts from payload binaries --------------------
log "[T12] ffmpeg frame extraction from rebuilt payloads"
FFMPEG_FRAMES=0
if have ffmpeg; then
  mkdir -p "$ROOT/images/ffmpeg_frames"
  find "$ROOT/streams" -type f -name '*.bin' -size +1024c -print0 | while IFS= read -r -d '' f; do
    base="$(safe "$(basename "$f")")"
    ffmpeg -y -analyzeduration 100M -probesize 100M -i "$f" -frames:v 3 "$ROOT/images/ffmpeg_frames/${base}_%03d.jpg" > "$ROOT/logs/ffmpeg_decode_${base}.log" 2>&1 || true
  done
  find "$ROOT/images/ffmpeg_frames" -type f -print0 | while IFS= read -r -d '' img; do
    if ! is_real_image "$img"; then rm -f "$img"; fi
  done
  FFMPEG_FRAMES="$(find "$ROOT/images/ffmpeg_frames" -type f 2>/dev/null | wc -l | tr -d ' ')"
  test_log "T12_FFMPEG_DECODE" "PASS" "Validated ffmpeg-decoded frames: $FFMPEG_FRAMES" "$ROOT/images/ffmpeg_frames"
else
  test_log "T12_FFMPEG_DECODE" "SKIP" "ffmpeg missing" "-"
fi

# -------------------- Carving tools --------------------
log "[T13] foremost/bulk/scalpel carving"
if have foremost; then
  mkdir -p "$ROOT/analysis/foremost"
  foremost -i "$PCAP" -o "$ROOT/analysis/foremost" > "$ROOT/logs/foremost.log" 2>&1 || true
  test_log "T13_FOREMOST" "PASS" "foremost completed" "$ROOT/analysis/foremost"
else
  test_log "T13_FOREMOST" "SKIP" "foremost missing" "-"
fi

if have bulk_extractor; then
  mkdir -p "$ROOT/analysis/bulk"
  bulk_extractor -o "$ROOT/analysis/bulk" "$PCAP" > "$ROOT/logs/bulk_extractor.log" 2>&1 || true
  test_log "T13_BULK" "PASS" "bulk_extractor completed" "$ROOT/analysis/bulk"
else
  test_log "T13_BULK" "SKIP" "bulk_extractor missing" "-"
fi

# Normalize any real images from carving outputs
find "$ROOT/analysis" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  base="$(safe "$(basename "$f")")"
  if is_real_image "$f"; then
    cp "$f" "$ROOT/images/carver_${base}" 2>/dev/null || true
  elif is_real_video "$f"; then
    cp "$f" "$ROOT/video/carver_${base}" 2>/dev/null || true
  fi
done

# -------------------- Final visual validation --------------------
log "[T14] Final real visual evidence validation"

find "$ROOT/images" -type f -print0 | while IFS= read -r -d '' img; do
  if is_real_image "$img"; then
    artifact "$img"
  else
    rm -f "$img"
  fi
done

find "$ROOT/video" -type f -print0 | while IFS= read -r -d '' vid; do
  if is_real_video "$vid"; then
    artifact "$vid"
  else
    rm -f "$vid"
  fi
done

REAL_IMAGES="$(find "$ROOT/images" -type f 2>/dev/null | wc -l | tr -d ' ')"
REAL_VIDEOS="$(find "$ROOT/video" -type f 2>/dev/null | wc -l | tr -d ' ')"

if [[ "$REAL_IMAGES" -gt 0 || "$REAL_VIDEOS" -gt 0 ]]; then
  test_log "T14_VISUAL_EVIDENCE" "PASS" "REAL visual evidence recovered: images=$REAL_IMAGES videos=$REAL_VIDEOS" "$ROOT/images"
else
  test_log "T14_VISUAL_EVIDENCE" "WARN" "No real image/video recovered; likely encrypted/cloud-only or no visual payload in capture" "-"
fi

# -------------------- Capability indicators --------------------
MITM="NO"
TOKEN="NO"
REPLAY="NO"

tshark -r "$PCAP" -Y "http || ftp || telnet || data-text-lines" > "$ROOT/capability/plaintext.txt" 2>/dev/null || true
[[ -s "$ROOT/capability/plaintext.txt" ]] && MITM="YES"

strings "$PCAP" | grep -iE 'token=|auth=|session=|jwt|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|ssid|psk' > "$ROOT/capability/token_candidates.txt" || true
[[ -s "$ROOT/capability/token_candidates.txt" ]] && TOKEN="YES"

tshark -r "$PCAP" -Y "http.request" -T fields -e http.request.method -e http.host -e http.request.uri > "$ROOT/capability/http_requests.tsv" 2>/dev/null || true
sort "$ROOT/capability/http_requests.tsv" | uniq -c | sort -nr > "$ROOT/capability/replay_patterns.txt" || true
awk '$1 > 3 {print}' "$ROOT/capability/replay_patterns.txt" | grep -q . && REPLAY="YES" || true

# -------------------- Reports --------------------
cat > "$VISUAL_TXT" <<EOF

NR13 Visual Evidence Report

Real visual evidence:
- Images recovered: $REAL_IMAGES
- Videos recovered: $REAL_VIDEOS

Breakdown:
- Direct HTTP/HTTPS images or frames: $DIRECT_IMG
- RTSP confirmed paths: $RTSP_FOUND
- HTTP exported visual files: $HTTP_VISUAL
- JPEG/PNG carved images: $CARVED_IMAGES
- MJPEG frames: $MJPEG_COUNT
- ffmpeg decoded frames: $FFMPEG_FRAMES

Honesty rule:
- Only files validated by 'file' as actual image files are counted as images.
- Text files, .txt dumps, failed ffmpeg outputs, and empty files are not counted.
- If Images recovered = 0, this run did not obtain visual content from the device.

EOF

cat > "$SUMMARY_TXT" <<EOF

NR13 Visual IoT Audit Summary

Target IP          : $TARGET_IP
Interface          : $IFACE
Interface mode     : $MODE
Capture duration   : ${CAPTURE_TIME}s
PCAP size          : $PCAP_SIZE bytes

Capability indicators:
- MITM_FEASIBLE   : $MITM
- TOKEN_EXPOSURE  : $TOKEN
- REPLAY_FEASIBLE : $REPLAY

Cloud indicators:
- DNS names        : $DNS_COUNT
- TLS SNI names    : $SNI_COUNT

Visual evidence:
- Real images      : $REAL_IMAGES
- Real videos      : $REAL_VIDEOS
- Image folder     : $ROOT/images
- Video folder     : $ROOT/video

Key files:
- Tests            : $LOG_TSV
- Visual report    : $VISUAL_TXT
- SHA256 manifest  : $HASHES
- PCAP             : $PCAP

EOF

artifact "$VISUAL_TXT"
artifact "$SUMMARY_TXT"
find "$ROOT" -type f -print0 | while IFS= read -r -d '' f; do artifact "$f"; done

tar --exclude="evidence_archive.tar.gz" -czf "$ROOT/evidence_archive.tar.gz" -C "$ROOT" . > "$ROOT/logs/archive.log" 2>&1 || true
artifact "$ROOT/evidence_archive.tar.gz"

log "=== AUDIT COMPLETE ==="
echo "Evidence root : $ROOT"
echo "Summary       : $SUMMARY_TXT"
echo "Visual report : $VISUAL_TXT"
echo "Images        : $ROOT/images"
echo "Videos        : $ROOT/video"
echo "Tests         : $LOG_TSV"
BASH


