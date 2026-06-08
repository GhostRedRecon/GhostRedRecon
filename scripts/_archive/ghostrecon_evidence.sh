#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}

CAMERA_KEYWORDS = (
    "camera", "ipcam", "onvif", "rtsp", "snapshot", "mjpeg", "mjpg",
    "hikvision", "dahua", "reolink", "tapo", "arlo", "ring", "eufy",
    "doorbell", "isapi", "cgi-bin"
)

def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")

def run(cmd: list[str], timeout: int = 120, cwd: Path | None = None) -> dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "cmd": cmd,
        }
    except Exception as e:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": str(e), "cmd": cmd}

def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"Missing required tool: {name}")
    return path

def safe_copy(src: Path, dst_dir: Path) -> str:
    dst_dir.mkdir(parents=True, exist_ok=True)
    target = dst_dir / src.name
    stem = src.stem
    suffix = src.suffix
    i = 1
    while target.exists():
        target = dst_dir / f"{stem}_{i}{suffix}"
        i += 1
    shutil.copy2(src, target)
    return str(target)

def parse_fields_csv(csv_path: Path) -> dict[str, Any]:
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return {
            "dns_names": [],
            "tls_sni": [],
            "http_hosts": [],
            "http_uris": [],
            "rtsp_urls": [],
            "camera_hits": [],
            "local_extractable": False,
            "encrypted_camera_like": False,
        }

    dns_names: set[str] = set()
    tls_sni: set[str] = set()
    http_hosts: set[str] = set()
    http_uris: set[str] = set()
    rtsp_urls: set[str] = set()
    camera_hits: set[str] = set()
    saw_tls = False
    saw_rtsp = False
    saw_http = False

    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for field in ("dns.qry.name", "dns.resp.name"):
                v = (row.get(field) or "").strip()
                if v:
                    dns_names.add(v)
                    if any(k in v.lower() for k in CAMERA_KEYWORDS):
                        camera_hits.add(v)

            sni = (row.get("tls.handshake.extensions_server_name") or "").strip()
            if sni:
                saw_tls = True
                tls_sni.add(sni)
                if any(k in sni.lower() for k in CAMERA_KEYWORDS):
                    camera_hits.add(sni)

            host = (row.get("http.host") or "").strip()
            uri = (row.get("http.request.uri") or "").strip()
            if host:
                saw_http = True
                http_hosts.add(host)
                if any(k in host.lower() for k in CAMERA_KEYWORDS):
                    camera_hits.add(host)
            if uri:
                saw_http = True
                http_uris.add(uri)
                if any(k in uri.lower() for k in CAMERA_KEYWORDS):
                    camera_hits.add(uri)

            rtsp = (row.get("rtsp.url") or "").strip()
            if rtsp:
                saw_rtsp = True
                rtsp_urls.add(rtsp)
                camera_hits.add(rtsp)

    local_extractable = bool(rtsp_urls) or any(
        any(k in uri.lower() for k in ("snapshot", "onvif", "isapi", "mjpeg", "cgi-bin"))
        for uri in http_uris
    )

    encrypted_camera_like = bool(camera_hits) and saw_tls and not local_extractable and not saw_rtsp

    return {
        "dns_names": sorted(dns_names)[:50],
        "tls_sni": sorted(tls_sni)[:50],
        "http_hosts": sorted(http_hosts)[:50],
        "http_uris": sorted(http_uris)[:50],
        "rtsp_urls": sorted(rtsp_urls)[:50],
        "camera_hits": sorted(camera_hits)[:50],
        "local_extractable": local_extractable,
        "encrypted_camera_like": encrypted_camera_like,
    }

def find_images(root: Path) -> list[str]:
    out: list[str] = []
    if not root.exists():
        return out
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in IMAGE_EXTS:
            out.append(str(p))
    return sorted(out)

def main() -> int:
    ap = argparse.ArgumentParser(description="Owned-device camera audit and evidence collector")
    ap.add_argument("--pcap", required=True, help="Path to pcap/pcapng")
    ap.add_argument("--label", default="device", help="Label for this audit run")
    ap.add_argument("--outdir", default="", help="Output directory")
    ap.add_argument("--extract-http", action="store_true", help="Export HTTP objects")
    ap.add_argument("--carve", action="store_true", help="Run foremost file carving")
    ap.add_argument("--target-mac", default="", help="Optional target MAC to include in report")
    args = ap.parse_args()

    tshark = require_tool("tshark")
    outdir = Path(args.outdir).expanduser() if args.outdir else Path.cwd() / f"audit_{args.label}_{now_ts()}"
    outdir.mkdir(parents=True, exist_ok=True)

    pcap = Path(args.pcap).expanduser()
    if not pcap.exists():
        raise SystemExit(f"PCAP not found: {pcap}")

    shutil.copy2(pcap, outdir / pcap.name)

    fields_csv = outdir / "fields.csv"
    fields_cmd = [
        tshark, "-r", str(pcap),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.protocols",
        "-e", "wlan.sa",
        "-e", "wlan.da",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.qry.name",
        "-e", "dns.resp.name",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.server",
        "-e", "rtsp.url",
    ]
    fields_res = run(fields_cmd, timeout=300)
    fields_csv.write_text(fields_res.get("stdout", ""), encoding="utf-8")

    analysis = parse_fields_csv(fields_csv)

    analysis_txt = outdir / "analysis.txt"
    filt = "dns || tls.handshake.extensions_server_name || http || rtsp"
    analysis_res = run([tshark, "-r", str(pcap), "-Y", filt], timeout=300)
    analysis_txt.write_text(analysis_res.get("stdout", ""), encoding="utf-8")

    extracted_images: list[str] = []
    if args.extract_http:
        http_dir = outdir / "http_objects"
        http_dir.mkdir(parents=True, exist_ok=True)
        run([tshark, "-r", str(pcap), "--export-objects", f"http,{http_dir}"], timeout=300)
        extracted_images.extend(find_images(http_dir))

    if args.carve:
        foremost = shutil.which("foremost")
        if foremost:
            carve_dir = outdir / "carved"
            run([foremost, "-i", str(pcap), "-o", str(carve_dir)], timeout=300)
            extracted_images.extend(find_images(carve_dir))

    evidence_dir = outdir / "evidence_images"
    saved_images: list[str] = []
    for img in sorted(set(extracted_images)):
        saved_images.append(safe_copy(Path(img), evidence_dir))

    verdict = "unknown"
    if analysis["local_extractable"]:
        verdict = "camera-like with local extractable surface"
    elif analysis["encrypted_camera_like"]:
        verdict = "camera-like but encrypted/cloud-mediated"
    elif analysis["camera_hits"]:
        verdict = "camera-like indicators observed"
    else:
        verdict = "no strong camera-specific indicators"

    report = {
        "generated_at": int(time.time()),
        "label": args.label,
        "target_mac": args.target_mac,
        "pcap": str(pcap),
        "outdir": str(outdir),
        "verdict": verdict,
        "camera_hits": analysis["camera_hits"],
        "local_extractable": analysis["local_extractable"],
        "encrypted_camera_like": analysis["encrypted_camera_like"],
        "dns_names": analysis["dns_names"],
        "tls_sni": analysis["tls_sni"],
        "http_hosts": analysis["http_hosts"],
        "http_uris": analysis["http_uris"],
        "rtsp_urls": analysis["rtsp_urls"],
        "saved_images": saved_images,
        "counts": {
            "saved_image_count": len(saved_images),
        },
        "notes": [
            "This script audits owned-device traffic and preserves evidence.",
            "It does not bypass encryption or authentication.",
            "No images usually means encrypted/cloud-mediated media, not necessarily script failure.",
        ],
    }

    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = [
        f"Label: {args.label}",
        f"PCAP: {pcap}",
        f"Verdict: {verdict}",
        f"Target MAC: {args.target_mac or '--'}",
        f"Saved images: {len(saved_images)}",
        "",
        "Camera hits:",
        *[f"- {x}" for x in analysis["camera_hits"]],
        "",
        "RTSP URLs:",
        *[f"- {x}" for x in analysis["rtsp_urls"]],
        "",
        "HTTP hosts:",
        *[f"- {x}" for x in analysis["http_hosts"]],
        "",
        "TLS SNI:",
        *[f"- {x}" for x in analysis["tls_sni"]],
    ]
    (outdir / "summary.txt").write_text("\n".join(summary).strip() + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "verdict": verdict,
        "outdir": str(outdir),
        "saved_image_count": len(saved_images),
        "saved_images": saved_images,
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
