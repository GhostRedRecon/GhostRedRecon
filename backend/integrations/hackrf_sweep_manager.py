from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections import Counter, deque
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional


class HackRFSweepManager:
    BENIGN_STDERR_MARKERS = (
        "call hackrf_",
        "stop with ctrl-c",
        "caught signal",
        "exiting...",
        "total time:",
        "fclose() done",
        "exit",
        "sweeping from ",
        "hz/10.000 mhz",
        "mb/second",
        "average power",
    )
    ERROR_STDERR_MARKERS = (
        "error",
        "failed",
        "unable",
        "not found",
        "resource busy",
        "permission denied",
        "no such device",
        "device busy",
        "invalid",
        "usb transfer error",
    )
    PROFILES: Dict[str, Dict[str, Any]] = {
        "eu_ism": {
            "label": "EU ISM Sweep",
            "freq_min_mhz": 300,
            "freq_max_mhz": 1000,
            "bin_width_hz": 1000000,
        },
        "ism_24": {
            "label": "2.4 GHz Sweep",
            "freq_min_mhz": 2400,
            "freq_max_mhz": 2485,
            "bin_width_hz": 500000,
        },
        "eu_433_868": {
            "label": "EU 433 / 868 Focused Sweep",
            "freq_min_mhz": 430,
            "freq_max_mhz": 870,
            "bin_width_hz": 250000,
        },
        "eu_meter": {
            "label": "EU Utility / Meter Sweep",
            "freq_min_mhz": 868,
            "freq_max_mhz": 870,
            "bin_width_hz": 100000,
        },
        "smart_home_24": {
            "label": "2.4 GHz Smart-Home Sweep",
            "freq_min_mhz": 2400,
            "freq_max_mhz": 2485,
            "bin_width_hz": 250000,
        },
        "drone_24": {
            "label": "Drone 2.4 GHz Sweep",
            "freq_min_mhz": 2400,
            "freq_max_mhz": 2485,
            "bin_width_hz": 500000,
        },
        "drone_58": {
            "label": "Drone 5.8 GHz Sweep",
            "freq_min_mhz": 5725,
            "freq_max_mhz": 5850,
            "bin_width_hz": 1000000,
        },
        "full_redteam": {
            "label": "Full Red-Team Sweep",
            "freq_min_mhz": 300,
            "freq_max_mhz": 2700,
            "bin_width_hz": 1000000,
        },
    }
    LAB_DIR = Path("/home/ghost/Documents/GhostRedRecon/rf_lab")

    def __init__(self) -> None:
        self.binary = which("hackrf_sweep")
        self.process: Optional[subprocess.Popen[str]] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.logs: deque[str] = deque(maxlen=40)
        self.rows: deque[Dict[str, Any]] = deque(maxlen=200)
        self.started_at: Optional[float] = None
        self.completed_at: Optional[float] = None
        self.last_error: str = ""
        self.last_exit_code: Optional[int] = None
        self.profile_key: str = ""
        self.running: bool = False
        self.completed: bool = False
        self.row_annotations: Dict[str, Dict[str, Any]] = {}
        self.auto_decode_queue: deque[str] = deque()
        self.auto_decode_running: bool = False
        self.auto_decode_mode: str = "idle"
        self.auto_decode_started_at: Optional[float] = None
        self.auto_decode_completed_at: Optional[float] = None
        self.auto_decode_stop_requested: bool = False
        self.auto_decode_current_row_id: str = ""
        self._lock = threading.RLock()
        self.LAB_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _classify_peak(peak_mhz: float) -> Dict[str, str]:
        freq = float(peak_mhz or 0.0)
        if 2401.5 <= freq <= 2402.5:
            return {"family": "BLE Advertising", "recommended_tab": "Bluetooth", "action": "Run BLE sweep on ADV37 / 2402 MHz."}
        if 2425.5 <= freq <= 2426.5:
            return {"family": "BLE Advertising", "recommended_tab": "Bluetooth", "action": "Run BLE sweep on ADV38 / 2426 MHz."}
        if 2479.5 <= freq <= 2480.5:
            return {"family": "BLE / Zigbee Overlap", "recommended_tab": "Bluetooth or Zigbee", "action": "Check BLE ADV39 and Zigbee CH26 for overlap."}
        if 2404.5 <= freq <= 2475.5 and ((freq - 2405.0) % 5.0) < 0.51:
            return {"family": "Zigbee / 802.15.4", "recommended_tab": "Zigbee", "action": "Run Zigbee sweep on the nearest 802.15.4 channel."}
        if any(abs(freq - channel) <= 1.5 for channel in (2412.0, 2437.0, 2462.0)):
            return {"family": "WiFi 2.4 GHz", "recommended_tab": "WiFi", "action": "Run WiFi sweep and correlate with Kismet if available."}
        if 5725.0 <= freq <= 5850.0:
            return {"family": "5.8 GHz Drone / WiFi Link", "recommended_tab": "Hunt Drones", "action": "Correlate this 5.8 GHz peak with Hunt Drones Wi-Fi detections and controller activity."}
        if any(abs(freq - channel) <= 1.0 for channel in (868.1, 868.3, 868.5, 915.0)):
            return {"family": "LoRa / LPWAN", "recommended_tab": "LoRa", "action": "Run the LoRa tab and check EU868/US915 profile alignment."}
        if any(abs(freq - channel) <= 0.75 for channel in (433.92, 868.30, 868.95, 869.525)):
            return {"family": "EU ISM / Sub-GHz", "recommended_tab": "433/868 Decoder", "action": "Run 433/868 Decoder or Sub-GHz sweep at this center."}
        if 433.0 <= freq <= 434.8 or 863.0 <= freq <= 870.0:
            return {"family": "EU ISM / Sub-GHz", "recommended_tab": "433/868 Decoder", "action": "Run 433/868 Decoder first, then capture to Signal Lab if no protocol is decoded."}
        return {"family": "Unknown RF Hotspot", "recommended_tab": "Signal Lab", "action": "Capture and inspect this peak in Signal Lab."}

    def is_installed(self) -> bool:
        return bool(self.binary)

    @staticmethod
    def _confidence_label(peak_db: float) -> str:
        if peak_db > -55:
            return "high"
        if peak_db > -70:
            return "medium"
        return "low"

    @staticmethod
    def _row_id(row: Dict[str, Any]) -> str:
        captured_at = str(row.get("captured_at") or "unknown").replace(" ", "_")
        hz_low = int(float(row.get("hz_low") or 0.0))
        peak_mhz = str(row.get("peak_mhz") or 0.0).replace(".", "p")
        return f"{captured_at}_{hz_low}_{peak_mhz}"

    def _decorate_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        lead = self._classify_peak(row.get("peak_mhz", 0.0))
        peak_db = float(row.get("peak_db", -999.0))
        decorated = {
            **row,
            "row_id": self._row_id(row),
            "confidence": self._confidence_label(peak_db),
            "family": lead["family"],
            "recommended_tab": lead["recommended_tab"],
            "action": lead["action"],
        }
        return self._merge_annotation(decorated)

    def _risk_label(self, row: Dict[str, Any]) -> str:
        family = str(row.get("family") or "")
        recommended_tab = str(row.get("recommended_tab") or "")
        if "Overlap" in family:
            return "possible overlap"
        if family in {"EU ISM / Sub-GHz", "LoRa / LPWAN"}:
            return "wireless utility"
        if recommended_tab == "Zigbee":
            return "mesh device"
        if recommended_tab == "WiFi":
            return "likely consumer IoT"
        if recommended_tab == "Bluetooth":
            return "likely consumer IoT"
        return "unknown hotspot"

    def _base_tags(self, row: Dict[str, Any]) -> List[str]:
        tags: List[str] = []
        if row.get("confidence") in {"high", "medium"}:
            tags.append("recon-first")
        risk = self._risk_label(row)
        if risk == "likely consumer IoT":
            tags.append("likely consumer IoT")
        if risk == "wireless utility":
            tags.append("possible utility")
        if risk == "possible overlap":
            tags.append("possible overlap")
        if row.get("confidence") == "high" or float(row.get("peak_db", -999.0)) > -60.0:
            tags.append("high-value")
        return tags

    def _default_annotation(self, row: Dict[str, Any]) -> Dict[str, Any]:
        tags = self._base_tags(row)
        return {
            "retention_state": "new",
            "operator_priority": "normal",
            "risk_label": self._risk_label(row),
            "tags": tags,
            "decode_status": "new",
            "decode_attempts": 0,
            "last_decode_at": None,
            "last_decode_summary": "",
            "last_decode_result": None,
            "evidence_summary": {
                "live_signals": 0,
                "matched_devices": 0,
                "top_vendor_hint": "",
                "protocol_confidence": row.get("confidence") or "low",
            },
        }

    def _merge_annotation(self, row: Dict[str, Any]) -> Dict[str, Any]:
        row_id = str(row.get("row_id") or "")
        if not row_id:
            return row
        annotation = self.row_annotations.setdefault(row_id, self._default_annotation(row))
        merged_tags = list(dict.fromkeys([*(self._base_tags(row)), *(annotation.get("tags") or [])]))
        annotation["tags"] = merged_tags
        annotation.setdefault("risk_label", self._risk_label(row))
        annotation.setdefault("retention_state", "new")
        annotation.setdefault("operator_priority", "normal")
        annotation.setdefault("decode_status", "new")
        annotation.setdefault("decode_attempts", 0)
        annotation.setdefault("last_decode_at", None)
        annotation.setdefault("last_decode_summary", "")
        annotation.setdefault("last_decode_result", None)
        annotation.setdefault("evidence_summary", {
            "live_signals": 0,
            "matched_devices": 0,
            "top_vendor_hint": "",
            "protocol_confidence": row.get("confidence") or "low",
        })
        return {**row, **annotation}

    def update_row_annotation(self, row_id: str, **updates: Any) -> Dict[str, Any]:
        with self._lock:
            annotation = self.row_annotations.setdefault(str(row_id), {})
            for key, value in updates.items():
                if key == "tags" and value is not None:
                    annotation[key] = list(dict.fromkeys(str(tag) for tag in value if tag))
                elif key == "evidence_summary" and isinstance(value, dict):
                    current = dict(annotation.get("evidence_summary") or {})
                    current.update(value)
                    annotation[key] = current
                else:
                    annotation[key] = value
            return dict(annotation)

    def queue_rows(self, row_ids: List[str], mode: str) -> Dict[str, Any]:
        with self._lock:
            self.auto_decode_queue.clear()
            for row_id in row_ids:
                self.auto_decode_queue.append(str(row_id))
                self.update_row_annotation(str(row_id), decode_status="queued")
            self.auto_decode_running = True
            self.auto_decode_mode = mode
            self.auto_decode_started_at = time.time()
            self.auto_decode_completed_at = None
            self.auto_decode_stop_requested = False
            self.auto_decode_current_row_id = ""
            return self.get_queue_state()

    def request_queue_stop(self) -> Dict[str, Any]:
        with self._lock:
            self.auto_decode_running = False
            self.auto_decode_stop_requested = True
            self.auto_decode_current_row_id = ""
            self.auto_decode_completed_at = time.time()
            self.auto_decode_mode = "stopped"
            return self.get_queue_state()

    def queue_next_row(self) -> Optional[str]:
        with self._lock:
            if not self.auto_decode_queue:
                self.auto_decode_running = False
                self.auto_decode_mode = "idle"
                self.auto_decode_current_row_id = ""
                self.auto_decode_completed_at = time.time()
                return None
            row_id = self.auto_decode_queue.popleft()
            self.auto_decode_current_row_id = row_id
            self.update_row_annotation(row_id, decode_status="decoding", retention_state="triaged")
            return row_id

    def complete_queue_row(self, row_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        status = str(result.get("status") or "decoded")
        evidence_summary = {
            "live_signals": int(result.get("signal_count") or len(result.get("decoded_events") or [])),
            "matched_devices": int(result.get("matched_device_count") or 0),
            "top_vendor_hint": "",
            "protocol_confidence": "high" if status == "decoded" else "medium" if status == "no_decode" else "low",
        }
        devices = result.get("devices") or []
        decoded_events = result.get("decoded_events") or []
        if devices and isinstance(devices, list):
            evidence_summary["top_vendor_hint"] = str((devices[0] or {}).get("vendor") or "")
        elif decoded_events and isinstance(decoded_events, list):
            first_event = decoded_events[0] or {}
            evidence_summary["top_vendor_hint"] = str(first_event.get("brand") or first_event.get("model") or "")
        elif result.get("top_brands"):
            evidence_summary["top_vendor_hint"] = str(result["top_brands"][0][0])
        retention_state = "decoded" if status == "decoded" else "needs_capture" if status == "no_decode" else "triaged"
        summary = str(result.get("message") or result.get("strategy", {}).get("action") or "")
        annotation = self.update_row_annotation(
            row_id,
            decode_status=status,
            retention_state=retention_state,
            decode_attempts=int((self.row_annotations.get(row_id, {}) or {}).get("decode_attempts") or 0) + 1,
            last_decode_at=time.time(),
            last_decode_summary=summary,
            last_decode_result=result,
            evidence_summary=evidence_summary,
        )
        with self._lock:
            self.auto_decode_current_row_id = ""
            if not self.auto_decode_queue:
                self.auto_decode_running = False
                self.auto_decode_mode = "idle"
                self.auto_decode_completed_at = time.time()
        return annotation

    def get_queue_state(self) -> Dict[str, Any]:
        pending = []
        current_rows = {row.get("row_id"): row for row in [self._decorate_row(row) for row in list(self.rows)]}
        for row_id in list(self.auto_decode_queue)[:10]:
            row = current_rows.get(row_id) or {"row_id": row_id}
            pending.append({
                "row_id": row_id,
                "peak_mhz": row.get("peak_mhz"),
                "family": row.get("family"),
                "retention_state": row.get("retention_state"),
                "decode_status": row.get("decode_status"),
            })
        return {
            "running": self.auto_decode_running,
            "mode": self.auto_decode_mode,
            "started_at": self.auto_decode_started_at,
            "completed_at": self.auto_decode_completed_at,
            "stop_requested": self.auto_decode_stop_requested,
            "current_row_id": self.auto_decode_current_row_id,
            "pending_count": len(self.auto_decode_queue),
            "pending_rows": pending,
        }

    def start(self, profile_key: str = "eu_ism") -> Dict[str, Any]:
        with self._lock:
            if not self.binary:
                return {"status": "unavailable", "error": "hackrf_sweep is not installed on this host."}

            profile = self.PROFILES.get(profile_key) or self.PROFILES["eu_ism"]
            if self.process and self.process.poll() is None:
                return {"status": "already_running", "profile_key": self.profile_key}

            self.logs.clear()
            self.rows.clear()
            self.last_error = ""
            self.last_exit_code = None
            self.completed = False
            self.completed_at = None
            self.started_at = time.time()
            self.profile_key = profile_key if profile_key in self.PROFILES else "eu_ism"

            cmd = [
                self.binary,
                "-1",
                "-f",
                f"{profile['freq_min_mhz']}:{profile['freq_max_mhz']}",
                "-w",
                str(profile["bin_width_hz"]),
            ]

            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                self.running = True
                self.scan_thread = threading.Thread(target=self._reader_loop, daemon=True)
                self.scan_thread.start()
                return {"status": "started", "profile_key": self.profile_key}
            except Exception as exc:
                self.process = None
                self.running = False
                self.last_error = str(exc)
                return {"status": "failed", "error": str(exc)}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self.process:
                self.running = False
                return {"status": "idle"}
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.last_exit_code = self.process.poll()
            self.process = None
            self.running = False
            self.completed = True
            self.completed_at = time.time()
            return {"status": "stopped", "exit_code": self.last_exit_code}

    def _ingest_csv_row(self, line: str) -> None:
        if (
            not line
            or line.startswith("call ")
            or line.startswith("Sweeping from ")
            or line.startswith("Stop with Ctrl-C")
            or line.startswith("Exiting")
            or line.startswith("Total sweeps:")
            or line.startswith("hackrf_")
            or line == "exit"
            or line.startswith("date, time, hz_low")
        ):
            return
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 7:
            self.logs.append(line)
            return
        try:
            date_part = parts[0]
            time_part = parts[1]
            hz_low = float(parts[2])
            hz_high = float(parts[3])
            hz_bin_width = float(parts[4])
            power_values = [float(value) for value in parts[6:] if value]
        except Exception:
            self.logs.append(line)
            return

        if not power_values:
            return

        peak_power = max(power_values)
        peak_index = power_values.index(peak_power)
        peak_hz = hz_low + (peak_index * hz_bin_width)
        center_hz = (hz_low + hz_high) / 2.0
        self.rows.appendleft({
            "timestamp": time.time(),
            "captured_at": f"{date_part} {time_part}",
            "hz_low": hz_low,
            "hz_high": hz_high,
            "center_mhz": center_hz / 1_000_000.0,
            "peak_mhz": peak_hz / 1_000_000.0,
            "peak_db": peak_power,
            "bin_width_khz": hz_bin_width / 1000.0,
        })

    def _reader_loop(self) -> None:
        process = self.process
        if not process:
            return

        if process.stderr:
            def classify_stderr(line: str) -> str:
                lowered = line.lower()
                if any(marker in lowered for marker in self.ERROR_STDERR_MARKERS):
                    return "error"
                if any(marker in lowered for marker in self.BENIGN_STDERR_MARKERS):
                    return "benign"
                return "info"

            def consume_stderr() -> None:
                for line in process.stderr:
                    cleaned = (line or "").replace("\x00", " ").strip()
                    if not cleaned:
                        continue
                    classification = classify_stderr(cleaned)
                    if classification != "benign":
                        self.logs.append(cleaned)
                    if classification == "error":
                        self.last_error = cleaned
            threading.Thread(target=consume_stderr, daemon=True).start()

        if process.stdout:
            for line in process.stdout:
                cleaned = (line or "").strip()
                if not cleaned:
                    continue
                self._ingest_csv_row(cleaned)

        try:
            self.last_exit_code = process.wait(timeout=1)
        except Exception:
            self.last_exit_code = process.poll()
        finally:
            with self._lock:
                if self.last_exit_code not in (None, 0, -15, 130, 143) and not self.last_error:
                    self.last_error = f"hackrf_sweep exited unexpectedly with code {self.last_exit_code}."
                self.running = False
                self.completed = True
                self.completed_at = time.time()
                self.process = None

    def get_state(self) -> Dict[str, Any]:
        profile = self.PROFILES.get(self.profile_key) or self.PROFILES.get("eu_ism") or {}
        decorated_rows = [self._decorate_row(row) for row in list(self.rows)]
        top_peaks = sorted(decorated_rows, key=lambda row: row.get("peak_db", -999.0), reverse=True)[:12]
        target_leads = []
        family_counts: Counter[str] = Counter()
        recent_rows = list(decorated_rows[:60])
        recent_timestamps = [float(row.get("timestamp") or 0.0) for row in recent_rows if row.get("timestamp")]
        time_span = max(1.0, (max(recent_timestamps) - min(recent_timestamps))) if recent_timestamps else 1.0
        noise_floor_db = (
            sum(float(row.get("peak_db") or -110.0) for row in recent_rows[-12:]) / max(1, len(recent_rows[-12:]))
            if recent_rows else -92.0
        )
        cluster_map: Dict[str, Dict[str, Any]] = {}
        for row in recent_rows:
            peak_mhz = float(row.get("peak_mhz") or 0.0)
            family = str(row.get("family") or "Unknown")
            cluster_center = round(peak_mhz / 4.0) * 4.0
            key = f"{family}:{cluster_center:.1f}"
            cluster = cluster_map.setdefault(
                key,
                {
                    "family": family,
                    "cluster_center_mhz": cluster_center,
                    "rows": [],
                    "strongest": row,
                },
            )
            cluster["rows"].append(row)
            if float(row.get("peak_db") or -999.0) > float(cluster["strongest"].get("peak_db") or -999.0):
                cluster["strongest"] = row
        ranked_clusters = sorted(
            cluster_map.values(),
            key=lambda cluster: (
                len(cluster["rows"]),
                float(cluster["strongest"].get("peak_db") or -999.0),
            ),
            reverse=True,
        )[:10]
        for cluster in ranked_clusters:
            row = cluster["strongest"]
            family_counts[row["family"]] += 1
            recurrence = len(cluster["rows"])
            density = min(1.0, recurrence / time_span)
            persistence = min(1.0, recurrence / max(3, len(recent_rows)))
            target_leads.append({
                "peak_mhz": row.get("peak_mhz"),
                "peak_db": row.get("peak_db"),
                "family": row["family"],
                "recommended_tab": row["recommended_tab"],
                "action": row["action"],
                "confidence": row["confidence"],
                "row_id": row["row_id"],
                "timestamp": float(row.get("timestamp") or 0.0),
                "noise_floor_db": noise_floor_db,
                "burst_density": round(density, 3),
                "burst_recurrence": recurrence,
                "rolling_persistence": round(persistence, 3),
                "cluster_peak_list_mhz": [round(float(item.get("peak_mhz") or 0.0), 1) for item in cluster["rows"][:8]],
            })
        verified_detection_count = len([row for row in decorated_rows if float(row.get("peak_db", -999.0)) > -70.0])
        top_family = family_counts.most_common(1)[0][0] if family_counts else "Unknown"
        if self.running:
            status_detail = "running"
        elif self.last_error:
            status_detail = "completed_with_error" if self.completed else "idle_with_error"
        elif self.completed and verified_detection_count:
            status_detail = "completed_with_detections"
        elif self.completed and self.rows:
            status_detail = "completed_with_weak_peaks"
        elif self.completed:
            status_detail = "completed_no_peaks"
        else:
            status_detail = "idle"
        return {
            "installed": self.is_installed(),
            "binary": self.binary,
            "running": self.running,
            "completed": self.completed,
            "status_detail": status_detail,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "last_error": self.last_error,
            "last_exit_code": self.last_exit_code,
            "profile_key": self.profile_key,
            "profile": profile,
            "row_count": len(self.rows),
            "verified_detection_count": verified_detection_count,
            "top_family": top_family,
            "family_counts": dict(family_counts),
            "top_peaks": top_peaks,
            "target_leads": target_leads,
            "recent_rows": decorated_rows[:25],
            "table_rows": decorated_rows[:50],
            "recent_logs": list(self.logs)[:20],
            "profiles": self.PROFILES,
            "queue": self.get_queue_state(),
        }

    def capture_peak(self, peak_mhz: float, family: str = "", notes: str = "") -> Dict[str, Any]:
        lead = self._classify_peak(peak_mhz)
        safe_family = (family or lead["family"] or "unknown").replace("/", "_").replace(" ", "_").lower()
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        target_path = self.LAB_DIR / f"wb_hunt_peak_{safe_family}_{str(peak_mhz).replace('.', 'p')}_{timestamp}.json"
        payload = {
            "captured_at": timestamp,
            "source": "wb_hunt",
            "peak_mhz": float(peak_mhz),
            "family": family or lead["family"],
            "recommended_tab": lead["recommended_tab"],
            "action": lead["action"],
            "profile_key": self.profile_key,
            "profile": self.PROFILES.get(self.profile_key) or self.PROFILES.get("eu_ism"),
            "notes": notes or "Captured from WB Hunt for follow-up in Signal Lab.",
            "top_rows_snapshot": list(self.rows)[:12],
        }
        with target_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return {
            "status": "captured",
            "path": str(target_path),
            "filename": target_path.name,
            "peak_mhz": float(peak_mhz),
            "family": payload["family"],
            "recommended_tab": payload["recommended_tab"],
        }
