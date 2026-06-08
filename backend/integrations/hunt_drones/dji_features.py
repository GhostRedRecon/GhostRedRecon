from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from typing import Any, Dict, Iterable, List


class SDRBurstLockEngine:
    DJI_CENTER_FREQS_MHZ = (
        2399.5,
        2414.5,
        2429.5,
        2444.5,
        2459.5,
        5756.5,
        5776.5,
        5796.5,
    )

    @classmethod
    def _nearest_center(cls, peak_mhz: float) -> float:
        return min(cls.DJI_CENTER_FREQS_MHZ, key=lambda center: abs(float(peak_mhz) - center))

    def build_locks(self, rows: Iterable[Dict[str, Any]], now: float | None = None) -> List[Dict[str, Any]]:
        current_time = float(now or time.time())
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for item in rows or []:
            peak_mhz = float(item.get("peak_mhz") or 0.0)
            nearest = self._nearest_center(peak_mhz)
            if abs(peak_mhz - nearest) > 28.0:
                continue
            band = "5.8 GHz" if peak_mhz >= 5000.0 else "2.4 GHz"
            key = f"{band}:{nearest:.1f}"
            grouped[key].append(dict(item))

        locks: List[Dict[str, Any]] = []
        for key, cluster in grouped.items():
            cluster = sorted(
                cluster,
                key=lambda item: (
                    float(item.get("burst_recurrence") or 0.0),
                    float(item.get("rolling_persistence") or 0.0),
                    float(item.get("peak_db") or -999.0),
                ),
                reverse=True,
            )
            strongest = cluster[0]
            recurrence = max(float(item.get("burst_recurrence") or 0.0) for item in cluster)
            persistence = max(float(item.get("rolling_persistence") or 0.0) for item in cluster)
            density = max(float(item.get("burst_density") or 0.0) for item in cluster)
            peak_list = [round(float(item.get("peak_mhz") or 0.0), 1) for item in cluster[:12]]
            nearest_center = self._nearest_center(float(strongest.get("peak_mhz") or 0.0))
            lock_state = "watch"
            if recurrence >= 3 or persistence >= 0.32 or density >= 0.45:
                lock_state = "candidate_lock"
            if recurrence >= 5 or (persistence >= 0.5 and density >= 0.4):
                lock_state = "burst_locked"
            lock_strength = min(
                100,
                int(
                    28
                    + recurrence * 9
                    + persistence * 24
                    + density * 18
                    + max(0.0, (float(strongest.get("peak_db") or -100.0) + 80.0))
                ),
            )
            lock_id = hashlib.sha1(f"{key}|{peak_list[:4]}".encode("utf-8")).hexdigest()[:14]
            sample_window = {
                "window_id": f"sample-{lock_id}",
                "relative_start_sec": max(0.0, current_time - float(strongest.get("timestamp") or current_time)),
                "duration_ms": 1200 if lock_state == "burst_locked" else 650,
                "row_ids": [str(item.get("row_id") or "") for item in cluster[:8]],
                "reference": f"sdr/iq_snippets/{lock_id}.json",
            }
            locks.append(
                {
                    "lock_id": lock_id,
                    "lock_state": lock_state,
                    "lock_strength": lock_strength,
                    "band": key.split(":")[0],
                    "nearest_center_mhz": nearest_center,
                    "peak_list_mhz": peak_list,
                    "burst_recurrence": recurrence,
                    "burst_density": round(density, 3),
                    "rolling_persistence": round(persistence, 3),
                    "strongest_peak_db": float(strongest.get("peak_db") or -110.0),
                    "first_seen": min(float(item.get("timestamp") or current_time) for item in cluster),
                    "last_seen": max(float(item.get("timestamp") or current_time) for item in cluster),
                    "sample_window": sample_window,
                    "row_ids": sample_window["row_ids"],
                }
            )
        locks.sort(key=lambda item: (int(item.get("lock_strength") or 0), float(item.get("burst_recurrence") or 0.0)), reverse=True)
        return locks[:12]


class AdditiveUAVEnrichmentService:
    MANUFACTURER_HINTS = {
        "dji": "DJI Family",
        "autel": "Autel Family",
        "parrot": "Parrot Family",
        "skydio": "Skydio Family",
        "ryze": "Ryze / DJI Family",
        "tello": "Ryze / DJI Family",
    }

    def enrich(self, row: Dict[str, Any]) -> Dict[str, Any]:
        item = dict(row)
        ssid = str(item.get("ssid") or "").strip().lower()
        vendor = str(item.get("vendor") or item.get("oui_vendor") or item.get("manufacturer") or "").strip().lower()
        channel = int(item.get("channel") or 0) if str(item.get("channel") or "").isdigit() else 0
        packet_count = int(item.get("packet_count") or 0)
        hints: List[str] = []
        family = ""
        score = 0
        for token, label in self.MANUFACTURER_HINTS.items():
            if token in ssid or token in vendor:
                family = label
                score += 30
                hints.append(f"Manufacturer hint matched {label}.")
                break
        if channel in {36, 40, 44, 48, 149, 153, 157, 161, 165}:
            score += 10
            hints.append("Observed in UAV-relevant 5 GHz Wi-Fi window.")
        if packet_count >= 6:
            score += 8
            hints.append("Repeated management recurrence retained.")
        if not ssid and channel in {36, 40, 44, 48, 149, 153, 157, 161, 165}:
            score += 8
            hints.append("Hidden high-band network retained as UAV candidate.")
        item["uav_enrichment"] = {
            "score": score,
            "family_label": family or "Unknown UAV Family",
            "hints": hints,
            "source": "additive_uav_enrichment",
        }
        return item
