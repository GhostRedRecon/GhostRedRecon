from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class DJIDroneIDAdapter:
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
    def _matches_dji_frequency(cls, peak_mhz: float) -> bool:
        return any(abs(float(peak_mhz) - center) <= 14.5 for center in cls.DJI_CENTER_FREQS_MHZ)

    @classmethod
    def _near_dji_frequency(cls, peak_mhz: float) -> bool:
        return any(abs(float(peak_mhz) - center) <= 24.0 for center in cls.DJI_CENTER_FREQS_MHZ)

    def decode(self, sdr_candidates: List[Dict[str, Any]], burst_locks: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        matched = [item for item in (sdr_candidates or []) if self._matches_dji_frequency(float(item.get("peak_mhz") or 0.0))]
        near_matched = [
            item for item in (sdr_candidates or [])
            if item not in matched and self._near_dji_frequency(float(item.get("peak_mhz") or 0.0))
        ]
        unmatched = [item for item in (sdr_candidates or []) if item not in matched]
        targets: List[Dict[str, Any]] = []
        promoted = list(matched)
        if not promoted and near_matched:
            strongest_near = sorted(
                near_matched,
                key=lambda item: (
                    float(item.get("burst_recurrence") or 0.0),
                    float(item.get("rolling_persistence") or 0.0),
                    float(item.get("peak_db") or -999.0),
                ),
                reverse=True,
            )
            candidate = strongest_near[0]
            if float(candidate.get("burst_recurrence") or 0.0) >= 2 or float(candidate.get("rolling_persistence") or 0.0) >= 0.18:
                promoted = strongest_near[:4]
        parsed_objects: List[Dict[str, Any]] = []
        sample_windows: List[Dict[str, Any]] = []
        for lock in burst_locks or []:
            if "5.8" not in str(lock.get("band") or "") and "2.4" not in str(lock.get("band") or ""):
                continue
            parsed_objects.append(
                {
                    "object_type": "dji_burst_lock",
                    "lock_id": lock.get("lock_id"),
                    "lock_state": lock.get("lock_state"),
                    "lock_strength": lock.get("lock_strength"),
                    "nearest_center_mhz": lock.get("nearest_center_mhz"),
                    "band": lock.get("band"),
                    "peak_list_mhz": lock.get("peak_list_mhz") or [],
                    "burst_recurrence": lock.get("burst_recurrence"),
                    "rolling_persistence": lock.get("rolling_persistence"),
                    "sample_window_reference": ((lock.get("sample_window") or {}).get("reference") or ""),
                }
            )
            if lock.get("sample_window"):
                sample_windows.append(dict(lock["sample_window"]))

        if promoted:
            strongest = sorted(promoted, key=lambda item: float(item.get("peak_db") or -999.0), reverse=True)
            confidence = 58
            reasons = [
                "HackRF peaks overlap known DJI DroneID / OcuSync-adjacent frequencies from public research.",
                f"{len(promoted)} SDR peaks matched or clustered near the DJI frequency set.",
            ]
            if len(promoted) >= 4:
                confidence += 14
                reasons.append("Multi-peak cluster supports a DJI-family RF profile.")
            peak_db = float(strongest[0].get("peak_db") or -110.0)
            if peak_db >= -60.0:
                confidence += 10
                reasons.append("Strong SDR peak strength for the leading cluster.")
            strongest_recurrence = float(strongest[0].get("burst_recurrence") or 0.0)
            strongest_persistence = float(strongest[0].get("rolling_persistence") or 0.0)
            if strongest_recurrence >= 2:
                confidence += 8
                reasons.append("Repeated SDR recurrence retained across sweep windows.")
            if strongest_persistence >= 0.18:
                confidence += 6
                reasons.append("Cluster persistence supports sustained DJI-family RF activity.")
            peak_list = [round(float(item.get("peak_mhz") or 0.0), 1) for item in strongest[:10]]
            supporting_locks = [
                lock for lock in (burst_locks or [])
                if any(abs(float(freq) - float(lock.get("nearest_center_mhz") or 0.0)) <= 24.0 for freq in peak_list)
            ]
            if any(str(lock.get("lock_state") or "") == "burst_locked" for lock in supporting_locks):
                confidence += 8
                reasons.append("Explicit SDR burst lock retained for the DJI-adjacent cluster.")
            band = "5.8 GHz" if any(float(item.get("peak_mhz") or 0.0) >= 5000.0 for item in promoted) else "2.4 GHz"
            targets.append(
                {
                    "target_id": f"dji-rf-{int(abs(peak_list[0]) * 10)}",
                    "label": "DJI Family RF Profile",
                    "classification": "Probable Drone",
                    "target_type": "probable_drone",
                    "confidence": max(68, min(94, confidence)),
                    "manufacturer": "DJI",
                    "model_family": "DJI / OcuSync platform unresolved",
                    "proof_level": "dji_rf_profile",
                    "identifier": ",".join(str(value) for value in peak_list[:4]),
                    "family_label": "DJI Family",
                    "band": band,
                    "channel": "--",
                    "packet_count": 0,
                    "decoder": {
                        "name": "DJI DroneID RF Adapter",
                        "status": "candidate",
                        "rationale": reasons,
                        "peak_list_mhz": peak_list,
                        "parsed_objects": parsed_objects[:12],
                        "sample_windows": sample_windows[:12],
                    },
                    "rf": {
                        "sweep_status": f"DJI-like {band} SDR cluster retained",
                        "bands_seen": [band],
                        "peak_list_mhz": peak_list,
                        "peak_db": peak_db,
                    },
                    "hard_audit": {
                        "detection_surface": "HackRF passive sweep",
                        "identity_exposure": "Manufacturer only",
                        "rf_visibility": "DJI-family RF cluster retained",
                        "correlation_strength": "SDR-only until Wi-Fi or Remote ID corroborates",
                        "evidence_sufficiency": "Moderate",
                        "audit_completeness": "Partial",
                    },
                    "reasons": reasons,
                    "evidence_sensors": ["sdr"],
                    "evidence": [
                        {
                            "artifact_type": "dji_rf_profile",
                            "sensor": "HackRF",
                            "reference": sample_windows[0]["reference"] if sample_windows else "",
                            "timestamp": float(strongest[0].get("timestamp") or 0.0),
                        }
                    ],
                    "swarm_label": "DJI Family",
                    "swarm_count": len(matched),
                    "swarm_role": "Clustered RF Source",
                    "first_seen": float(strongest[-1].get("timestamp") or 0.0),
                    "last_seen": float(strongest[0].get("timestamp") or 0.0),
                }
            )
        manifest = {
            "decoder": "DJI DroneID RF Adapter",
            "matched_count": len(promoted),
            "unmatched_count": len(unmatched),
            "targets": targets,
            "matched_peaks": promoted[:24],
            "burst_locks": burst_locks or [],
            "parsed_objects": parsed_objects[:24],
            "sample_windows": sample_windows[:24],
            "decoder_diagnostics": {
                "status": "candidate_frame_and_burst_lock",
                "lock_count": len(burst_locks or []),
                "sample_window_count": len(sample_windows),
            },
        }
        return manifest

    @staticmethod
    def write_manifest(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
