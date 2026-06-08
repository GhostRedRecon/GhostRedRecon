from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Any, Dict, List


class WiFiEvidenceRetentionEngine:
    def __init__(self, root_dir: Path, tshark_path: str | None = None) -> None:
        self.root_dir = root_dir
        self.evidence_root = self._resolve_writable_root(
            preferred=root_dir / "evidence" / "wifi_hunt" / "sessions",
            fallback=root_dir / "evidence" / "_wifi_hunt" / "sessions",
            temp_fallback=Path(tempfile.gettempdir()) / "ghostrecon_wifi_hunt" / "sessions",
        )
        self.audit_root = self._resolve_writable_root(
            preferred=root_dir / "evidence" / "Audit",
            fallback=root_dir / "evidence" / "_wifi_hunt" / "Audit",
            temp_fallback=Path(tempfile.gettempdir()) / "ghostrecon_wifi_hunt" / "Audit",
        )
        self.tshark_path = tshark_path or which("tshark") or ""
        self.mergecap_path = which("mergecap") or ""
        self.current_session: Dict[str, Any] = {}
        self.current_targets: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _session_id() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _stable_target_id(target: Dict[str, Any]) -> str:
        if str(target.get("mac") or "").strip():
            return f"client_{str(target.get('mac') or '').strip().lower().replace(':', '')}"
        raw = str(target.get("bssid") or target.get("record_id") or "").strip().lower()
        return f"network_{raw.replace(':', '').replace('/', '_')}"

    @staticmethod
    def _safe_path(value: str) -> str:
        return str(value or "").strip()

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _safe_folder_name(value: str, fallback: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._")
        return cleaned or fallback

    @staticmethod
    def _ensure_writable_dir(path: Path) -> Path | None:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return path
        except Exception:
            return None

    def _resolve_writable_root(self, *, preferred: Path, fallback: Path, temp_fallback: Path) -> Path:
        for candidate in (preferred, fallback, temp_fallback):
            writable = self._ensure_writable_dir(candidate)
            if writable is not None:
                return writable
        return temp_fallback

    def _write_json(self, path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _read_json(path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _append_session_note(self, note: str) -> None:
        if not self.current_session:
            return
        notes = list(self.current_session.get("notes") or [])
        notes.append(str(note))
        self.current_session["notes"] = notes[-8:]

    def _session_dir_path(self) -> Path | None:
        if not self.current_session:
            return None
        session_dir_value = str(self.current_session.get("session_dir") or "").strip()
        if session_dir_value:
            return Path(session_dir_value)
        session_id = str(self.current_session.get("session_id") or "").strip()
        if not session_id:
            self._append_session_note("session_dir_missing: no session_id available to recover evidence root")
            return None
        recovered = self.evidence_root / session_id
        self.current_session["session_dir"] = str(recovered)
        self._append_session_note("session_dir_missing: recovered from session_id")
        return recovered

    def reset(self) -> None:
        self.current_session = {}
        self.current_targets = {}

    def start_session(
        self,
        *,
        adapter_identifier: str,
        bands: List[str],
        dwell_ms: int,
        duration_seconds: int,
        scan_mode: str,
        scan_scenario: str,
        locked_channels: List[int],
        interfaces: List[str],
        deep_packet_enrichment: bool,
        camera_hunt: bool,
    ) -> Dict[str, Any]:
        session_id = self._session_id()
        session_dir = self.evidence_root / session_id
        payload = {
            "session_id": session_id,
            "session_dir": str(session_dir),
            "started_at": self._utc_now(),
            "ended_at": "",
            "adapter_identifier": adapter_identifier,
            "bands": list(bands or []),
            "dwell_ms": int(dwell_ms or 0),
            "duration_seconds": int(duration_seconds or 0),
            "scan_mode": str(scan_mode or "broad"),
            "scan_scenario": str(scan_scenario or "passive_observation"),
            "locked_channels": [int(value) for value in (locked_channels or [])],
            "interfaces": [str(value).strip() for value in (interfaces or []) if str(value).strip()],
            "deep_packet_enrichment": bool(deep_packet_enrichment),
            "camera_hunt": bool(camera_hunt),
            "capture_files": [],
            "target_count": 0,
            "handshake_session_count": 0,
            "storage_root": str(self.evidence_root),
            "audit_root": str(self.audit_root),
            "notes": [],
        }
        self.current_session = payload
        self.current_targets = {}
        self._write_session_manifest()
        return dict(self.current_session)

    def _write_session_manifest(self) -> None:
        if not self.current_session:
            return
        session_dir = self._session_dir_path()
        if session_dir is None:
            return
        session_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(session_dir / "session_manifest.json", self.session_manifest())

    def session_manifest(self) -> Dict[str, Any]:
        if not self.current_session:
            return {}
        capture_files = [dict(item) for item in (self.current_session.get("capture_files") or [])]
        return {
            "session_id": self.current_session.get("session_id") or "",
            "capture_start": self.current_session.get("started_at") or "",
            "capture_end": self.current_session.get("ended_at") or "",
            "adapter_identifier": self.current_session.get("adapter_identifier") or "",
            "bands": list(self.current_session.get("bands") or []),
            "dwell_ms": int(self.current_session.get("dwell_ms") or 0),
            "duration_seconds": int(self.current_session.get("duration_seconds") or 0),
            "scan_mode": self.current_session.get("scan_mode") or "",
            "scan_scenario": self.current_session.get("scan_scenario") or "",
            "locked_channels": list(self.current_session.get("locked_channels") or []),
            "interfaces": list(self.current_session.get("interfaces") or []),
            "deep_packet_enrichment": bool(self.current_session.get("deep_packet_enrichment")),
            "camera_hunt": bool(self.current_session.get("camera_hunt")),
            "capture_files": capture_files,
            "target_count": int(self.current_session.get("target_count") or 0),
            "handshake_session_count": int(self.current_session.get("handshake_session_count") or 0),
            "storage_root": self.current_session.get("storage_root") or str(self.evidence_root),
            "audit_root": self.current_session.get("audit_root") or str(self.audit_root),
            "notes": list(self.current_session.get("notes") or []),
            "artifacts": {
                "full_session_pcap": self.current_session.get("full_session_pcap") or "",
                "full_session_packet_count": int(self.current_session.get("full_session_packet_count") or 0),
                "full_session_integrity_hash": self.current_session.get("full_session_integrity_hash") or "",
            },
        }

    def record_channel_capture(
        self,
        *,
        source_pcap_path: str,
        channel: int,
        band: str,
        interface: str,
        frame_count: int,
    ) -> Dict[str, Any]:
        if not self.current_session:
            return {}
        source = Path(source_pcap_path)
        if not source.exists():
            return {}
        session_dir = Path(self.current_session["session_dir"])
        channels_dir = session_dir / "channels"
        channels_dir.mkdir(parents=True, exist_ok=True)
        artifact_name = f"ch_{int(channel):02d}_{self._session_id()}.pcapng"
        artifact_path = channels_dir / artifact_name
        shutil.copy2(source, artifact_path)
        artifact = {
            "artifact_type": "per_channel_pcap",
            "session_id": self.current_session.get("session_id") or "",
            "target_id": "",
            "channel": int(channel),
            "band": str(band or ""),
            "interface": str(interface or ""),
            "capture_start": self.current_session.get("started_at") or "",
            "capture_end": self._utc_now(),
            "source_tool": "dumpcap",
            "filter_used": "",
            "packet_count": int(frame_count or 0),
            "reason_for_retention": f"Controlled WiFi Hunt channel {int(channel):02d} evidence retention.",
            "integrity_hash": self._sha256(artifact_path),
            "path": str(artifact_path),
            "source_path": str(source),
        }
        capture_files = list(self.current_session.get("capture_files") or [])
        capture_files.append(artifact)
        self.current_session["capture_files"] = capture_files
        self._write_json(artifact_path.with_suffix(".json"), artifact)
        self._write_session_manifest()
        return artifact

    def finalize_session(self, *, handshake_session_count: int = 0) -> Dict[str, Any]:
        if not self.current_session:
            return {}
        self.current_session["ended_at"] = self._utc_now()
        self.current_session["handshake_session_count"] = int(handshake_session_count or 0)
        capture_files = [item for item in (self.current_session.get("capture_files") or []) if str(item.get("path") or "").strip()]
        channel_paths = [str(item.get("path") or "").strip() for item in capture_files if str(item.get("path") or "").strip()]
        session_dir = Path(self.current_session["session_dir"])
        full_session_path = session_dir / "full_session.pcapng"
        if channel_paths and self.mergecap_path:
            try:
                result = subprocess.run(
                    [self.mergecap_path, "-w", str(full_session_path), *channel_paths],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode == 0 and full_session_path.exists():
                    self.current_session["full_session_pcap"] = str(full_session_path)
                    self.current_session["full_session_packet_count"] = sum(int(item.get("packet_count") or 0) for item in capture_files)
                    self.current_session["full_session_integrity_hash"] = self._sha256(full_session_path)
                else:
                    notes = list(self.current_session.get("notes") or [])
                    notes.append((result.stderr or result.stdout or "mergecap failed").strip())
                    self.current_session["notes"] = notes[-8:]
            except Exception as exc:
                notes = list(self.current_session.get("notes") or [])
                notes.append(f"mergecap_exception:{exc}")
                self.current_session["notes"] = notes[-8:]
        elif channel_paths:
            notes = list(self.current_session.get("notes") or [])
            notes.append("mergecap_unavailable: full_session.pcapng could not be synthesized; per-channel evidence retained.")
            self.current_session["notes"] = notes[-8:]
        self._write_session_manifest()
        return self.session_manifest()

    def _allowed_session_path(self, candidate: str) -> Path:
        path = Path(candidate).expanduser().resolve()
        session_root = Path(self.current_session.get("session_dir") or "").resolve()
        if session_root and (path == session_root or session_root in path.parents):
            return path
        raise ValueError("artifact path outside active session root")

    def _extract_filtered_pcap(self, *, source_path: str, display_filter: str, destination_path: Path) -> Dict[str, Any]:
        if not self.tshark_path:
            return {"ok": False, "error": "tshark unavailable"}
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [self.tshark_path, "-r", source_path, "-Y", display_filter, "-w", str(destination_path)],
            capture_output=True,
            text=True,
            timeout=40,
            check=False,
        )
        if result.returncode != 0 or not destination_path.exists():
            return {"ok": False, "error": (result.stderr or result.stdout or "tshark filter extraction failed").strip()}
        packet_count = 0
        try:
            count = subprocess.run(
                [self.tshark_path, "-r", str(destination_path), "-T", "fields", "-e", "frame.number"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if count.returncode == 0:
                packet_count = len([line for line in (count.stdout or "").splitlines() if line.strip()])
        except Exception:
            packet_count = 0
        return {"ok": True, "packet_count": packet_count}

    def _convert_to_pcap(self, source_path: Path, destination_path: Path) -> Dict[str, Any]:
        if not self.tshark_path or not source_path.exists():
            return {"ok": False, "error": "tshark unavailable"}
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [self.tshark_path, "-r", str(source_path), "-F", "pcap", "-w", str(destination_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0 or not destination_path.exists():
            return {"ok": False, "error": (result.stderr or result.stdout or "pcap conversion failed").strip()}
        return {"ok": True, "path": str(destination_path), "integrity_hash": self._sha256(destination_path)}

    def _export_audit_artifacts(
        self,
        *,
        stable_target_id: str,
        ssid: str,
        filtered_artifact: str,
        handshake_artifact: str,
    ) -> Dict[str, Any]:
        label = self._safe_folder_name(ssid or stable_target_id, stable_target_id)
        base_dir = self.audit_root / label
        pcapng_dir = base_dir / "pcapng"
        pcap_dir = base_dir / "pcap"
        exports = {
            "audit_folder": str(base_dir),
            "pcapng_exports": [],
            "pcap_exports": [],
        }
        for source_path, logical_name in (
            (filtered_artifact, "target_filtered"),
            (handshake_artifact, "handshake_evidence"),
        ):
            cleaned = str(source_path or "").strip()
            if not cleaned:
                continue
            source = Path(cleaned)
            if not source.exists():
                continue
            pcapng_dir.mkdir(parents=True, exist_ok=True)
            exported_pcapng = pcapng_dir / f"{logical_name}.pcapng"
            shutil.copy2(source, exported_pcapng)
            exports["pcapng_exports"].append(
                {
                    "artifact_type": f"audit_{logical_name}_pcapng",
                    "path": str(exported_pcapng),
                    "integrity_hash": self._sha256(exported_pcapng),
                }
            )
            converted = self._convert_to_pcap(exported_pcapng, pcap_dir / f"{logical_name}.pcap")
            if converted.get("ok"):
                exports["pcap_exports"].append(
                    {
                        "artifact_type": f"audit_{logical_name}_pcap",
                        "path": str(converted.get("path") or ""),
                        "integrity_hash": str(converted.get("integrity_hash") or ""),
                    }
                )
        return exports

    def write_target_artifacts(
        self,
        *,
        target: Dict[str, Any],
        ddi_resolution: Dict[str, Any],
        handshake_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not self.current_session:
            return {}
        session_dir = self._session_dir_path()
        if session_dir is None:
            return {}
        stable_target_id = self._stable_target_id(target)
        target_dir = session_dir / "targets" / stable_target_id
        target_dir.mkdir(parents=True, exist_ok=True)
        target_id = str(ddi_resolution.get("target_id") or stable_target_id)
        mac = str(target.get("mac") or "").strip().lower()
        bssid = str(target.get("bssid") or target.get("associated_bssid") or "").strip().lower()
        ssid = str(target.get("ssid") or ((target.get("associated_network") or {}).get("ssid") or "")).strip()
        candidate_sources = list(ddi_resolution.get("candidate_ips") or [])
        evidence_refs = list(ddi_resolution.get("evidence") or [])
        source_capture_files = [dict(item) for item in (self.current_session.get("capture_files") or [])]
        session_full_pcap = str(self.current_session.get("full_session_pcap") or "").strip()
        if session_full_pcap:
            source_capture_files = [{"path": session_full_pcap, "packet_count": int(self.current_session.get("full_session_packet_count") or 0)}, *source_capture_files]

        filtered_artifact_path = target_dir / "target_filtered.pcapng"
        filtered_artifact = ""
        filtered_packet_count = 0
        if source_capture_files and self.tshark_path and (mac or bssid):
            filters = []
            if mac:
                filters.append(f"wlan.addr == {mac}")
                filters.append(f"eth.addr == {mac}")
                if bssid and bssid != mac:
                    filters.append(f"wlan.bssid == {bssid}")
            elif bssid:
                filters.append(f"wlan.bssid == {bssid}")
                filters.append(f"eth.addr == {bssid}")
            display_filter = " or ".join(filters)
            for source in source_capture_files[:6]:
                extract = self._extract_filtered_pcap(
                    source_path=str(source.get("path") or ""),
                    display_filter=display_filter,
                    destination_path=filtered_artifact_path,
                )
                if extract.get("ok") and filtered_artifact_path.exists() and int(extract.get("packet_count") or 0) > 0:
                    filtered_artifact = str(filtered_artifact_path)
                    filtered_packet_count = int(extract.get("packet_count") or 0)
                    break

        handshake_artifact_path = target_dir / "handshake_evidence.pcapng"
        handshake_artifact = ""
        handshake_packet_count = 0
        handshake_filter = ""
        if self.tshark_path and bssid and mac:
            handshake_filter = f"eapol && wlan.addr == {bssid} && wlan.addr == {mac}"
        elif self.tshark_path and bssid:
            handshake_filter = f"eapol && wlan.bssid == {bssid}"
        elif self.tshark_path and mac:
            handshake_filter = f"eapol && wlan.addr == {mac}"
        has_handshake_evidence = (
            int(handshake_summary.get("frame_count") or 0) > 0
            or int(handshake_summary.get("session_count") or 0) > 0
            or str(handshake_summary.get("state") or "").upper()
            not in {"", "NO_HANDSHAKE_OBSERVED", "NONE"}
        )
        if handshake_filter and has_handshake_evidence:
            for source in source_capture_files[:6]:
                extract = self._extract_filtered_pcap(
                    source_path=str(source.get("path") or ""),
                    display_filter=handshake_filter,
                    destination_path=handshake_artifact_path,
                )
                if extract.get("ok") and handshake_artifact_path.exists() and int(extract.get("packet_count") or 0) > 0:
                    handshake_artifact = str(handshake_artifact_path)
                    handshake_packet_count = int(extract.get("packet_count") or 0)
                    break

        ddi_path = target_dir / "ddi_resolution.json"
        self._write_json(ddi_path, ddi_resolution)

        manifest = {
            "session_id": self.current_session.get("session_id") or "",
            "target_id": target_id,
            "stable_target_id": stable_target_id,
            "target_kind": "client" if mac else "network",
            "mac": mac,
            "bssid": bssid,
            "ssid": ssid,
            "capture_files": source_capture_files,
            "filtered_artifact_files": [
                {
                    "artifact_type": "target_filtered_pcap",
                    "path": filtered_artifact,
                    "packet_count": filtered_packet_count,
                    "filter_used": "wlan/eth target filter" if filtered_artifact else "",
                    "reason_for_retention": "Target-scoped packet truth retention for manual review.",
                    "integrity_hash": self._sha256(filtered_artifact_path) if filtered_artifact else "",
                }
            ],
            "handshake_artifact_files": [
                {
                    "artifact_type": "handshake_evidence_pcap",
                    "path": handshake_artifact,
                    "packet_count": handshake_packet_count,
                    "filter_used": handshake_filter,
                    "reason_for_retention": "Observed EAPOL/authentication evidence retained for manual review.",
                    "integrity_hash": self._sha256(handshake_artifact_path) if handshake_artifact else "",
                }
            ],
            "ddi_resolution_path": str(ddi_path),
            "extraction_methods": sorted({str(item.get("method") or "").strip() for item in evidence_refs if str(item.get("method") or "").strip()}),
            "timestamps": {
                "first_seen": ddi_resolution.get("first_seen") or "",
                "last_seen": ddi_resolution.get("last_seen") or "",
                "written_at": self._utc_now(),
            },
            "frame_references": evidence_refs,
            "evidence_summary": {
                "resolution_state": ddi_resolution.get("resolution_state") or "",
                "explanation": ddi_resolution.get("explanation") or "",
                "validated_candidates": list(ddi_resolution.get("validated_candidates") or []),
                "candidate_count": len(candidate_sources),
            },
            "handshake_summary": handshake_summary,
            "notes": list(ddi_resolution.get("notes") or []),
        }
        audit_exports = self._export_audit_artifacts(
            stable_target_id=stable_target_id,
            ssid=ssid,
            filtered_artifact=filtered_artifact,
            handshake_artifact=handshake_artifact,
        )
        meaningful_capture_saved = bool(filtered_artifact and filtered_packet_count > 0)
        meaningful_handshake_saved = bool(handshake_artifact and handshake_packet_count > 0)
        manifest["audit_exports"] = audit_exports
        manifest["artifact_status"] = {
            "target_capture_saved": meaningful_capture_saved,
            "target_capture_packet_count": filtered_packet_count,
            "handshake_capture_saved": meaningful_handshake_saved,
            "handshake_capture_packet_count": handshake_packet_count,
            "handshake_state": str(handshake_summary.get("state") or "NO_HANDSHAKE_OBSERVED"),
        }
        manifest_path = target_dir / "target_manifest.json"
        self._write_json(manifest_path, manifest)
        target_record = {
            "target_id": target_id,
            "stable_target_id": stable_target_id,
            "session_manifest": str(session_dir / "session_manifest.json"),
            "target_manifest": str(manifest_path),
            "ddi_resolution_path": str(ddi_path),
            "target_filtered_pcap": filtered_artifact,
            "handshake_evidence_pcap": handshake_artifact,
            "audit_exports": audit_exports,
            "artifact_status": dict(manifest.get("artifact_status") or {}),
        }
        self.current_targets[target_id] = target_record
        self.current_session["target_count"] = len(self.current_targets)
        self._write_session_manifest()
        return target_record

    def write_service_audit_trace(self, *, target_id: str, audit_payload: Dict[str, Any]) -> str:
        if not self.current_session:
            return ""
        target_record = dict(self.current_targets.get(target_id) or {})
        stable_target_id = str(target_record.get("stable_target_id") or "").strip()
        if not stable_target_id:
            return ""
        session_dir = self._session_dir_path()
        if session_dir is None:
            return ""
        target_dir = session_dir / "targets" / stable_target_id
        target_dir.mkdir(parents=True, exist_ok=True)
        trace_path = target_dir / "service_audit_trace.json"
        self._write_json(trace_path, audit_payload)
        target_record["service_audit_trace"] = str(trace_path)
        self.current_targets[target_id] = target_record
        return str(trace_path)

    def write_destination_analysis_artifacts(
        self,
        *,
        target_id: str,
        analysis_payload: Dict[str, Any],
        external_ips: List[str],
        dns_records: List[Dict[str, Any]],
        tls_metadata: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        if not self.current_session:
            return {}
        target_record = dict(self.current_targets.get(target_id) or {})
        stable_target_id = str(target_record.get("stable_target_id") or "").strip()
        if not stable_target_id:
            return {}
        session_dir = self._session_dir_path()
        if session_dir is None:
            return {}
        target_dir = session_dir / "targets" / stable_target_id
        target_dir.mkdir(parents=True, exist_ok=True)

        destination_path = target_dir / "destination_analysis.json"
        external_ips_path = target_dir / "external_ips.txt"
        dns_records_path = target_dir / "dns_records.json"
        tls_metadata_path = target_dir / "tls_metadata.json"

        self._write_json(destination_path, analysis_payload)
        external_ips_path.write_text(
            "".join(f"{str(item).strip()}\n" for item in (external_ips or []) if str(item).strip()),
            encoding="utf-8",
        )
        self._write_json(
            dns_records_path,
            {
                "target_id": target_id,
                "record_count": len(dns_records or []),
                "records": list(dns_records or []),
            },
        )
        self._write_json(
            tls_metadata_path,
            {
                "target_id": target_id,
                "record_count": len(tls_metadata or []),
                "records": list(tls_metadata or []),
            },
        )

        manifest_path = Path(str(target_record.get("target_manifest") or "")).resolve() if str(target_record.get("target_manifest") or "").strip() else target_dir / "target_manifest.json"
        manifest = self._read_json(manifest_path)
        if manifest:
            manifest["destination_analysis_path"] = str(destination_path)
            manifest["external_ips_path"] = str(external_ips_path)
            manifest["dns_records_path"] = str(dns_records_path)
            manifest["tls_metadata_path"] = str(tls_metadata_path)
            artifact_status = dict(manifest.get("artifact_status") or {})
            artifact_status["destination_analysis_available"] = bool((analysis_payload.get("external_endpoints") or []))
            artifact_status["external_endpoint_count"] = len(analysis_payload.get("external_endpoints") or [])
            manifest["artifact_status"] = artifact_status
            manifest["destination_analysis_summary"] = {
                "analysis_state": analysis_payload.get("analysis_state") or "",
                "confidence": analysis_payload.get("confidence") or "",
                "confidence_score": int(analysis_payload.get("confidence_score") or 0),
                "assessment": analysis_payload.get("assessment") or "",
            }
            self._write_json(manifest_path, manifest)

        target_record["destination_analysis"] = str(destination_path)
        target_record["external_ips"] = str(external_ips_path)
        target_record["dns_records"] = str(dns_records_path)
        target_record["tls_metadata"] = str(tls_metadata_path)
        self.current_targets[target_id] = target_record
        return {
            "destination_analysis": str(destination_path),
            "external_ips": str(external_ips_path),
            "dns_records": str(dns_records_path),
            "tls_metadata": str(tls_metadata_path),
        }
