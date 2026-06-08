from __future__ import annotations

import json
import shutil
import time
from hashlib import sha1
from pathlib import Path
from typing import Any, Callable, Dict, List


class BLEValidationEngine:
    MODULE_CATALOG = [
        {
            "id": "adversary_emulation",
            "label": "Adversary Emulation Engine",
            "objective": "Generate non-standard BLE interaction sequences across pairing, trust, and reconnect flows.",
            "tools": ["bluetoothctl", "btmon", "scapy", "bluez_dbus"],
        },
        {
            "id": "trust_lifecycle",
            "label": "Trust Lifecycle Analysis Engine",
            "objective": "Model pairing, bonding, trust persistence, replacement, and reconnect behavior over time.",
            "tools": ["bluetoothctl", "btmon", "bluez_dbus"],
        },
        {
            "id": "security_boundary",
            "label": "Security Boundary Validation Engine",
            "objective": "Compare pre-pair and post-pair access and validate auth and authorization boundaries.",
            "tools": ["bluetoothctl", "gatttool", "bluez_dbus"],
        },
        {
            "id": "misuse_case",
            "label": "Misuse-Case Simulation Framework",
            "objective": "Exercise interrupted, reordered, and partial BLE interaction sequences in a controlled lab.",
            "tools": ["bluetoothctl", "scapy", "bluez_dbus"],
        },
        {
            "id": "stress_testing",
            "label": "Interaction Stress Testing Engine",
            "objective": "Measure stability under repeated connections, pairing attempts, and enumeration loops.",
            "tools": ["bluetoothctl", "btmon"],
        },
        {
            "id": "identity_emulation",
            "label": "Identity Emulation Module",
            "objective": "Plan or execute controlled address rotation and alternate advertising identities for owned lab systems.",
            "tools": ["scapy", "bluez_dbus", "nordic_sniffer"],
        },
        {
            "id": "post_association_surface",
            "label": "Post-Association Surface Analysis",
            "objective": "Map GATT surfaces and classify readable, writable, and likely sensitive controls.",
            "tools": ["bluetoothctl", "gatttool"],
        },
        {
            "id": "behavioral_anomaly",
            "label": "Behavioral Anomaly Detection Engine",
            "objective": "Detect inconsistent pairing, reconnect instability, service drift, and response irregularities.",
            "tools": ["btmon", "tshark", "nordic_sniffer"],
        },
        {
            "id": "path_recommendation",
            "label": "Adversary Path Recommendation Engine",
            "objective": "Rank validation priority and suggest the next highest-value trust or GATT test path.",
            "tools": ["internal_logic"],
        },
        {
            "id": "evidence_replay",
            "label": "Evidence Recording and Replay System",
            "objective": "Store interaction sequences, timestamps, responses, and reproducible replay steps.",
            "tools": ["json", "tshark", "btmon"],
        },
    ]

    def __init__(
        self,
        root_dir: Path,
        run_command: Callable[[list[str], float], Dict[str, Any]],
        run_bluetoothctl_session: Callable[[list[str], float], Dict[str, Any]],
        parse_bluetoothctl_info: Callable[[str], Dict[str, Any]],
        parse_bluetoothctl_gatt: Callable[[str], Dict[str, Any]],
        bluez_fetch_device_info: Callable[[str], Dict[str, Any]] | None = None,
        bluez_run_validation_session: Callable[[str], Dict[str, Any]] | None = None,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.runs_dir = self.root_dir / "logs" / "ble_nr5" / "validation_runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.pin_risk_db_path = self.root_dir / "config" / "ble_legacy_pin_risk_db.json"
        self.pin_risk_db = self._load_pin_risk_db()
        self._run_command = run_command
        self._run_bluetoothctl_session = run_bluetoothctl_session
        self._parse_bluetoothctl_info = parse_bluetoothctl_info
        self._parse_bluetoothctl_gatt = parse_bluetoothctl_gatt
        self._bluez_fetch_device_info = bluez_fetch_device_info
        self._bluez_run_validation_session = bluez_run_validation_session

    def _load_pin_risk_db(self) -> Dict[str, Any]:
        if not self.pin_risk_db_path.exists():
            return {}
        try:
            payload = json.loads(self.pin_risk_db_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def module_catalog(self) -> List[Dict[str, Any]]:
        return [dict(item) for item in self.MODULE_CATALOG]

    def tool_catalog(self) -> Dict[str, Dict[str, Any]]:
        catalog: Dict[str, Dict[str, Any]] = {}
        tool_map = {
            "wireshark": "wireshark",
            "tshark": "tshark",
            "btmon": "btmon",
            "bluetoothctl": "bluetoothctl",
            "gatttool": "gatttool",
            "bettercap": "bettercap",
            "scapy": "python3",
            "bluez_dbus": "dbus-send",
            "nordic_sniffer": "tshark",
        }
        for logical_name, binary in tool_map.items():
            path = shutil.which(binary)
            catalog[logical_name] = {
                "installed": bool(path),
                "path": path or "",
            }
        return catalog

    def _run_shell_tool(self, cmd: list[str], timeout: float = 8.0) -> Dict[str, Any]:
        return self._run_command(cmd, timeout)

    def _timestamp(self) -> float:
        return time.time()

    def _make_run_id(self, device_key: str) -> str:
        stamp = str(int(self._timestamp()))
        suffix = sha1(f"{device_key}:{stamp}".encode("utf-8")).hexdigest()[:10]
        return f"bleval-{stamp}-{suffix}"

    def _write_run(self, payload: Dict[str, Any]) -> None:
        run_id = str(payload.get("run_id") or "").strip()
        if not run_id:
            return
        target = self.runs_dir / f"{run_id}.json"
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    def _summarize_btmon_capability(self) -> Dict[str, Any]:
        tool = self.tool_catalog().get("btmon") or {}
        if not tool.get("installed"):
            return {
                "installed": False,
                "objective": "Capture HCI-level trace during validation runs.",
                "reproducibility_status": "blocked",
                "detail": "btmon not installed",
                "replay_steps": ["Install btmon / BlueZ monitor utilities on the lab host."],
            }
        return {
            "installed": True,
            "objective": "Capture HCI-level trace during validation runs.",
            "reproducibility_status": "ready",
            "detail": "btmon can be run alongside lab validation to capture HCI events",
            "replay_steps": ["Run `btmon` before the validation workflow and save the trace alongside the evidence JSON."],
        }

    def _summarize_tshark_capability(self) -> Dict[str, Any]:
        tool = self.tool_catalog().get("tshark") or {}
        if not tool.get("installed"):
            return {
                "installed": False,
                "objective": "Decode and correlate BLE captures or external sniffer traces.",
                "reproducibility_status": "blocked",
                "detail": "tshark not installed",
                "replay_steps": ["Install tshark or Wireshark CLI tools on the lab host."],
            }
        return {
            "installed": True,
            "objective": "Decode BLE traces and correlate them with validation timing and GATT evidence.",
            "reproducibility_status": "ready",
            "detail": "tshark can decode pcaps and exported sniffer traces for the run record",
            "replay_steps": ["Attach a capture file to the run and decode it with `tshark` using the saved run timestamps."],
        }

    def _build_sequence_step(self, tool: str, action: str, command: str, purpose: str) -> Dict[str, Any]:
        return {
            "tool": tool,
            "action": action,
            "command": command,
            "purpose": purpose,
        }

    def _build_trust_lifecycle(self, device: Dict[str, Any], pre_info: Dict[str, Any], post_info: Dict[str, Any], reconnect_probe: Dict[str, Any]) -> Dict[str, Any]:
        pairing_methods = list(device.get("pairing_methods") or [])
        bond_events = int(device.get("bond_events") or 0)
        repair_flags = int(device.get("repair_flags") or 0)
        pairing_failures = int(device.get("pairing_failures") or 0)
        silent_patterns = int(device.get("silent_pairing_patterns") or 0)
        pairing_method = pairing_methods[0] if pairing_methods else "unknown"
        if pre_info.get("legacy_pairing") is True or post_info.get("legacy_pairing") is True:
            pairing_method = "legacy pin"
        elif pre_info.get("paired") or post_info.get("paired"):
            pairing_method = pairing_method if pairing_method != "unknown" else "paired_unknown"
        trust_persistence = "persistent" if post_info.get("trusted") else ("not_trusted" if post_info.get("paired") else "unknown")
        return {
            "pairing_method": pairing_method,
            "pairing_methods_seen": pairing_methods,
            "trusted_before": bool(pre_info.get("trusted")),
            "trusted_after": bool(post_info.get("trusted")),
            "paired_before": bool(pre_info.get("paired")),
            "paired_after": bool(post_info.get("paired")),
            "connected_before": bool(pre_info.get("connected")),
            "connected_after": bool(post_info.get("connected")),
            "services_resolved_before": bool(pre_info.get("services_resolved")),
            "services_resolved_after": bool(post_info.get("services_resolved")),
            "legacy_pairing_before": bool(pre_info.get("legacy_pairing")),
            "legacy_pairing_after": bool(post_info.get("legacy_pairing")),
            "trust_persistence": trust_persistence,
            "bond_events": bond_events,
            "trust_replacement_events": repair_flags,
            "downgrade_indicators": ["pairing_failure_seen"] if pairing_failures else [],
            "reconnect_result": reconnect_probe.get("result") or "not_attempted",
            "silent_pairing_patterns": silent_patterns,
            "summary": (
                f"{pairing_method} · paired {bool(post_info.get('paired'))} · trusted {bool(post_info.get('trusted'))} · "
                f"svc-resolved {bool(post_info.get('services_resolved'))} · {reconnect_probe.get('result') or 'no reconnect probe'}"
            ),
        }

    def _build_gatt_summary(self, device: Dict[str, Any], gatt: Dict[str, Any], post_info: Dict[str, Any]) -> Dict[str, Any]:
        services = int(gatt.get("service_count") or device.get("gatt_service_count") or 0)
        characteristics = int(gatt.get("characteristic_count") or 0)
        writable = int(gatt.get("writable_count") or device.get("gatt_writable_count") or 0)
        readable = int(gatt.get("readable_count") or device.get("gatt_readable_count") or 0)
        notify_count = int(gatt.get("notify_count") or 0)
        unauth = int(gatt.get("unauth_writable_count") or device.get("writable_unauth_count") or 0)
        unauth_readable = int(gatt.get("unauth_readable_count") or 0)
        sensitive = int(device.get("sensitive_surface_count") or 0)
        service_records = list(gatt.get("services") or [])
        potential_control_surfaces: List[Dict[str, Any]] = []
        vendor_specific_services = 0
        maintenance_endpoints = 0
        for service in service_records:
            service_uuid = str(service.get("uuid") or "").lower()
            is_vendor_specific = bool(service_uuid) and not service_uuid.startswith("000018")
            if is_vendor_specific:
                vendor_specific_services += 1
            if any(token in service_uuid for token in ("fe59", "feaa", "1530", "dfu", "f000")):
                maintenance_endpoints += 1
            for characteristic in service.get("characteristics") or []:
                flags = [str(item).lower() for item in (characteristic.get("flags") or [])]
                if bool(characteristic.get("writable")) or ("write-without-response" in flags):
                    potential_control_surfaces.append(
                        {
                            "service_uuid": service_uuid,
                            "characteristic_uuid": str(characteristic.get("uuid") or "").lower(),
                            "flags": flags,
                            "requires_auth": bool(characteristic.get("requires_auth")),
                            "vendor_specific": is_vendor_specific,
                            "unauthenticated_writable": bool(characteristic.get("writable")) and not bool(characteristic.get("requires_auth")),
                        }
                    )
        access_consistency = "consistent"
        if not bool(post_info.get("services_resolved")) and services == 0:
            access_consistency = "unresolved"
        elif unauth > 0 or unauth_readable > 0:
            access_consistency = "permissive"
        elif not bool(post_info.get("paired")) and services > 0:
            access_consistency = "partial"
        return {
            "service_count": services,
            "characteristic_count": characteristics,
            "readable_count": readable,
            "writable_count": writable,
            "notify_count": notify_count,
            "unauth_readable_count": unauth_readable,
            "services_resolved": bool(post_info.get("services_resolved")),
            "unauthenticated_access_detected": unauth > 0,
            "sensitive_surface_count": sensitive,
            "post_pair_access_consistent": bool(post_info.get("paired")) or services > 0,
            "services": service_records,
            "access_consistency": access_consistency,
            "vendor_specific_services": vendor_specific_services,
            "maintenance_endpoints": maintenance_endpoints,
            "potential_control_surfaces": potential_control_surfaces[:20],
            "summary": f"{services} svc · {characteristics} char · {writable} writable · {unauth} unauth-w · {unauth_readable} unauth-r",
        }

    def _pin_candidates_for_device(self, device: Dict[str, Any]) -> List[Dict[str, str]]:
        candidates = list(self.pin_risk_db.get("common_legacy_pins") or [])
        results: List[Dict[str, str]] = []
        for item in candidates:
            pin = str(item.get("pin") or "").strip()
            if not pin:
                continue
            results.append(
                {
                    "pin": pin,
                    "prevalence": str(item.get("prevalence") or "unknown"),
                    "contexts": ", ".join(str(ctx) for ctx in (item.get("contexts") or [])),
                    "status": "not_observed",
                }
            )
        return results

    def _detect_pairing_challenge(self, raw_output: str) -> Dict[str, Any]:
        output = str(raw_output or "")
        lowered = output.lower()
        if any(token in lowered for token in ("enter pin", "pin code", "pincode", "request pin code")):
            return {"prompt_seen": True, "challenge_type": "pin", "prompt_family": "legacy_pin"}
        if any(token in lowered for token in ("confirm passkey", "request confirmation", "numeric comparison")):
            return {"prompt_seen": True, "challenge_type": "numeric comparison", "prompt_family": "secure_pairing"}
        if "passkey" in lowered:
            return {"prompt_seen": True, "challenge_type": "passkey", "prompt_family": "secure_pairing"}
        if "out of band" in lowered or " oob" in lowered:
            return {"prompt_seen": True, "challenge_type": "oob", "prompt_family": "secure_pairing"}
        if "just works" in lowered:
            return {"prompt_seen": True, "challenge_type": "just works", "prompt_family": "unauthenticated_pairing"}
        return {"prompt_seen": False, "challenge_type": "unknown", "prompt_family": "unknown"}

    def _build_pin_audit(self, device: Dict[str, Any], raw_output: str, trust_lifecycle: Dict[str, Any]) -> Dict[str, Any]:
        challenge = self._detect_pairing_challenge(raw_output)
        pairing_method = str(trust_lifecycle.get("pairing_method") or "").strip().lower()
        tested_pins = self._pin_candidates_for_device(device)
        evidence_sources: List[str] = []
        if challenge.get("prompt_seen") and challenge.get("challenge_type") in {"pin", "legacy pin"}:
            for item in tested_pins:
                item["status"] = "manual_lab_required"
            audit_state = "legacy_pin_challenge_observed"
            risk = "likely"
            summary = "legacy-pin challenge observed · manual owned-target confirmation required"
            evidence_sources.append("pairing_prompt")
        elif trust_lifecycle.get("legacy_pairing_before") or trust_lifecycle.get("legacy_pairing_after"):
            for item in tested_pins:
                item["status"] = "legacy_pairing_flag_seen"
            audit_state = "legacy_pairing_flag_seen"
            risk = "likely"
            summary = "BlueZ legacy-pairing flag observed"
            evidence_sources.append("bluez_legacy_pairing_flag")
        elif pairing_method in {"numeric comparison", "passkey", "oob"}:
            for item in tested_pins:
                item["status"] = "not_applicable"
            audit_state = "secure_pairing_mode"
            risk = "unlikely"
            summary = f"{pairing_method} observed · legacy PIN path not indicated"
            evidence_sources.append("secure_pairing_method")
        elif pairing_method in {"just works", "paired_unknown"}:
            audit_state = "unauthenticated_or_unknown_pairing"
            risk = "possible"
            summary = f"{pairing_method} observed · legacy PIN not proven"
            evidence_sources.append("pairing_method_inference")
        else:
            audit_state = "no_pin_exchange_observed"
            risk = "unknown"
            summary = "no legacy PIN exchange observed"
        return {
            "audit_state": audit_state,
            "risk": risk,
            "prompt_seen": bool(challenge.get("prompt_seen")),
            "challenge_type": str(challenge.get("challenge_type") or "unknown"),
            "prompt_family": str(challenge.get("prompt_family") or "unknown"),
            "tested_pins": tested_pins,
            "evidence_sources": evidence_sources,
            "summary": summary,
        }

    def _build_pairing_transcript(
        self,
        address: str,
        pre_info: Dict[str, Any],
        post_info: Dict[str, Any],
        trust_lifecycle: Dict[str, Any],
        raw_output: str,
        reconnect_probe: Dict[str, Any],
    ) -> Dict[str, Any]:
        challenge = self._detect_pairing_challenge(raw_output)
        transcript_steps: List[Dict[str, Any]] = []
        if address:
            transcript_steps = [
                {"step": "pre_info", "status": "completed", "detail": f"paired={bool(pre_info.get('paired'))} trusted={bool(pre_info.get('trusted'))}"},
                {"step": "pair_sequence", "status": "completed" if raw_output else "unknown", "detail": str(challenge.get("challenge_type") or "unknown")},
                {"step": "post_info", "status": "completed", "detail": f"paired={bool(post_info.get('paired'))} trusted={bool(post_info.get('trusted'))}"},
                {"step": "reconnect_probe", "status": "completed" if reconnect_probe.get("attempted") else "skipped", "detail": str(reconnect_probe.get("result") or "not_attempted")},
            ]
        return {
            "pairing_method": trust_lifecycle.get("pairing_method") or "unknown",
            "challenge_type": challenge.get("challenge_type") or "unknown",
            "prompt_seen": bool(challenge.get("prompt_seen")),
            "paired_before": bool(pre_info.get("paired")),
            "paired_after": bool(post_info.get("paired")),
            "trusted_before": bool(pre_info.get("trusted")),
            "trusted_after": bool(post_info.get("trusted")),
            "bond_created": not bool(pre_info.get("paired")) and bool(post_info.get("paired")),
            "trust_changed": bool(pre_info.get("trusted")) != bool(post_info.get("trusted")),
            "reconnect_result": reconnect_probe.get("result") or "not_attempted",
            "steps": transcript_steps,
            "summary": (
                f"{trust_lifecycle.get('pairing_method') or 'unknown'} · "
                f"{challenge.get('challenge_type') or 'unknown'} · "
                f"paired {bool(post_info.get('paired'))} · trusted {bool(post_info.get('trusted'))} · "
                f"svc-resolved {bool(post_info.get('services_resolved'))}"
            ),
        }

    def _build_capture_plan(self, run_id: str, address: str) -> Dict[str, Any]:
        safe_address = str(address or "unknown").replace(":", "").lower() or "unknown"
        btmon_file = self.runs_dir / f"{run_id}-{safe_address}.btmon.log"
        tshark_file = self.runs_dir / f"{run_id}-{safe_address}.pcapng"
        return {
            "btmon": {
                **self._summarize_btmon_capability(),
                "target_path": str(btmon_file),
                "start_command": f"btmon | tee {btmon_file.name}",
            },
            "tshark": {
                **self._summarize_tshark_capability(),
                "target_path": str(tshark_file),
                "start_command": f"tshark -w {tshark_file.name}",
            },
        }

    def _build_validation_confidence(
        self,
        *,
        address: str,
        tool_catalog: Dict[str, Dict[str, Any]],
        pairing_transcript: Dict[str, Any],
        gatt_audit: Dict[str, Any],
        anomalies: List[str],
    ) -> Dict[str, Any]:
        score = 0
        if address:
            score += 20
        if tool_catalog.get("bluetoothctl", {}).get("installed"):
            score += 10
        if tool_catalog.get("btmon", {}).get("installed"):
            score += 15
        if tool_catalog.get("tshark", {}).get("installed"):
            score += 15
        if pairing_transcript.get("prompt_seen"):
            score += 10
        if pairing_transcript.get("paired_after"):
            score += 10
        if pairing_transcript.get("trusted_after"):
            score += 5
        if int(gatt_audit.get("service_count") or 0) > 0:
            score += 10
        if int(gatt_audit.get("characteristic_count") or 0) > 0:
            score += 5
        if anomalies:
            score += 5
        level = "low"
        if score >= 70:
            level = "high"
        elif score >= 40:
            level = "medium"
        return {
            "score": score,
            "level": level,
            "summary": f"{level} confidence · score {score}",
            "signals": {
                "addressed_target": bool(address),
                "btmon_ready": bool(tool_catalog.get("btmon", {}).get("installed")),
                "tshark_ready": bool(tool_catalog.get("tshark", {}).get("installed")),
                "pairing_prompt_seen": bool(pairing_transcript.get("prompt_seen")),
                "paired_after": bool(pairing_transcript.get("paired_after")),
                "trusted_after": bool(pairing_transcript.get("trusted_after")),
                "gatt_services_seen": int(gatt_audit.get("service_count") or 0),
                "gatt_characteristics_seen": int(gatt_audit.get("characteristic_count") or 0),
                "anomaly_count": len(anomalies),
            },
        }

    def _build_anomalies(self, device: Dict[str, Any], trust_lifecycle: Dict[str, Any], gatt_summary: Dict[str, Any]) -> List[str]:
        anomalies: List[str] = []
        if int(device.get("identity_variants") or 0) > 1:
            anomalies.append("identity_variation")
        if int(device.get("pairing_failures") or 0) > 0:
            anomalies.append("pairing_instability")
        if str(trust_lifecycle.get("reconnect_result") or "").startswith("reconnect_"):
            anomalies.append("reconnect_instability")
        if bool(gatt_summary.get("unauthenticated_access_detected")):
            anomalies.append("unauthenticated_gatt_access")
        if int(device.get("service_signatures") or 0) > 1:
            anomalies.append("service_exposure_drift")
        return anomalies

    def _build_recommendations(self, device: Dict[str, Any], trust_lifecycle: Dict[str, Any], gatt_summary: Dict[str, Any], anomalies: List[str]) -> List[str]:
        recommendations: List[str] = []
        if not bool(device.get("connectable")):
            recommendations.append("Keep this asset in passive monitoring until a connectable window is observed.")
        if str((device.get("resolution_state") or "")).lower() not in {"materialized", "validation_ready"}:
            recommendations.append("Improve host-side target materialization before deeper lab validation.")
        if bool(device.get("connectable")) and not bool(trust_lifecycle.get("services_resolved_after")):
            recommendations.append("Repeat the active test until BlueZ resolves services, then rerun the GATT audit.")
        if bool(gatt_summary.get("unauthenticated_access_detected")):
            recommendations.append("Repeat the GATT audit and verify that sensitive writable paths require authenticated and authorized access.")
        if "reconnect_instability" in anomalies:
            recommendations.append("Run a dedicated reconnect regression sequence and compare behavior across firmware versions.")
        if int(device.get("pairing_failures") or 0) > 0 or int(device.get("repair_flags") or 0) > 0:
            recommendations.append("Review pairing and bond lifecycle handling for downgrade, overwrite, or replacement edge cases.")
        if not recommendations:
            recommendations.append("Record this device as a baseline BLE target and compare future validation runs for drift.")
        return recommendations

    def _build_harder_test_vectors(
        self,
        *,
        address: str,
        session_result: Dict[str, Any],
        trust_lifecycle: Dict[str, Any],
        gatt_audit: Dict[str, Any],
        anomalies: List[str],
        executed_tests: List[Dict[str, Any]] | None = None,
    ) -> List[Dict[str, Any]]:
        reconnect_result = str(trust_lifecycle.get("reconnect_result") or "not_attempted")
        service_count = int(gatt_audit.get("service_count") or 0)
        writable_count = int(gatt_audit.get("writable_count") or 0)
        unauth_writable = bool(gatt_audit.get("unauthenticated_access_detected"))
        descriptor_count = int(gatt_audit.get("descriptor_count") or 0)
        cccd_count = int(gatt_audit.get("cccd_count") or 0)
        blocked = str(session_result.get("error") or "").strip().lower()
        blocked_detail = str(session_result.get("detail") or "").strip()
        executed_map = {
            str(item.get("id") or "").strip(): item
            for item in (executed_tests or [])
            if isinstance(item, dict) and str(item.get("id") or "").strip()
        }

        def vector(vector_id: str, label: str, objective: str, readiness: str, detail: str, evidence: List[str]) -> Dict[str, Any]:
            return {
                "id": vector_id,
                "label": label,
                "objective": objective,
                "readiness": readiness,
                "detail": detail,
                "evidence": evidence,
            }

        if not address:
            return [
                vector(
                    "target_missing",
                    "Target Address Gate",
                    "Harder owned-target validation requires a concrete BLE target address.",
                    "blocked",
                    "No target address available for active BLE testing.",
                    ["no_address"],
                )
            ]

        if blocked:
            return [
                vector(
                    "host_path_recovery",
                    "Host Materialization Recovery",
                    "Recover BlueZ and adapter readiness before deeper owned-target testing.",
                    "blocked",
                    blocked_detail or "Active validation path is blocked on host prerequisites.",
                    [blocked, "restore_host_stack", "retry_active_validation"],
                )
            ]

        vectors: List[Dict[str, Any]] = [
            vector(
                "reconnect_drift",
                "Reconnect Drift Audit",
                "Compare trust, service resolution, and visible GATT surface across disconnect/reconnect cycles.",
                "ready" if reconnect_result not in {"not_attempted", "dbus_unavailable"} else "partial",
                str((executed_map.get("reconnect_drift") or {}).get("detail") or f"Current reconnect result: {reconnect_result}. Re-run with repeated reconnect loops and compare post-reconnect drift."),
                list((executed_map.get("reconnect_drift") or {}).get("evidence") or [f"reconnect_result={reconnect_result}", f"anomalies={','.join(anomalies) or 'none'}"]),
            ),
            vector(
                "notify_surface",
                "Notify/Indicate Surface Audit",
                "Subscribe to notify and indicate paths on owned targets and capture pre/post-trust exposure changes.",
                "ready" if cccd_count > 0 or descriptor_count > 0 else "partial",
                str((executed_map.get("notify_surface") or {}).get("detail") or f"{cccd_count} CCCD descriptor(s) and {descriptor_count} descriptor(s) observed."),
                list((executed_map.get("notify_surface") or {}).get("evidence") or [f"cccd_count={cccd_count}", f"descriptor_count={descriptor_count}", f"service_count={service_count}"]),
            ),
            vector(
                "auth_boundary",
                "Authorization Boundary Probe",
                "Verify that writable and sensitive characteristics stay gated before trust, after trust, and after reconnect.",
                "ready" if service_count > 0 else "partial",
                str((executed_map.get("auth_boundary") or {}).get("detail") or f"{writable_count} writable characteristic(s) observed; unauthenticated writable exposure = {unauth_writable}."),
                list((executed_map.get("auth_boundary") or {}).get("evidence") or [f"writable_count={writable_count}", f"unauth_writable={unauth_writable}", f"service_count={service_count}"]),
            ),
            vector(
                "service_changed",
                "Service-Changed / Drift Audit",
                "Check whether service inventory or handles drift across trust transitions and reconnects.",
                "ready" if service_count > 0 else "partial",
                str((executed_map.get("service_changed") or {}).get("detail") or f"{service_count} service(s) currently visible in the owned-target session."),
                list((executed_map.get("service_changed") or {}).get("evidence") or [f"service_count={service_count}", f"reconnect_result={reconnect_result}"]),
            ),
        ]
        for item in vectors:
            executed = executed_map.get(str(item.get("id") or ""))
            if executed:
                item["execution_status"] = str(executed.get("status") or "completed")
                item["executed"] = bool(executed.get("executed"))
                item["findings"] = list(executed.get("findings") or [])
        return vectors

    def _module_status(self, observed_behavior: str, deviation: str, reproducibility_status: str = "reproducible") -> str:
        lowered_observed = str(observed_behavior or "").lower()
        lowered_deviation = str(deviation or "").lower()
        lowered_repro = str(reproducibility_status or "").lower()
        if lowered_repro in {"blocked", "planned"}:
            return "blocked" if lowered_repro == "blocked" else "planned"
        if any(token in lowered_deviation for token in ("unauthorized", "instability", "replacement", "downgrade", "requires review", "failed")):
            return "weak"
        if "blocked" in lowered_observed or "not available" in lowered_observed or "not executed" in lowered_observed:
            return "blocked"
        return "pass"

    def _red_team_value_summary(
        self,
        *,
        trust_lifecycle: Dict[str, Any],
        gatt_audit: Dict[str, Any],
        anomalies: List[str],
        harder_tests: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        highlights: List[str] = []
        if str(trust_lifecycle.get("reconnect_result") or "") not in {"", "not_attempted"}:
            highlights.append(f"reconnect={trust_lifecycle.get('reconnect_result')}")
        if int(gatt_audit.get("service_count") or 0) > 0:
            highlights.append(
                f"gatt={int(gatt_audit.get('service_count') or 0)}svc/{int(gatt_audit.get('characteristic_count') or 0)}char"
            )
        if bool(gatt_audit.get("unauthenticated_access_detected")):
            highlights.append("unauth_writable_detected")
        if anomalies:
            highlights.append(f"anomalies={','.join(anomalies[:3])}")
        ready_vectors = [item for item in harder_tests if str(item.get("readiness") or "") == "ready"]
        executed_vectors = [item for item in harder_tests if bool(item.get("executed"))]
        if ready_vectors:
            highlights.append(f"hard_tests_ready={len(ready_vectors)}")
        if executed_vectors:
            highlights.append(f"hard_tests_executed={len(executed_vectors)}")
        summary = "No high-value red-team evidence retained yet."
        if highlights:
            summary = " · ".join(highlights[:4])
        return {
            "summary": summary,
            "highlights": highlights[:6],
            "ready_hard_test_count": len(ready_vectors),
        }

    def _workflow_status(
        self,
        *,
        session_result: Dict[str, Any],
        trust_lifecycle: Dict[str, Any],
        gatt_audit: Dict[str, Any],
    ) -> str:
        if str(session_result.get("error") or "") in {"device_not_materialized", "dbus_unavailable"}:
            return "blocked"
        if bool(trust_lifecycle.get("paired_after")) and bool(trust_lifecycle.get("trusted_after")) and int(gatt_audit.get("service_count") or 0) > 0:
            return "verified"
        if str(trust_lifecycle.get("reconnect_result") or "") == "reconnect_failed":
            return "failed"
        if int(gatt_audit.get("service_count") or 0) > 0 or bool(trust_lifecycle.get("paired_after")) or bool(trust_lifecycle.get("trusted_after")):
            return "partial"
        return "blocked"

    def _result_record(
        self,
        *,
        module_id: str,
        objective: str,
        interaction_sequence: List[Dict[str, Any]],
        observed_behavior: str,
        expected_behavior: str,
        deviation: str,
        confidence_level: str,
        recommended_follow_up_actions: List[str],
        reproducibility_status: str = "reproducible",
        evidence: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {
            "module_id": module_id,
            "status": self._module_status(observed_behavior, deviation, reproducibility_status),
            "objective": objective,
            "interaction_sequence": interaction_sequence,
            "observed_behavior": observed_behavior,
            "expected_behavior": expected_behavior,
            "deviation": deviation,
            "reproducibility_status": reproducibility_status,
            "confidence_level": confidence_level,
            "recommended_follow_up_actions": recommended_follow_up_actions,
            "evidence": evidence or {},
        }

    def execute_workflow(self, device: Dict[str, Any], owned_target: bool, notes: str = "") -> Dict[str, Any]:
        if not owned_target:
            return {"status": "error", "error": "owned_target confirmation is required"}

        device_key = str(device.get("device_key") or "").strip().lower()
        address = str(device.get("address") or "").strip()
        run_id = self._make_run_id(device_key or address or "unknown")
        tool_catalog = self.tool_catalog()
        session_result: Dict[str, Any] = {}
        if address and self._bluez_run_validation_session:
            session_result = self._bluez_run_validation_session(address)
        use_dbus = bool(address) and (session_result.get("ok") or session_result.get("error"))
        if address and self._bluez_fetch_device_info:
            pre_info = self._bluez_fetch_device_info(address)
        elif address and session_result.get("ok"):
            pre_info = session_result.get("pre_info") if isinstance(session_result.get("pre_info"), dict) else {}
        else:
            pre_info = {}

        adversary_sequence = [
            self._build_sequence_step("bluez_dbus", "info", f"Device1.GetAll {address}", "Capture baseline trust state"),
            self._build_sequence_step("bluez_dbus", "connect", f"Device1.Connect {address}", "Test initial non-standard connect path"),
            self._build_sequence_step("bluez_dbus", "disconnect", f"Device1.Disconnect {address}", "Force reconnect boundary"),
            self._build_sequence_step("bluez_dbus", "pair", f"Device1.Pair {address}", "Trigger pairing while varying trust assumptions"),
            self._build_sequence_step("bluez_dbus", "trust", f"Device1.Trusted=true {address}", "Check host trust transitions"),
            self._build_sequence_step("bluez_dbus", "reconnect", f"Device1.Connect/Disconnect loop {address}", "Re-test behavior after trust transition"),
        ] if address else []
        if address and session_result.get("ok"):
            adversary_text = str(session_result.get("raw_output") or "")
            post_info = session_result.get("post_info") if isinstance(session_result.get("post_info"), dict) else {}
        elif address and use_dbus:
            adversary_text = str(session_result.get("detail") or session_result.get("raw_output") or "")
            post_info = self._bluez_fetch_device_info(address) if self._bluez_fetch_device_info else pre_info
        else:
            adversary_text = ""
            post_info = {}

        gatt_sequence = [
            self._build_sequence_step("bluez_dbus", "connect", f"Device1.Connect {address}", "Establish post-association session"),
            self._build_sequence_step("bluez_dbus", "introspect", f"Introspect {address}", "Enumerate service objects"),
            self._build_sequence_step("bluez_dbus", "gatt-getall", f"GattService1/GattCharacteristic1 GetAll {address}", "Enumerate services and characteristics"),
            self._build_sequence_step("bluez_dbus", "disconnect", f"Device1.Disconnect {address}", "Close validation session"),
        ] if address else []
        if address and session_result.get("ok"):
            gatt_summary = session_result.get("gatt") if isinstance(session_result.get("gatt"), dict) else {}
        elif address and use_dbus:
            gatt_summary = {}
        else:
            gatt_summary = {}

        stress_sequence = [
            self._build_sequence_step("bluez_dbus", "connect_loop", f"Device1.Connect/Disconnect {address} x3", "Measure stability under repeated sessions"),
        ] if address else []
        if address and session_result.get("ok"):
            reconnect_probe = session_result.get("reconnect_probe") if isinstance(session_result.get("reconnect_probe"), dict) else {}
            stress_successes = int(reconnect_probe.get("successful_attempts") or 0)
        elif address and use_dbus:
            reconnect_probe = {
                "attempted": bool(address),
                "result": str(session_result.get("error") or "reconnect_unknown"),
                "detail": str(session_result.get("detail") or "DBus validation path did not complete reconnect loop"),
                "successful_attempts": 0,
                "connect_attempts": 0,
            }
            stress_successes = 0
        else:
            reconnect_probe = {
                "attempted": False,
                "result": "no_address",
                "detail": "no address available",
                "successful_attempts": 0,
                "connect_attempts": 0,
            }
            stress_successes = 0

        trust_lifecycle = self._build_trust_lifecycle(device, pre_info, post_info, reconnect_probe)
        pin_audit = self._build_pin_audit(device, adversary_text, trust_lifecycle)
        gatt_audit = self._build_gatt_summary(device, gatt_summary, post_info)
        anomalies = self._build_anomalies(device, trust_lifecycle, gatt_audit)
        recommendations = self._build_recommendations(device, trust_lifecycle, gatt_audit, anomalies)
        pairing_transcript = self._build_pairing_transcript(address, pre_info, post_info, trust_lifecycle, adversary_text, reconnect_probe)
        capture_plan = self._build_capture_plan(run_id, address)
        harder_tests = self._build_harder_test_vectors(
            address=address,
            session_result=session_result,
            trust_lifecycle=trust_lifecycle,
            gatt_audit=gatt_audit,
            anomalies=anomalies,
            executed_tests=list(session_result.get("harder_test_results") or []),
        )
        validation_confidence = self._build_validation_confidence(
            address=address,
            tool_catalog=tool_catalog,
            pairing_transcript=pairing_transcript,
            gatt_audit=gatt_audit,
            anomalies=anomalies,
        )
        red_team_value = self._red_team_value_summary(
            trust_lifecycle=trust_lifecycle,
            gatt_audit=gatt_audit,
            anomalies=anomalies,
            harder_tests=harder_tests,
        )
        workflow_status = self._workflow_status(
            session_result=session_result,
            trust_lifecycle=trust_lifecycle,
            gatt_audit=gatt_audit,
        )

        modules = [
            self._result_record(
                module_id="adversary_emulation",
                objective="Exercise varied pairing, trust, and interrupted interaction flows.",
                interaction_sequence=adversary_sequence,
                observed_behavior=(
                    (
                        f"connect/pair/reconnect path executed · paired={bool(post_info.get('paired'))} · "
                        f"trusted={bool(post_info.get('trusted'))} · reconnect={reconnect_probe.get('result') or 'unknown'}"
                    ) if session_result.get("ok") else
                    (str(session_result.get("detail") or "BlueZ DBus validation path could not resolve the target.") if address else "No address available for active interaction.")
                ),
                expected_behavior="Owned device should handle repeated or interrupted trust interactions without unstable state transitions.",
                deviation=(
                    "Trust lifecycle anomalies observed."
                    if trust_lifecycle.get("trust_replacement_events") or trust_lifecycle.get("bond_events") or "reconnect_instability" in anomalies
                    else "No major trust deviation observed."
                ),
                confidence_level="medium",
                recommended_follow_up_actions=recommendations[:2],
                reproducibility_status="reproducible" if session_result.get("ok") else ("blocked" if address else "blocked"),
                evidence={"raw_output": adversary_text[-3000:], "pre_info": pre_info, "post_info": post_info, "session_error": session_result.get("error")},
            ),
            self._result_record(
                module_id="trust_lifecycle",
                objective="Model device behavior across pairing, bonding, trust persistence, and reconnect.",
                interaction_sequence=[
                    self._build_sequence_step("bluetoothctl", "info", f"info {address}", "Capture trust state before and after interaction")
                ] if address else [],
                observed_behavior=trust_lifecycle.get("summary") or "No trust lifecycle data.",
                expected_behavior="Trust state should remain consistent and explicit across controlled lab interactions.",
                deviation="Trust replacement or downgrade indicators present." if trust_lifecycle.get("trust_replacement_events") or trust_lifecycle.get("downgrade_indicators") else "No explicit trust lifecycle deviation observed.",
                confidence_level="high" if address else "low",
                recommended_follow_up_actions=recommendations[:2],
                evidence={**trust_lifecycle, "pairing_transcript": pairing_transcript},
            ),
            self._result_record(
                module_id="legacy_pin_audit",
                objective="Assess whether the device exposed a legacy PIN workflow and record the audit state for common default PINs.",
                interaction_sequence=[
                    self._build_sequence_step("bluez_dbus", "pair", f"Device1.Pair {address}", "Observe whether a PIN-based legacy challenge is presented")
                ] if address else [],
                observed_behavior=pin_audit.get("summary") or "No PIN audit evidence.",
                expected_behavior="Modern BLE devices should avoid reusable legacy PIN flows unless explicitly documented and controlled.",
                deviation="Legacy PIN workflow exposed." if pin_audit.get("risk") == "likely" else "No legacy PIN workflow observed.",
                confidence_level=validation_confidence.get("level") if address else "low",
                recommended_follow_up_actions=[
                    "If a legacy PIN prompt appears on an owned target, manually validate the provisioning flow and remove default-PIN behavior from production firmware."
                ],
                reproducibility_status="reproducible" if address else "blocked",
                evidence=pin_audit,
            ),
            self._result_record(
                module_id="security_boundary",
                objective="Compare pre-pair and post-pair access and validate authorization boundaries.",
                interaction_sequence=gatt_sequence,
                observed_behavior=(
                    f"{gatt_audit.get('summary') or 'No GATT data available.'} · "
                    f"vendor={int(gatt_audit.get('vendor_specific_services') or 0)} · "
                    f"ctrl={len(gatt_audit.get('potential_control_surfaces') or [])} · "
                    f"cccd={int(gatt_audit.get('cccd_count') or 0)}"
                ),
                expected_behavior="Sensitive surfaces should not expose unauthenticated or inconsistent access paths.",
                deviation="Potential unauthorized GATT surface detected." if gatt_audit.get("unauthenticated_access_detected") else "No obvious unauthorized GATT surface detected.",
                confidence_level="medium",
                recommended_follow_up_actions=recommendations[:2],
                reproducibility_status="reproducible" if session_result.get("ok") else ("blocked" if address else "blocked"),
                evidence=gatt_audit,
            ),
            self._result_record(
                module_id="misuse_case",
                objective="Run interrupted or reordered trust interactions.",
                interaction_sequence=adversary_sequence[:5],
                observed_behavior=(
                    f"interrupted sequence result={reconnect_probe.get('result') or 'unknown'} · "
                    f"pairing_failures={int(device.get('pairing_failures') or 0)} · "
                    f"repair_flags={int(device.get('repair_flags') or 0)}"
                ) if session_result.get("ok") else (str(session_result.get("detail") or "Misuse-case path did not execute.") if address else "No address available for misuse-case simulation."),
                expected_behavior="Device should roll back cleanly and avoid entering ambiguous trust state.",
                deviation="Observed pairing failure or lifecycle anomaly." if int(device.get("pairing_failures") or 0) > 0 or anomalies else "No clear misuse-case deviation observed.",
                confidence_level="medium",
                recommended_follow_up_actions=recommendations[:2],
                reproducibility_status="reproducible" if session_result.get("ok") else ("blocked" if address else "blocked"),
                evidence={"pairing_failures": int(device.get("pairing_failures") or 0), "anomalies": anomalies},
            ),
            self._result_record(
                module_id="stress_testing",
                objective="Measure device stability under repeated rapid interactions.",
                interaction_sequence=stress_sequence,
                observed_behavior=(
                    f"{stress_successes}/3 rapid connection attempts succeeded · reconnect={reconnect_probe.get('result') or 'unknown'}"
                    if address else "Stress test not executed."
                ),
                expected_behavior="Owned device should remain stable and consistent under repeated connect/disconnect loops.",
                deviation="Reconnect instability observed." if reconnect_probe.get("result") != "stable_reconnect" else "No major reconnect instability observed.",
                confidence_level="medium",
                recommended_follow_up_actions=recommendations[:2],
                reproducibility_status="reproducible" if session_result.get("ok") else ("blocked" if address else "blocked"),
                evidence=reconnect_probe,
            ),
            self._result_record(
                module_id="identity_emulation",
                objective="Prepare address rotation and alternate advertisement identity workflows for owned lab emitters.",
                interaction_sequence=[
                    self._build_sequence_step("bluez_dbus", "privacy-on", "btmgmt privacy on", "Enable host privacy rotation"),
                    self._build_sequence_step("scapy", "custom-adv", "python3 scapy_ble_identity_variation.py", "Craft alternate advertisement payloads"),
                    self._build_sequence_step("nordic_sniffer", "validate", "capture with Nordic Sniffer", "Validate rotated identity over the air"),
                ],
                observed_behavior="Identity emulation path defined, but not executed. This platform has no transmit-capable lab emitter enabled for this run.",
                expected_behavior="Owned lab emitter should be able to rotate identity and be observed by the passive sensor stack.",
                deviation="Execution deferred until a transmit-capable lab path is enabled.",
                confidence_level="low",
                recommended_follow_up_actions=[
                    "Add a dedicated transmit-capable lab adapter or custom firmware path before executing identity emulation.",
                    "Validate address rotation behavior with Nordic Sniffer and retained evidence correlation.",
                ],
                reproducibility_status="planned",
                evidence={"tool_prerequisites": self.tool_catalog()},
            ),
            self._result_record(
                module_id="post_association_surface",
                objective="Summarize post-association GATT surface and control exposure.",
                interaction_sequence=gatt_sequence,
                observed_behavior=(
                    f"{gatt_audit.get('summary') or 'No post-association data available.'} · "
                    f"notify={int(gatt_audit.get('notify_count') or 0)} · "
                    f"desc={int(gatt_audit.get('descriptor_count') or 0)}"
                ),
                expected_behavior="Writable and sensitive surfaces should be explicit, minimal, and consistently gated.",
                deviation="Sensitive surface or writable exposure requires review." if gatt_audit.get("writable_count") or gatt_audit.get("sensitive_surface_count") else "No high-value control surface observed.",
                confidence_level="medium",
                recommended_follow_up_actions=recommendations[:2],
                evidence=gatt_audit,
            ),
            self._result_record(
                module_id="behavioral_anomaly",
                objective="Identify pairing, reconnect, and service-exposure irregularities under controlled stress.",
                interaction_sequence=[],
                observed_behavior=", ".join(anomalies) if anomalies else "No major anomalies flagged by current evidence.",
                expected_behavior="Behavior should stay stable across repeated and interrupted interactions.",
                deviation="Anomalies detected." if anomalies else "No anomaly deviation observed.",
                confidence_level="medium",
                recommended_follow_up_actions=recommendations,
                evidence={"anomalies": anomalies},
            ),
            self._result_record(
                module_id="path_recommendation",
                objective="Rank the next highest-value validation path for this asset.",
                interaction_sequence=[],
                observed_behavior=red_team_value.get("summary") or "Recommendations generated from trust, GATT, and anomaly evidence.",
                expected_behavior="Platform should suggest reproducible next steps instead of relying on operator guesswork.",
                deviation="No deviation; this module is advisory.",
                confidence_level="high",
                recommended_follow_up_actions=recommendations,
                evidence={"recommended_next_steps": recommendations, "red_team_value": red_team_value, "harder_tests": harder_tests},
            ),
            self._result_record(
                module_id="evidence_replay",
                objective="Persist validation evidence and replay instructions for reproducibility.",
                interaction_sequence=[],
                observed_behavior="Validation run saved to JSON with replay-ready step sequences.",
                expected_behavior="Every lab run should produce structured evidence and replay instructions.",
                deviation="No deviation; evidence recording complete.",
                confidence_level="high",
                recommended_follow_up_actions=[
                    "Replay the same sequence after firmware changes and compare trust lifecycle deltas.",
                    "Attach btmon or tshark captures to the stored run for deeper protocol review.",
                ],
                evidence={
                    "btmon_capability": self._summarize_btmon_capability(),
                    "tshark_capability": self._summarize_tshark_capability(),
                    "capture_plan": capture_plan,
                    "replay_steps": [
                        "Load the saved validation run JSON.",
                        "Execute each interaction_sequence command in order on an owned target.",
                        "Compare observed_behavior and deviation fields against the previous run.",
                    ],
                },
            ),
        ]

        asset = {
            "identity_confidence": device.get("identity_confidence") or "low",
            "vendor_inference": device.get("vendor") or "Unknown",
            "category": device.get("priority_class") or "general",
            "product_family": device.get("likely_family") or "generic_ble",
            "logical_device_id": device.get("logical_device_id") or device_key,
            "linked_addresses": list(device.get("linked_addresses") or [address]),
            "identity_cluster_confidence": device.get("identity_cluster_confidence") or 0.0,
            "identity_cluster_evidence": list(device.get("identity_cluster_evidence") or []),
            "identity_cluster_ambiguity": bool(device.get("identity_cluster_ambiguity")),
            "pairability": device.get("pairable") or "unknown",
            "pairing_posture": trust_lifecycle.get("pairing_method") or "unknown",
            "legacy_pin_audit": pin_audit,
            "pairing_transcript": pairing_transcript,
            "trust_lifecycle_summary": trust_lifecycle,
            "gatt_exposure_summary": gatt_audit,
            "anomaly_indicators": anomalies,
            "validation_confidence": validation_confidence,
            "validation_history": [],
            "recommended_next_steps": recommendations,
            "harder_tests": harder_tests,
            "red_team_value": red_team_value,
        }
        payload = {
            "status": "completed",
            "workflow_status": workflow_status,
            "run_id": run_id,
            "timestamp": self._timestamp(),
            "device_key": device_key,
            "device_address": address,
            "notes": str(notes or "").strip(),
            "tool_catalog": tool_catalog,
            "modules": self.module_catalog(),
            "validation_results": modules,
            "asset": asset,
            "pin_audit": pin_audit,
            "pairing_transcript": pairing_transcript,
            "trust_lifecycle": trust_lifecycle,
            "gatt_audit": gatt_audit,
            "behavioral_anomalies": anomalies,
            "capture_plan": capture_plan,
            "validation_confidence": validation_confidence,
            "recommended_next_steps": recommendations,
            "harder_tests": harder_tests,
            "red_team_value": red_team_value,
        }
        self._write_run(payload)
        return payload

    def list_runs(self, device_key: str = "") -> List[Dict[str, Any]]:
        normalized_key = str(device_key or "").strip().lower()
        results: List[Dict[str, Any]] = []
        for path in sorted(self.runs_dir.glob("*.json"), reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if normalized_key and str(payload.get("device_key") or "").strip().lower() != normalized_key:
                continue
            results.append(
                {
                    "run_id": payload.get("run_id"),
                    "timestamp": payload.get("timestamp"),
                    "device_key": payload.get("device_key"),
                    "device_address": payload.get("device_address"),
                    "anomaly_count": len(payload.get("behavioral_anomalies") or []),
                    "recommendation_count": len(payload.get("recommended_next_steps") or []),
                }
            )
        return results
