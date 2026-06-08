from __future__ import annotations

from typing import Any, Dict, List


class TopologyGraphBuilder:
    def build(self, session_id: str, session_name: str, detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        if session_id:
            nodes.append({"id": f"session-{session_id}", "label": session_name, "type": "session", "confidence": 100})
            nodes.append({"id": f"sensor-wifi-{session_id}", "label": "MK7AC", "type": "sensor", "confidence": 100})
            nodes.append({"id": f"sensor-sdr-{session_id}", "label": "HackRF", "type": "sensor", "confidence": 100})
        seen_family_nodes: Dict[str, str] = {}
        for item in detections:
            family = str(item.get("family_label") or item.get("manufacturer") or "Unknown Family")
            if family not in seen_family_nodes:
                family_id = f"family-{family.lower().replace(' ', '-')}"
                seen_family_nodes[family] = family_id
                nodes.append({"id": family_id, "label": family, "type": "family_cluster", "confidence": max(40, int(item.get("confidence_score", {}).get("score", 0)) - 5)})
            target_id = str(item.get("target_id") or item.get("identifier") or family)
            nodes.append(
                {
                    "id": target_id,
                    "label": item.get("label") or target_id,
                    "type": "target",
                    "confidence": int(item.get("confidence_score", {}).get("score", 0)),
                    "proof_tier": item.get("proof_tier", {}).get("tier"),
                }
            )
            if session_id:
                edges.append({"id": f"edge-session-{target_id}", "source": f"session-{session_id}", "target": target_id, "type": "same_session_recurrence"})
                edges.append({"id": f"edge-family-{target_id}", "source": seen_family_nodes[family], "target": target_id, "type": "same_family"})
                for sensor in item.get("sensor_sources") or []:
                    sensor_id = f"sensor-{sensor.lower()}-{session_id}"
                    edges.append({"id": f"edge-{sensor_id}-{target_id}", "source": sensor_id, "target": target_id, "type": "seen_together_in_time"})
        return {"nodes": nodes, "edges": edges}


class ReportBuilder:
    def build(self, session: Dict[str, Any], detections: List[Dict[str, Any]], baseline: Dict[str, Any]) -> Dict[str, Any]:
        proof_histogram: Dict[str, int] = {}
        for item in detections:
            key = str(item.get("proof_tier", {}).get("tier", 0))
            proof_histogram[key] = proof_histogram.get(key, 0) + 1
        evidence_manifest = {
            "target_count": len(detections),
            "replayable": True,
            "required_paths": [
                "session.json",
                "policy_state.json",
                "environment_baseline.json",
                "targets/index.json",
                "timeline/events.jsonl",
                "reports/summary.json",
            ],
        }
        return {
            "generated_at": session.get("created_at"),
            "session_id": session.get("session_id"),
            "session_name": session.get("session_name"),
            "score_model_version": "hunt_drones_v2",
            "summary": {
                "detections": len(detections),
                "confirmed_remote_id": len([item for item in detections if str(item.get("target_class") or "") == "Confirmed Remote ID Drone"]),
                "decoder_backed": len([item for item in detections if int(item.get("proof_tier", {}).get("tier", 0)) >= 2]),
                "multi_sensor": len([item for item in detections if "sdr" in (item.get("sensor_sources") or []) and "wifi" in (item.get("sensor_sources") or [])]),
            },
            "proof_tier_distribution": proof_histogram,
            "baseline_summary": baseline.get("summary"),
            "language": [
                "Passive evidence indicates drone-related activity only where retained artifacts support the claim.",
                "Exact model identification is avoided unless decoder-backed evidence justifies it.",
                "Disruption Susceptibility Score is an audit estimate and never an operational recommendation.",
            ],
            "evidence_manifest": evidence_manifest,
        }

    def build_operator_markdown(self, report: Dict[str, Any], detections: List[Dict[str, Any]]) -> str:
        lines = [
            f"# {report.get('session_name') or 'Hunt Drones Session'}",
            "",
            "## Summary",
            f"- Detections: {report.get('summary', {}).get('detections', 0)}",
            f"- Decoder-backed: {report.get('summary', {}).get('decoder_backed', 0)}",
            f"- Multi-sensor: {report.get('summary', {}).get('multi_sensor', 0)}",
            "",
            "## Targets",
        ]
        for item in detections[:12]:
            lines.append(
                f"- {item.get('label')}: proof tier {item.get('proof_tier', {}).get('tier', 0)} · confidence {item.get('confidence_score', {}).get('score', 0)} · DSS {item.get('disruption_susceptibility', {}).get('label', 'Unknown')}"
            )
        return "\n".join(lines) + "\n"
