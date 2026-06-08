from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class ReplayManager:
    def __init__(self, evidence_root: Path) -> None:
        self.evidence_root = Path(evidence_root)

    def list_sessions(self) -> List[Dict[str, Any]]:
        sessions: List[Dict[str, Any]] = []
        for entry in sorted(self.evidence_root.glob("SESSION_*"), reverse=True):
            session_json = entry / "session.json"
            targets_json = entry / "targets" / "index.json"
            if not session_json.exists():
                continue
            try:
                session = json.loads(session_json.read_text(encoding="utf-8"))
            except Exception:
                continue
            target_count = 0
            if targets_json.exists():
                try:
                    target_count = int((json.loads(targets_json.read_text(encoding="utf-8")) or {}).get("count") or 0)
                except Exception:
                    target_count = 0
            sessions.append(
                {
                    "session_id": session.get("session_id") or entry.name,
                    "session_name": session.get("session_name") or entry.name,
                    "path": str(entry),
                    "created_at": session.get("created_at"),
                    "scan_profile": session.get("scan_profile"),
                    "target_count": target_count,
                }
            )
        return sessions[:32]

    def load_session(self, session_id: str) -> Dict[str, Any]:
        session_dir = self.evidence_root / session_id
        if not session_dir.exists():
            return {"ok": False, "error": "Replay session not found."}
        try:
            session = json.loads((session_dir / "session.json").read_text(encoding="utf-8"))
            targets = json.loads((session_dir / "targets" / "index.json").read_text(encoding="utf-8"))
            topology = json.loads((session_dir / "topology" / "graph.json").read_text(encoding="utf-8"))
            report = json.loads((session_dir / "reports" / "summary.json").read_text(encoding="utf-8"))
            baseline = json.loads((session_dir / "environment_baseline.json").read_text(encoding="utf-8"))
            dji_manifest = json.loads((session_dir / "dji" / "decode_manifest.json").read_text(encoding="utf-8")) if (session_dir / "dji" / "decode_manifest.json").exists() else {}
            remote_id_entities = json.loads((session_dir / "remote_id" / "parsed_entities.json").read_text(encoding="utf-8")) if (session_dir / "remote_id" / "parsed_entities.json").exists() else {}
            remote_id_objects = json.loads((session_dir / "remote_id" / "parsed_objects.json").read_text(encoding="utf-8")) if (session_dir / "remote_id" / "parsed_objects.json").exists() else {}
            leads = json.loads((session_dir / "leads" / "index.json").read_text(encoding="utf-8")) if (session_dir / "leads" / "index.json").exists() else {}
            session_trace = json.loads((session_dir / "replay" / "session_trace.json").read_text(encoding="utf-8")) if (session_dir / "replay" / "session_trace.json").exists() else {}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {
            "ok": True,
            "session": session,
            "detections": targets.get("targets") or [],
            "topology": topology,
            "report": report,
            "baseline": baseline,
            "dji_manifest": dji_manifest,
            "remote_id_entities": remote_id_entities.get("items") or [],
            "remote_id_objects": remote_id_objects.get("items") or [],
            "assurance_leads": leads.get("items") or [],
            "session_trace": session_trace,
            "replay_status": "loaded",
            "comparison": {
                "previous_score_model": report.get("score_model_version") or "unknown",
                "current_score_model": report.get("score_model_version") or "unknown",
                "delta_summary": "Replay loaded from retained evidence bundle.",
            },
        }
