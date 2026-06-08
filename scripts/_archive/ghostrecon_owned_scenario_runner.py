#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]


def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def log(message: str) -> None:
    print(f"[owned-scenario-runner] {message}", flush=True)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


class OwnedScenarioRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root_dir = REPO_ROOT
        self.run_dir = self.root_dir / "evidence" / "scenario_runs" / now_ts()
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> int:
        scenarios = [item.strip().lower() for item in self.args.scenario if item.strip()]
        if not scenarios:
            scenarios = ["idle", "app_open", "live_view"]

        runs: List[Dict[str, Any]] = []
        for scenario in scenarios:
            cmd = [
                "python3",
                str(self.root_dir / "scripts" / "ghostrecon_camera_huntv3.py"),
                "--preset",
                self.args.preset,
                "--duration-seconds",
                str(int(self.args.duration_seconds)),
                "--dwell-ms",
                str(int(self.args.dwell_ms)),
                "--scan-scenario",
                scenario,
                "--force-reset",
            ]
            for channel in self.args.evidence_channel:
                cmd.extend(["--evidence-channel", str(int(channel))])
            if self.args.decrypt_followup:
                cmd.append("--decrypt-followup")

            started = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            runs.append(
                {
                    "scenario": scenario,
                    "command": cmd,
                    "ok": result.returncode == 0,
                    "returncode": result.returncode,
                    "elapsed_seconds": round(time.time() - started, 1),
                    "stdout_tail": (result.stdout or "").splitlines()[-30:],
                    "stderr_tail": (result.stderr or "").splitlines()[-30:],
                }
            )
            log(f"{scenario}: returncode={result.returncode}")

        payload = {
            "generated_at": int(time.time()),
            "preset": self.args.preset,
            "duration_seconds": int(self.args.duration_seconds),
            "dwell_ms": int(self.args.dwell_ms),
            "decrypt_followup": bool(self.args.decrypt_followup),
            "runs": runs,
        }
        write_json(self.run_dir / "owned_scenario_runner_report.json", payload)
        log(f"run directory: {self.run_dir}")
        return 0 if all(item["ok"] for item in runs) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run owned camera scenarios against a preset target")
    parser.add_argument("--preset", default="xiaomi_owned", help="Owned preset name")
    parser.add_argument("--scenario", action="append", default=[], help="Scenario name; repeat for multiple scenarios")
    parser.add_argument("--duration-seconds", type=int, default=60, help="Duration for each scenario run")
    parser.add_argument("--dwell-ms", type=int, default=1200, help="Per-channel dwell in milliseconds")
    parser.add_argument("--evidence-channel", action="append", type=int, default=[6], help="Authorized evidence channels")
    parser.add_argument("--decrypt-followup", action="store_true", help="Run decrypt follow-up for each scenario")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return OwnedScenarioRunner(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
