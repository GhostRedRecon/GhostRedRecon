from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable, Dict, List, Optional


SweepSnapshotFn = Callable[[str, Dict[str, Any]], Dict[str, Any]]
RuntimeResetFn = Callable[[], None]
RetuneFn = Callable[[float], Dict[str, Any]]


DEFAULT_TAB_PROFILES: Dict[str, Dict[str, Any]] = {
    "SUB-GHZ": {
        "dwell_ms": 2500,
        "channels": [
            {"label": "315M", "frequency_mhz": 315.0},
            {"label": "433.92M", "frequency_mhz": 433.92},
            {"label": "868.1M", "frequency_mhz": 868.1},
            {"label": "915M", "frequency_mhz": 915.0},
        ],
    },
    "BLE": {
        "dwell_ms": 2500,
        "channels": [
            {"label": "ADV37", "frequency_mhz": 2402.0},
            {"label": "ADV38", "frequency_mhz": 2426.0},
            {"label": "ADV39", "frequency_mhz": 2480.0},
        ],
    },
    "LORA": {
        "dwell_ms": 2500,
        "channels": [
            {"label": "EU868", "frequency_mhz": 868.1},
            {"label": "US915", "frequency_mhz": 915.0},
            {"label": "ISM433", "frequency_mhz": 433.92},
        ],
    },
    "ZIGBEE": {
        "dwell_ms": 2500,
        "channels": [
            {"label": "CH11", "frequency_mhz": 2405.0},
            {"label": "CH15", "frequency_mhz": 2425.0},
            {"label": "CH20", "frequency_mhz": 2450.0},
            {"label": "CH24", "frequency_mhz": 2470.0},
            {"label": "CH26", "frequency_mhz": 2480.0},
        ],
    },
    "IOT": {
        "dwell_ms": 2500,
        "channels": [
            {"label": "BLE37", "frequency_mhz": 2402.0},
            {"label": "ZB11", "frequency_mhz": 2405.0},
            {"label": "WIFI1", "frequency_mhz": 2412.0},
            {"label": "ZB15", "frequency_mhz": 2425.0},
            {"label": "BLE38", "frequency_mhz": 2426.0},
            {"label": "WIFI6", "frequency_mhz": 2437.0},
            {"label": "ZB20", "frequency_mhz": 2450.0},
            {"label": "WIFI11", "frequency_mhz": 2462.0},
            {"label": "ZB24", "frequency_mhz": 2470.0},
            {"label": "BLE39", "frequency_mhz": 2480.0},
            {"label": "433.92", "frequency_mhz": 433.92},
            {"label": "868.30", "frequency_mhz": 868.30},
            {"label": "868.95", "frequency_mhz": 868.95},
            {"label": "869.525", "frequency_mhz": 869.525},
            {"label": "LORA915", "frequency_mhz": 915.0},
        ],
    },
    "WIFI": {
        "dwell_ms": 2500,
        "channels": [
            {"label": "CH1", "frequency_mhz": 2412.0},
            {"label": "CH6", "frequency_mhz": 2437.0},
            {"label": "CH11", "frequency_mhz": 2462.0},
        ],
    },
}


class SDRTabSweepManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tabs = {tab: self._empty_entry() for tab in DEFAULT_TAB_PROFILES}
        self._active_tab: Optional[str] = None
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _empty_entry(self) -> Dict[str, Any]:
        return {
            "state": None,
            "archive_signals": [],
            "archive_devices": [],
            "profile_counts": {},
            "last_sweep_meta": None,
        }

    def get_state(self, tab: str) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._tabs.get(tab.upper(), self._empty_entry()))

    def start(
        self,
        tab: str,
        *,
        duration_minutes: float,
        snapshot_fn: SweepSnapshotFn,
        retune_fn: RetuneFn,
        reset_runtime_fn: RuntimeResetFn,
        dwell_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        tab = str(tab or "").upper()
        profile = DEFAULT_TAB_PROFILES.get(tab)
        if not profile:
            return {"status": "error", "error": f"Unsupported tab: {tab}"}

        with self._lock:
            if self._active_tab and self._active_tab != tab and self._worker and self._worker.is_alive():
                return {
                    "status": "busy",
                    "error": f"{self._active_tab} sweep is already running.",
                    "sweep": self.get_state(self._active_tab),
                }
            if self._active_tab == tab and self._worker and self._worker.is_alive():
                return {"status": "already_running", "sweep": self.get_state(tab)}

            self._stop_event.clear()
            self._active_tab = tab
            self._tabs[tab] = self._empty_entry()

            channels = [dict(channel) for channel in profile.get("channels", [])]
            effective_dwell_ms = int(dwell_ms or profile.get("dwell_ms") or 2500)
            started_at = time.time()
            duration_ms = int(max(0.0, float(duration_minutes or 0.0)) * 60_000)
            state = {
                "tab": tab,
                "running": True,
                "completed": False,
                "stopRequested": False,
                "stoppedByOperator": False,
                "currentIndex": 0,
                "total": len(channels),
                "currentLabel": channels[0]["label"] if channels else None,
                "currentFrequencyMHz": channels[0]["frequency_mhz"] if channels else None,
                "dwellMs": effective_dwell_ms,
                "cycle": 1,
                "startedAt": started_at,
                "completedAt": None,
                "durationMinutes": float(duration_minutes or 0.0),
                "durationMs": duration_ms,
                "error": "",
            }
            self._tabs[tab]["state"] = state

            self._worker = threading.Thread(
                target=self._run_sweep,
                kwargs={
                    "tab": tab,
                    "channels": channels,
                    "dwell_ms": effective_dwell_ms,
                    "duration_ms": duration_ms,
                    "snapshot_fn": snapshot_fn,
                    "retune_fn": retune_fn,
                    "reset_runtime_fn": reset_runtime_fn,
                },
                daemon=True,
            )
            self._worker.start()
            return {"status": "started", "sweep": self.get_state(tab)}

    def stop(self, tab: str) -> Dict[str, Any]:
        tab = str(tab or "").upper()
        with self._lock:
            state = self._tabs.get(tab, {}).get("state")
            if not state or tab != self._active_tab or not state.get("running"):
                return {"status": "idle", "sweep": self.get_state(tab)}
            state["stopRequested"] = True
            state["stoppedByOperator"] = True
            self._stop_event.set()
        return {"status": "stop_requested", "sweep": self.get_state(tab)}

    def clear(self, tab: str, reset_runtime_fn: Optional[RuntimeResetFn] = None) -> Dict[str, Any]:
        tab = str(tab or "").upper()
        self.stop(tab)
        worker = None
        with self._lock:
            worker = self._worker if self._active_tab == tab else None
        if worker and worker.is_alive():
            worker.join(timeout=1.5)
        if reset_runtime_fn:
            try:
                reset_runtime_fn()
            except Exception:
                pass
        with self._lock:
            self._tabs[tab] = self._empty_entry()
            if self._active_tab == tab:
                self._active_tab = None
                self._worker = None
                self._stop_event.clear()
        return {"status": "cleared", "sweep": self.get_state(tab)}

    def _run_sweep(
        self,
        *,
        tab: str,
        channels: List[Dict[str, Any]],
        dwell_ms: int,
        duration_ms: int,
        snapshot_fn: SweepSnapshotFn,
        retune_fn: RetuneFn,
        reset_runtime_fn: RuntimeResetFn,
    ) -> None:
        try:
            reset_runtime_fn()
        except Exception:
            pass

        started_at = time.time()
        cycle = 1
        try:
            while not self._stop_event.is_set():
                for index, channel in enumerate(channels):
                    if self._stop_event.is_set():
                        break
                    if duration_ms > 0 and ((time.time() - started_at) * 1000.0) >= duration_ms:
                        self._finalize(tab, completed=True, cycle=cycle)
                        return
                    self._update_state(
                        tab,
                        currentIndex=index + 1,
                        currentLabel=channel.get("label"),
                        currentFrequencyMHz=channel.get("frequency_mhz"),
                        cycle=cycle,
                    )
                    retune_fn(float(channel.get("frequency_mhz")))
                    self._sample_channel(tab, channel, dwell_ms, snapshot_fn)
                if self._stop_event.is_set() or duration_ms <= 0:
                    break
                cycle += 1
            self._finalize(tab, completed=not self._tabs.get(tab, {}).get("state", {}).get("stoppedByOperator"), cycle=cycle)
        except Exception as exc:
            self._update_state(tab, running=False, completed=False, error=str(exc), completedAt=time.time())
            with self._lock:
                if self._active_tab == tab:
                    self._active_tab = None
                    self._worker = None
                    self._stop_event.clear()

    def _sample_channel(
        self,
        tab: str,
        channel: Dict[str, Any],
        dwell_ms: int,
        snapshot_fn: SweepSnapshotFn,
    ) -> None:
        dwell_seconds = max(0.25, dwell_ms / 1000.0)
        settle_seconds = min(0.35, dwell_seconds * 0.2)
        deadline = time.time() + dwell_seconds
        if settle_seconds > 0:
            time.sleep(settle_seconds)
        sample_spacing = max(0.3, min(0.9, (dwell_seconds - settle_seconds) / 2 if dwell_seconds > settle_seconds else dwell_seconds))
        while time.time() < deadline and not self._stop_event.is_set():
            snapshot = snapshot_fn(tab, channel) or {}
            self._merge_snapshot(tab, channel, snapshot)
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            time.sleep(min(sample_spacing, remaining))

    def _merge_snapshot(self, tab: str, channel: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        with self._lock:
            entry = self._tabs[tab]
            profile_key = f"{channel.get('label')}::{channel.get('frequency_mhz')}"
            profile_stats = entry["profile_counts"].setdefault(
                profile_key,
                {
                    "label": channel.get("label"),
                    "frequencyMHz": channel.get("frequency_mhz"),
                    "signals": 0,
                    "devices": 0,
                    "lastUpdatedAt": None,
                },
            )
            now = time.time()
            profile_stats["lastUpdatedAt"] = now

            signal_index = {
                str(item.get("signal_id") or f"{item.get('frequency_mhz')}::{item.get('protocol')}"): item
                for item in entry["archive_signals"]
                if isinstance(item, dict)
            }
            new_signal_count = 0
            for signal in snapshot.get("signals") or []:
                if not isinstance(signal, dict):
                    continue
                key = str(signal.get("signal_id") or f"{signal.get('frequency_mhz')}::{signal.get('protocol')}")
                if key not in signal_index:
                    signal_copy = copy.deepcopy(signal)
                    signal_copy["sweep_profile_label"] = channel.get("label")
                    signal_copy["sweep_profile_frequency_mhz"] = channel.get("frequency_mhz")
                    entry["archive_signals"].append(signal_copy)
                    signal_index[key] = signal_copy
                    new_signal_count += 1
            device_index = {
                str(item.get("device_id") or item.get("mac_address") or item.get("vendor") or id(item)): item
                for item in entry["archive_devices"]
                if isinstance(item, dict)
            }
            new_device_count = 0
            for device in snapshot.get("devices") or []:
                if not isinstance(device, dict):
                    continue
                key = str(device.get("device_id") or device.get("mac_address") or device.get("vendor") or id(device))
                if key not in device_index:
                    entry["archive_devices"].append(copy.deepcopy(device))
                    device_index[key] = device
                    new_device_count += 1
            profile_stats["signals"] += new_signal_count
            profile_stats["devices"] += new_device_count

            entry["archive_signals"] = entry["archive_signals"][-350:]
            entry["archive_devices"] = entry["archive_devices"][-160:]

    def _update_state(self, tab: str, **updates: Any) -> None:
        with self._lock:
            state = self._tabs.get(tab, {}).get("state")
            if not state:
                return
            state.update(updates)

    def _finalize(self, tab: str, *, completed: bool, cycle: int) -> None:
        with self._lock:
            entry = self._tabs.get(tab) or self._empty_entry()
            state = entry.get("state") or {}
            now = time.time()
            if state:
                state["running"] = False
                state["completed"] = bool(completed)
                state["completedAt"] = now
                state["cycle"] = cycle
            entry["last_sweep_meta"] = {
                "completedAt": now,
                "signalCount": len(entry.get("archive_signals") or []),
                "deviceCount": len(entry.get("archive_devices") or []),
                "profilesScanned": state.get("total") or len(DEFAULT_TAB_PROFILES.get(tab, {}).get("channels", [])),
                "finalLabel": state.get("currentLabel"),
                "finalFrequencyMHz": state.get("currentFrequencyMHz"),
                "tab": tab,
                "completed": bool(completed),
                "stoppedByOperator": bool(state.get("stoppedByOperator")),
            }
            if self._active_tab == tab:
                self._active_tab = None
                self._worker = None
                self._stop_event.clear()
