# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         behavior_profiler.py
# VERSION:      v3.1.0 (PIPELINE SAFE + NON-DESTRUCTIVE)
# UPDATED:      2026-03-25
# =============================================================================

import time
from collections import defaultdict, deque
import statistics


class BehaviorProfiler:
    """
    SIGINT Behavior Profiler

    Responsibilities:
    - Track device activity over time
    - Extract temporal patterns
    - Identify transmission behavior
    - Classify device behavior types
    - Support BLE + Zigbee + future protocols

    Core Concepts:
    - Event stream → temporal model → behavior inference
    """

    def __init__(self, window_size=100):

        # Store last N timestamps per device
        self.device_events = defaultdict(lambda: deque(maxlen=window_size))

        # Behavior profiles
        self.device_profiles = {}

        # Stats
        self.total_events = 0

        # Config
        self.window_size = window_size

        print("🧠 [BEHAVIOR] Profiler initialized")

    # -----------------------------------------------------------------------------
    # 🔥 NEW: PIPELINE ENTRY (CRITICAL FIX)
    # -----------------------------------------------------------------------------
    def process(self, events):
        """
        Pipeline-safe batch processor
        NEVER drops events
        """

        if not events:
            return events

        enriched_events = []

        for event in events:

            # 🔹 Run existing logic
            self.process_event(event)

            # 🔹 Attach behavior if available
            device_id = event.get("device_id") or event.get("mac_address")

            if device_id:
                profile = self.device_profiles.get(device_id)

                if profile:
                    event["behavior"] = profile
                else:
                    event["behavior"] = {"type": "insufficient_data"}

            enriched_events.append(event)

        # ✅ CRITICAL: ALWAYS return events
        return enriched_events

    # -----------------------------------------------------------------------------
    # ORIGINAL FUNCTION (UNCHANGED)
    # -----------------------------------------------------------------------------
    def process_event(self, event):
        """
        Process incoming event from BLE / Zigbee / RF
        """

        device_id = event.get("device_id") or event.get("mac_address")
        timestamp = event.get("timestamp", time.time())

        if not device_id:
            return

        # Store timestamp
        self.device_events[device_id].append(timestamp)

        self.total_events += 1

        # Update behavior profile
        if len(self.device_events[device_id]) >= 5:
            profile = self._analyze_device(device_id)
            self.device_profiles[device_id] = profile

    # -----------------------------------------------------------------------------
    # DEVICE ANALYSIS (UNCHANGED)
    # -----------------------------------------------------------------------------
    def _analyze_device(self, device_id):

        timestamps = list(self.device_events[device_id])

        if len(timestamps) < 5:
            return {"type": "insufficient_data"}

        # Compute intervals
        intervals = [
            t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])
        ]

        avg_interval = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # ---------------------------------------------------------
        # CLASSIFICATION LOGIC (CORE INTELLIGENCE)
        # ---------------------------------------------------------

        if std_dev < 0.05 and avg_interval < 2:
            behavior_type = "periodic_beacon"

        elif std_dev < 0.1 and avg_interval >= 2:
            behavior_type = "low_power_device"

        elif std_dev > 0.5 and avg_interval < 1:
            behavior_type = "bursty_device"

        elif std_dev > 0.5:
            behavior_type = "mobile_device"

        else:
            behavior_type = "unknown"

        # ---------------------------------------------------------
        # DENSITY / ACTIVITY LEVEL
        # ---------------------------------------------------------
        event_count = len(timestamps)

        if event_count > 50:
            activity = "high"
        elif event_count > 20:
            activity = "medium"
        else:
            activity = "low"

        return {
            "type": behavior_type,
            "avg_interval": round(avg_interval, 3),
            "std_dev": round(std_dev, 3),
            "activity": activity,
            "event_count": event_count,
            "last_seen": timestamps[-1]
        }

    # -----------------------------------------------------------------------------
    def get_profiles(self):
        return self.device_profiles

    def get_device_profile(self, device_id):
        return self.device_profiles.get(device_id)

    def get_summary(self):

        summary = defaultdict(int)

        for profile in self.device_profiles.values():
            summary[profile["type"]] += 1

        return dict(summary)

    def is_active(self):
        return len(self.device_profiles) > 0
