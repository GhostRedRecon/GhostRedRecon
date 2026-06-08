# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       ADAPTIVE LEARNING ENGINE (PERSISTENCE ENABLED)
# FILE:         backend/recon/intelligence/adaptive_learning_engine.py
#
# VERSION:      v3.0.0 (SIGINT ADAPTIVE LEARNING + PERSISTENCE + LONG-TERM MEMORY)
# UPDATED:      2026-03-18
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# This module provides a SIGINT-grade adaptive intelligence layer with durable
# memory. It learns from RF observations over time and persists knowledge across
# sessions, enabling long-term intelligence accumulation.
#
# It enhances:
# • device identity confidence via reinforcement/decay
# • ecosystem detection via learned patterns
# • co-occurrence intelligence across devices
# • anomaly detection for rare/unseen behaviors
# • long-term memory across runs (disk persistence)
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# device_fusion.py (v13)          → devices + edges (graph)
# device_identity_engine.py (v2)  → per-device identity/confidence
# device_intelligence.py (v2)     → ecosystem + roles
#        ↓
# AdaptiveLearningEngine (THIS)   → learn() / adjust_confidence() / anomalies
#        ↓
# Persistent Store (JSON)         → load() / save() / rotate()
#        ↓
# Feedback loop                  → identity & ecosystem refinement
#
# =============================================================================
# INTERNAL FLOW
# =============================================================================
#
# load_state()  → load persisted memory (if present)
# learn()       → update in-memory stats from current scan
# save_state()  → persist snapshot (periodic or on shutdown)
# adjust_confidence() → apply reinforcement + decay
# detect_anomaly()    → flag rare protocols / combos
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. DURABLE INTELLIGENCE
#    Knowledge must survive process restarts.
#
# 2. CONSERVATIVE LEARNING
#    Only reinforce repeated, stable observations.
#
# 3. DECAY OVER TIME
#    Stale observations lose influence.
#
# 4. DETERMINISTIC & AUDITABLE
#    No black-box ML; all effects are explainable.
#
# 5. BOUNDED STORAGE
#    Cap growth and rotate files to avoid unbounded size.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
# • long-term device memory (observations, dominant features)
# • protocol frequency modeling
# • device co-occurrence learning
# • environment trend learning
# • confidence adjustment (reinforcement + decay)
# • anomaly detection
# • persistence (load/save/rotation)
#
# This module is NOT responsible for:
# • signal processing / SDR control
# • classification logic (identity engine owns it)
# • API transport
#
# =============================================================================
# IMPORTANT NOTES
# =============================================================================
#
# • Persistence uses JSON for portability and auditability
# • Writes are atomic (temp file → replace) to avoid corruption
# • Periodic save is recommended (e.g., every N seconds)
# • Memory growth is capped via max_devices and rotation
# • Never over-boost confidence (strict caps enforced)
#
# =============================================================================

import json
import os
import time
from collections import defaultdict
from typing import Dict, Any, List


class AdaptiveLearningEngine:

    VERSION = "3.0.0"

    MAX_CONFIDENCE_BOOST = 0.25
    DECAY_FACTOR = 0.995

    DEFAULT_PATH = "/tmp/ghostrecon_learning.json"
    ROTATE_LIMIT = 3  # keep last N snapshots
    MAX_DEVICES = 10000

    # ------------------------------------------------------------------
    # INIT
    # ------------------------------------------------------------------

    def __init__(self, persistence_path: str = None):

        self.persistence_path = persistence_path or self.DEFAULT_PATH

        # in-memory structures
        self.device_memory: Dict[str, Dict[str, Any]] = {}
        self.protocol_memory = defaultdict(int)
        self.cooccurrence_matrix = defaultdict(lambda: defaultdict(int))
        self.environment_profiles = defaultdict(int)

        self._last_save_ts = 0.0

        # load existing state if present
        self.load_state()

    # ------------------------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------------------------

    def load_state(self):
        try:
            if not os.path.exists(self.persistence_path):
                return

            with open(self.persistence_path, "r") as f:
                data = json.load(f)

            self.device_memory = data.get("device_memory", {})
            self.protocol_memory = defaultdict(int, data.get("protocol_memory", {}))

            # rebuild nested defaultdict for cooccurrence
            raw = data.get("cooccurrence_matrix", {})
            self.cooccurrence_matrix = defaultdict(lambda: defaultdict(int))
            for a, inner in raw.items():
                for b, v in inner.items():
                    self.cooccurrence_matrix[a][b] = v

            self.environment_profiles = defaultdict(int, data.get("environment_profiles", {}))

        except Exception:
            # fail-safe: start fresh
            self.device_memory = {}
            self.protocol_memory = defaultdict(int)
            self.cooccurrence_matrix = defaultdict(lambda: defaultdict(int))
            self.environment_profiles = defaultdict(int)

    def save_state(self, force: bool = False):
        now = time.time()

        # throttle saves (e.g., every 10s) unless forced
        if not force and (now - self._last_save_ts) < 10:
            return

        self._last_save_ts = now

        data = {
            "version": self.VERSION,
            "ts": now,
            "device_memory": self.device_memory,
            "protocol_memory": dict(self.protocol_memory),
            "cooccurrence_matrix": {
                a: dict(inner) for a, inner in self.cooccurrence_matrix.items()
            },
            "environment_profiles": dict(self.environment_profiles),
        }

        tmp_path = self.persistence_path + ".tmp"

        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f)

            os.replace(tmp_path, self.persistence_path)
            self._rotate_backups()

        except Exception:
            # best-effort persistence; do not crash pipeline
            pass

    def _rotate_backups(self):
        base = self.persistence_path
        for i in range(self.ROTATE_LIMIT, 0, -1):
            older = f"{base}.{i}"
            newer = f"{base}.{i-1}" if i > 1 else base
            if os.path.exists(newer):
                try:
                    os.replace(newer, older)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # MAIN LEARNING ENTRY
    # ------------------------------------------------------------------

    def learn(self, devices: List[Dict[str, Any]], edges: List[Dict[str, Any]], ecosystem: Dict[str, Any]):

        now = time.time()

        self._learn_devices(devices, now)
        self._learn_protocols(devices)
        self._learn_relationships(edges)
        self._learn_environment(ecosystem)

        # optional periodic save
        self.save_state()

    # ------------------------------------------------------------------
    # DEVICE MEMORY
    # ------------------------------------------------------------------

    def _learn_devices(self, devices, now):

        for d in devices or []:
            did = d.get("device_id")
            if not did:
                continue

            if did not in self.device_memory:
                if len(self.device_memory) >= self.MAX_DEVICES:
                    return  # cap growth

                self.device_memory[did] = {
                    "first_seen": now,
                    "last_seen": now,
                    "observations": 0,
                    "protocols": defaultdict(int),
                    "frequencies": defaultdict(int),
                }

            entry = self.device_memory[did]
            entry["observations"] += 1
            entry["last_seen"] = now

            for p in d.get("protocols", []) or []:
                entry["protocols"][p] += 1

            for f in d.get("frequencies", []) or []:
                try:
                    entry["frequencies"][round(float(f))] += 1
                except Exception:
                    continue

    # ------------------------------------------------------------------
    # PROTOCOL LEARNING
    # ------------------------------------------------------------------

    def _learn_protocols(self, devices):
        for d in devices or []:
            for p in d.get("protocols", []) or []:
                self.protocol_memory[p] += 1

    # ------------------------------------------------------------------
    # RELATIONSHIP LEARNING
    # ------------------------------------------------------------------

    def _learn_relationships(self, edges):
        for e in edges or []:
            a = e.get("device_a")
            b = e.get("device_b")
            if not a or not b:
                continue
            self.cooccurrence_matrix[a][b] += 1
            self.cooccurrence_matrix[b][a] += 1

    # ------------------------------------------------------------------
    # ENVIRONMENT LEARNING
    # ------------------------------------------------------------------

    def _learn_environment(self, ecosystem):
        env = (ecosystem or {}).get("environment_type")
        if env:
            self.environment_profiles[env] += 1

    # ------------------------------------------------------------------
    # CONFIDENCE ADJUSTMENT
    # ------------------------------------------------------------------

    def adjust_confidence(self, device_id: str, base_confidence: float) -> float:

        memory = self.device_memory.get(device_id)
        if not memory:
            return base_confidence

        observations = memory.get("observations", 0)
        last_seen = memory.get("last_seen", time.time())

        boost = min(self.MAX_CONFIDENCE_BOOST, observations * 0.01)

        age = max(0.0, time.time() - last_seen)
        decay = (self.DECAY_FACTOR ** age)

        adjusted = (base_confidence + boost) * decay
        return round(min(1.0, adjusted), 4)

    # ------------------------------------------------------------------
    # ANOMALY DETECTION
    # ------------------------------------------------------------------

    def detect_anomaly(self, device: Dict[str, Any]) -> Dict[str, Any]:

        protocols = device.get("protocols", []) or []

        rare_protocols = [p for p in protocols if self.protocol_memory[p] < 3]
        unusual_combo = len(protocols) > 2

        if rare_protocols or unusual_combo:
            return {
                "is_anomaly": True,
                "rare_protocols": rare_protocols,
                "unusual_combination": unusual_combo,
            }

        return {"is_anomaly": False}

    # ------------------------------------------------------------------
    # INTELLIGENCE PROFILE
    # ------------------------------------------------------------------

    def get_device_profile(self, device_id: str) -> Dict[str, Any]:

        memory = self.device_memory.get(device_id)
        if not memory:
            return {}

        return {
            "observations": memory.get("observations", 0),
            "dominant_protocol": self._max_key(memory.get("protocols", {})),
            "dominant_frequency": self._max_key(memory.get("frequencies", {})),
        }

    # ------------------------------------------------------------------
    # UTILS
    # ------------------------------------------------------------------

    def _max_key(self, d):
        if not d:
            return None
        return max(d.items(), key=lambda x: x[1])[0]
