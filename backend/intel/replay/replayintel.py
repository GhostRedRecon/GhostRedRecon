# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/replay/replayintel.py
# VERSION:      v32.0.0 (HIGH-FIDELITY + INTERVAL-AWARE + ROBUST HASHING)
# LAST UPDATED: 2026-03-03
#
# =============================================================================
# ARCHITECTURE
# -----------------------------------------------------------------------------
# SignalEngine (read path)
#     ↓
# ReplayIntel (Single Replay Authority)
#
# =============================================================================
# RESPONSIBILITY
# -----------------------------------------------------------------------------
# ✔ Envelope hashing
# ✔ Entropy modeling (32-bin)
# ✔ Sliding similarity reference
# ✔ Rolling counter detection
# ✔ Replay window estimation
# ✔ Memory bounded per signal
# ✔ HackRF 20 MHz compatible
#
# =============================================================================
# DESIGN PRINCIPLES
# -----------------------------------------------------------------------------
# ✔ Deterministic
# ✔ No exploit generation
# ✔ Per-signal isolation
# ✔ Memory bounded
# ✔ CPU-aware
# =============================================================================

import numpy as np
import hashlib
import time
from typing import Dict, Any


class ReplayIntel:

    def __init__(self, max_history: int = 80):
        self._history = {}
        self._max_history = max_history

    # =========================================================================
    # ENTRY
    # =========================================================================

    def process(self, signal_id: str, record: Dict[str, Any]) -> Dict[str, Any]:

        rf = record.get("rf_features", {})
        iq = rf.get("iq_samples") or record.get("iq_samples")

        if iq is None or len(iq) < 64:
            return {}

        iq = np.array(iq, dtype=np.complex64)
        amplitude = np.abs(iq)

        # Normalize energy envelope
        amplitude = amplitude / (np.max(amplitude) + 1e-9)

        entropy = self._entropy(amplitude)
        sig_hash = self._hash(amplitude)

        history = self._history.setdefault(signal_id, [])

        history.append({
            "hash": sig_hash,
            "entropy": entropy,
            "ts": time.time()
        })

        if len(history) > self._max_history:
            history.pop(0)

        similarity = self._similarity(history)
        entropy_var = self._entropy_variance(history)
        rolling = self._rolling_detect(history)

        replay_window = self._estimate_window(record)
        replay_score = self._score(similarity, entropy_var, rolling)

        return {
            "payload_entropy_score": round(entropy, 3),
            "replay_similarity_score": round(similarity, 3),
            "replay_entropy_variance": round(entropy_var, 6),
            "rolling_counter_detected": rolling,
            "replay_window_estimate_ms": replay_window,
            "replay_feasibility_score": round(replay_score, 3),
        }

    # =========================================================================
    # INTERNALS
    # =========================================================================

    def _entropy(self, data):
        hist, _ = np.histogram(data, bins=32, range=(0, 1), density=True)
        hist += 1e-9
        return float(-np.sum(hist * np.log2(hist)) / np.log2(len(hist)))

    def _hash(self, data):
        bins = np.digitize(data, bins=np.linspace(0, 1, 32))
        return hashlib.sha256(bytes(bins[:128])).hexdigest()[:16]

    def _similarity(self, history):

        if len(history) < 2:
            return 0.0

        reference = history[-1]["hash"]
        matches = sum(1 for h in history if h["hash"] == reference)

        return matches / len(history)

    def _entropy_variance(self, history):

        if len(history) < 2:
            return 0.0

        values = [h["entropy"] for h in history]
        return float(np.var(values))

    def _rolling_detect(self, history):

        if len(history) < 6:
            return False

        ent = [h["entropy"] for h in history]
        diffs = np.diff(ent)

        positive = sum(d > 0 for d in diffs)
        negative = sum(d < 0 for d in diffs)

        if positive >= len(diffs) * 0.75:
            return True

        if negative >= len(diffs) * 0.75:
            return True

        return False

    def _estimate_window(self, record):

        interval = float(record.get("frame_interval_ms", 0))

        if interval > 0:
            return min(interval * 0.6, 3000)

        return None

    def _score(self, similarity, entropy_var, rolling):

        score = 0.0

        if similarity > 0.85:
            score += 0.5

        if entropy_var < 0.005:
            score += 0.3

        if not rolling:
            score += 0.2

        return min(score, 1.0)
