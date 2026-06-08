# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/graph/graphintel.py
# VERSION:      v21.0.0 (PROTOCOL-AWARE + DENSITY-SCORING + CLEANUP-THROTTLED)
# LAST UPDATED: 2026-03-03
#
# =============================================================================
# ARCHITECTURE
# -----------------------------------------------------------------------------
# SignalEngine (read path)
#     ↓
# RFGraphIntel (Cluster + Density + Mesh Intelligence)
#
# =============================================================================
# RESPONSIBILITY
# -----------------------------------------------------------------------------
# ✔ Active signal tracking
# ✔ TTL-based cleanup (throttled)
# ✔ Frequency clustering (O(n log n))
# ✔ Protocol-aware grouping
# ✔ Mesh participation scoring
# ✔ Density scoring
# ✔ Cluster maturity modeling
#
# =============================================================================
# DESIGN PRINCIPLES
# -----------------------------------------------------------------------------
# ✔ Memory bounded
# ✔ Deterministic
# ✔ No DSP
# ✔ No identity logic
# ✔ No file I/O
# ✔ Scales to 500+ signals
# ✔ HackRF wideband safe
# =============================================================================

import time
from typing import Dict, Any, List
from collections import defaultdict


class RFGraphIntel:

    def __init__(self, ttl_seconds: float = 30.0):
        self._signals: Dict[str, Dict[str, Any]] = {}
        self._ttl = ttl_seconds
        self._last_cleanup = 0.0

    # =========================================================================
    # UPDATE NODE
    # =========================================================================

    def update(self, signal_id: str, record: Dict[str, Any]):

        now = time.time()

        self._signals[signal_id] = {
            "freq_mhz": float(record.get("freq_mhz", 0)),
            "protocol": record.get("protocol_signature"),
            "band": record.get("band"),
            "last_seen": now,
        }

        # Throttled cleanup (max once per second)
        if now - self._last_cleanup > 1.0:
            self._cleanup()
            self._last_cleanup = now

    # =========================================================================
    # CLEANUP
    # =========================================================================

    def _cleanup(self):

        now = time.time()

        stale = [
            sid for sid, node in self._signals.items()
            if (now - node["last_seen"]) > self._ttl
        ]

        for sid in stale:
            del self._signals[sid]

    # =========================================================================
    # ANALYSIS
    # =========================================================================

    def analyze(self, threshold_mhz: float = 0.5):

        if not self._signals:
            return {}

        nodes = sorted(
            self._signals.items(),
            key=lambda x: x[1]["freq_mhz"]
        )

        clusters: List[List[str]] = []
        current_cluster = [nodes[0][0]]

        for i in range(1, len(nodes)):
            prev_freq = nodes[i - 1][1]["freq_mhz"]
            curr_id, curr_node = nodes[i]

            if abs(curr_node["freq_mhz"] - prev_freq) <= threshold_mhz:
                current_cluster.append(curr_id)
            else:
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)
                current_cluster = [curr_id]

        if len(current_cluster) > 1:
            clusters.append(current_cluster)

        # Cluster metadata
        cluster_info = []
        mesh_scores = {}
        density_score = min(len(self._signals) / 100.0, 1.0)

        for cluster in clusters:

            protocols = defaultdict(int)

            for sid in cluster:
                proto = self._signals[sid].get("protocol")
                if proto:
                    protocols[proto] += 1

            dominant_protocol = max(protocols, key=protocols.get)

            cluster_size = len(cluster)
            maturity = min(cluster_size / 8.0, 1.0)

            for sid in cluster:
                mesh_scores[sid] = maturity

            cluster_info.append({
                "size": cluster_size,
                "dominant_protocol": dominant_protocol,
                "maturity_score": round(maturity, 3),
            })

        return {
            "active_signal_count": len(self._signals),
            "cluster_count": len(clusters),
            "clusters": clusters,
            "cluster_metadata": cluster_info,
            "mesh_scores": mesh_scores,
            "rf_density_score": round(density_score, 3),
        }
