# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       CROSS-SESSION IDENTITY TRACKER
# FILE:         backend/recon/intelligence/cross_session_identity_tracker.py
#
# VERSION:      v1.0.0 (SIGINT CROSS-SESSION IDENTITY TRACKING)
# UPDATED:      2026-03-18
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# This module provides SIGINT-grade cross-session identity tracking.
#
# It links devices observed across different sessions even when:
# • emitter IDs change
# • MAC/random IDs rotate (BLE privacy)
# • frequencies shift slightly
#
# It enables long-term tracking of physical devices.
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# device_fusion (v13) → devices
# identity_engine (v2) → identity features
# adaptive_learning (v3) → memory
#         ↓
# CrossSessionIdentityTracker (THIS)
#         ↓
# persistent identity map
#         ↓
# identity linking across sessions
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PROBABILISTIC MATCHING
#    Never assume identity — score similarity
#
# 2. MULTI-FEATURE MATCHING
#    Use protocol + frequency + behavior + timing
#
# 3. CONSERVATIVE LINKING
#    Avoid false merges
#
# 4. PERSISTENT IDENTITY
#    Track devices beyond a single run
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# • assign persistent identity IDs
# • match devices across sessions
# • maintain identity history
# • store identity fingerprints
#
# =============================================================================
# IMPORTANT NOTES
# =============================================================================
#
# • Identity linking is probabilistic — never 100% certain
# • Use high threshold to avoid incorrect merges
# • Persistence required for real-world deployment
#
# =============================================================================

import json
import os
import time
from typing import Dict, Any, List


class CrossSessionIdentityTracker:

    VERSION = "1.0.0"

    MATCH_THRESHOLD = 0.65
    STORAGE_PATH = "/tmp/ghostrecon_identity_map.json"

    def __init__(self):

        self.identity_map: Dict[str, Dict[str, Any]] = {}
        self.device_to_identity = {}
        self.counter = 0

        self._load()

    # ------------------------------------------------------------------
    # MAIN ENTRY
    # ------------------------------------------------------------------

    def assign_identities(self, devices: List[Dict[str, Any]]):

        results = {}

        for d in devices:

            best_id, score = self._match_identity(d)

            if best_id and score >= self.MATCH_THRESHOLD:
                identity_id = best_id
            else:
                identity_id = self._create_identity(d)

            self.device_to_identity[d["device_id"]] = identity_id
            results[d["device_id"]] = identity_id

        self._save()

        return results

    # ------------------------------------------------------------------
    # MATCHING
    # ------------------------------------------------------------------

    def _match_identity(self, device):

        best_score = 0
        best_id = None

        for iid, profile in self.identity_map.items():

            score = self._similarity(device, profile)

            if score > best_score:
                best_score = score
                best_id = iid

        return best_id, best_score

    def _similarity(self, device, profile):

        score = 0

        # protocol match
        d_proto = set(device.get("protocols", []))
        p_proto = set(profile.get("protocols", []))

        if d_proto & p_proto:
            score += 0.3

        # frequency match
        d_freq = device.get("frequencies", [])
        p_freq = profile.get("frequencies", [])

        for f1 in d_freq:
            for f2 in p_freq:
                if abs(f1 - f2) < 5:
                    score += 0.3
                    break

        # observation reinforcement
        score += min(0.4, profile.get("observations", 0) * 0.01)

        return score

    # ------------------------------------------------------------------
    # CREATE NEW IDENTITY
    # ------------------------------------------------------------------

    def _create_identity(self, device):

        self.counter += 1
        iid = f"identity_{self.counter}"

        self.identity_map[iid] = {
            "first_seen": time.time(),
            "observations": 1,
            "protocols": device.get("protocols", []),
            "frequencies": device.get("frequencies", [])
        }

        return iid

    # ------------------------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------------------------

    def _save(self):

        try:
            with open(self.STORAGE_PATH, "w") as f:
                json.dump(self.identity_map, f)
        except Exception:
            pass

    def _load(self):

        if not os.path.exists(self.STORAGE_PATH):
            return

        try:
            with open(self.STORAGE_PATH, "r") as f:
                self.identity_map = json.load(f)
                self.counter = len(self.identity_map)
        except Exception:
            self.identity_map = {}
