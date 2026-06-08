# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF CHANNEL AGGREGATOR
# FILE:         backend/recon/utils/channel_aggregator.py
#
# VERSION:      v2.0.0 (WIDEBAND EMITTER CONSOLIDATION ENGINE)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# PeakDetector
#     ↓
# EmitterClusterEngine
#     ↓
# RFChannelAggregator  ← THIS MODULE
#     ↓
# RFSignalRefiner
#     ↓
# FeatureExtractor
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. SPECTRAL COHERENCE
# Emitters that are spectrally close likely belong to the same transmission.
#
# 2. WIDEBAND CONSOLIDATION
# Wideband protocols (WiFi, BLE, Zigbee) produce fragmented peaks.
#
# 3. DETERMINISTIC GROUPING
# Same input must produce identical grouping results.
#
# 4. LOW CPU COST
# Must run on every FFT cycle.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • merging fragmented emitters
# • estimating center frequency
# • estimating channel bandwidth
#
# This module is NOT responsible for:
#
# • protocol detection
# • device inference
#
# =============================================================================

from statistics import mean


class RFChannelAggregator:

    VERSION = "2.0.0"

    MERGE_DISTANCE_MHZ = 12.0
    MIN_EMITTERS = 3

    # -------------------------------------------------------------------------

    def aggregate(self, emitters):

        if not emitters:
            return []

        valid_emitters = [
            e for e in emitters
            if isinstance(e, dict)
            and "freq_mhz" in e
            and "power_db" in e
        ]

        if not valid_emitters:
            return []

        valid_emitters.sort(key=lambda e: e["freq_mhz"])

        groups = []
        current_group = [valid_emitters[0]]

        for emitter in valid_emitters[1:]:

            group_center = mean(e["freq_mhz"] for e in current_group)

            if abs(emitter["freq_mhz"] - group_center) <= self.MERGE_DISTANCE_MHZ:

                current_group.append(emitter)

            else:

                groups.append(current_group)
                current_group = [emitter]

        groups.append(current_group)

        aggregated = []

        for group in groups:

            if len(group) < self.MIN_EMITTERS:

                aggregated.extend(group)
                continue

            aggregated.append(self._merge_group(group))

        return aggregated

    # -------------------------------------------------------------------------

    def _merge_group(self, group):

        freqs = [e["freq_mhz"] for e in group]
        powers = [e["power_db"] for e in group]

        weighted_center = sum(
            f * (10 ** (p / 10)) for f, p in zip(freqs, powers)
        ) / sum(10 ** (p / 10) for p in powers)

        bandwidth = max(freqs) - min(freqs)

        return {

            "freq_mhz": round(weighted_center, 3),

            "power_db": max(powers),

            "bandwidth_mhz": round(bandwidth, 3),

            "rf_fragment_count": len(group),

            "rf_fragmented": True,

        }
