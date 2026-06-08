# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/models/signal_state.py
# VERSION:      v8.0.0 (ENTERPRISE LIFECYCLE STATES)
# LAST UPDATED: 2026-02-24
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
# Defines canonical lifecycle states for SignalRecord.
#
# PURPOSE:
#   ✔ Prevent string-based magic states
#   ✔ Enforce deterministic lifecycle transitions
#   ✔ Standardize emitter maturity levels
#
# STATES:
#   NEW       → First observation
#   OBSERVED  → Seen multiple times but unstable
#   STABLE    → Stability threshold reached
#   PROMOTED  → Considered operational emitter
#   STALE     → Not seen recently
#   ARCHIVED  → Session-ended memory tier
# =============================================================================

from enum import Enum


class SignalState(str, Enum):
    NEW = "NEW"
    OBSERVED = "OBSERVED"
    STABLE = "STABLE"
    PROMOTED = "PROMOTED"
    STALE = "STALE"
    ARCHIVED = "ARCHIVED"
