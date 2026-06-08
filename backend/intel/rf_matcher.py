# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/rf_matcher.py
# VERSION:      v1.0.0 (PRODUCTION - YAML RF MATCHING ENGINE)
# UPDATED:      2026-03-24
# =============================================================================

"""
# 🧠 ARCHITECTURE OVERVIEW

Normalized RF
    ↓
RF Matcher (THIS FILE)
    ↓
YAML Intelligence DB
    ↓
Match Result (vendor / product / confidence)

# 🎯 PURPOSE

- Match normalized RF signatures to known device profiles
- Provide vendor / product inference
- Enable Phase 4 intelligence

# 🧩 RESPONSIBILITIES

- Compare normalized RF vs YAML DB
- Apply tolerant frequency matching
- Apply protocol-aware scoring
- Return best match

# ⚙️ DESIGN PRINCIPLES

- TOLERANT MATCHING → handles RF noise/drift
- SCORING-BASED → not binary matching
- SAFE → no crashes on bad data
- EXTENSIBLE → future ML upgrade possible

# 📦 MATCH OUTPUT

{
    "vendor": str,
    "product": str,
    "confidence": float
}

# 📜 CHANGELOG

v1.0.0
- Initial implementation
- Frequency + protocol scoring
- Safe fallback handling
"""

from typing import Dict, Any, List


# =============================================================================
# MAIN MATCHER
# =============================================================================
def match_yaml(normalized_rf: Dict[str, Any], yaml_db: List[Dict[str, Any]]):

    if not normalized_rf or not isinstance(yaml_db, list):
        return None

    center = normalized_rf.get("center_freq")
    protocols = normalized_rf.get("protocols") or []

    if center is None:
        return None

    best_match = None
    best_score = 0.0

    for entry in yaml_db:

        yaml_freq = entry.get("frequency_mhz")
        yaml_proto = entry.get("protocol")

        if yaml_freq is None or yaml_proto is None:
            continue

        # ---------------------------------------------------------------------
        # FREQUENCY SCORE (tolerant)
        # ---------------------------------------------------------------------
        freq_diff = abs(center - yaml_freq)

        if freq_diff > 3.0:
            continue

        freq_score = max(0.0, 1.0 - (freq_diff / 3.0))

        # ---------------------------------------------------------------------
        # PROTOCOL SCORE
        # ---------------------------------------------------------------------
        proto_score = 1.0 if yaml_proto in protocols else 0.0

        # ---------------------------------------------------------------------
        # FINAL SCORE
        # ---------------------------------------------------------------------
        score = (freq_score * 0.7) + (proto_score * 0.3)

        if score > best_score:
            best_score = score
            best_match = entry

    # -------------------------------------------------------------------------
    # THRESHOLD
    # -------------------------------------------------------------------------
    if best_match and best_score >= 0.5:
        return {
            "vendor": best_match.get("vendor"),
            "product": best_match.get("product"),
            "confidence": round(best_score, 2),
        }

    return None
