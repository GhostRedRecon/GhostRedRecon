# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/models/modelintel.py
# VERSION:      v29.0.0 (REGION-AGNOSTIC + STRUCTURE-CONSISTENT)
# LAST UPDATED: 2026-03-03
#
# =============================================================================
# RESPONSIBILITY
# -----------------------------------------------------------------------------
# ✔ Deterministic intelligence scoring
# ✔ Region-agnostic logic
# ✔ Replay-aware but non-duplicative
# ✔ Injection realism (HackRF constraints)
# ✔ Infrastructure leverage modeling
# ✔ Non-saturating scoring
# =============================================================================


# =============================================================================
# STABILITY MODEL
# =============================================================================

class StabilityModel:

    def score(self, event_count: int) -> float:

        try:
            ec = int(event_count or 0)
        except Exception:
            ec = 0

        if ec <= 0:
            return 0.0

        if ec < 5:
            return round(ec * 0.08, 3)

        if ec < 20:
            return round(0.4 + (ec - 5) * 0.03, 3)

        if ec < 40:
            return round(0.85 + (ec - 20) * 0.005, 3)

        return 0.95


# =============================================================================
# PERSISTENCE MODEL (SIMPLE & ROBUST)
# =============================================================================

class PersistenceModel:

    def evaluate(self, record):

        stability = float(record.get("stability_score", 0))
        hit_count = float(record.get("event_count", 0))

        if hit_count < 2:
            return 0.0

        return round(min((stability * 0.7) + (hit_count * 0.01), 1.0), 3)


# =============================================================================
# INFRASTRUCTURE CONFIDENCE MODEL (REGION AGNOSTIC)
# =============================================================================

class InfrastructureConfidenceModel:

    def evaluate(self, record):

        stability = float(record.get("stability_score", 0))
        persistence = float(record.get("persistence_confidence", 0))
        role = record.get("frame_role", "")
        infra_prob = float(record.get("infrastructure_probability", 0))
        mesh_score = float(record.get("mesh_participation_score", 0))

        score = 0.0

        if role in ["WIFI_INFRASTRUCTURE", "ZIGBEE_COORDINATOR"]:
            score += 0.5

        score += infra_prob * 0.4
        score += mesh_score * 0.3
        score += stability * 0.2
        score += persistence * 0.3

        return round(min(score, 1.0), 3)


# =============================================================================
# EXPLOITABILITY MODEL (CLEANED + REALISTIC)
# =============================================================================

class ExploitabilityModel:

    def evaluate(self, record):

        replay_score = float(record.get("replay_feasibility_score", 0))
        injection_score = self._injection_feasibility(record)
        leverage_score = self._infrastructure_leverage(record)
        weakness_score = self._protocol_weakness(record)

        final = (
            replay_score * 0.4 +
            injection_score * 0.25 +
            leverage_score * 0.2 +
            weakness_score * 0.15
        )

        return round(min(final, 1.0), 3)

    # -------------------------------------------------------------------------
    # Injection feasibility
    # -------------------------------------------------------------------------

    def _injection_feasibility(self, record):

        width = float(record.get("rf_width_mhz", 0))
        protocol = record.get("protocol_signature", "")
        role = record.get("frame_role", "")

        score = 0.0

        # HackRF practical injection limit
        if width <= 20:
            score += 0.2

        if protocol in ["SUBGHZ_FSK_OOK", "UNKNOWN_PROTOCOL"]:
            score += 0.3

        if role in ["ZIGBEE_COORDINATOR", "WIFI_BEACON"]:
            score += 0.3

        return min(score, 1.0)

    # -------------------------------------------------------------------------
    # Infrastructure leverage
    # -------------------------------------------------------------------------

    def _infrastructure_leverage(self, record):

        infra_prob = float(record.get("infrastructure_probability", 0))
        persistence = float(record.get("persistence_confidence", 0))

        return min((infra_prob * 0.6) + (persistence * 0.4), 1.0)

    # -------------------------------------------------------------------------
    # Protocol weakness
    # -------------------------------------------------------------------------

    def _protocol_weakness(self, record):

        protocol = record.get("protocol_signature", "")
        entropy = float(record.get("payload_entropy_score", 0))
        rolling = record.get("rolling_counter_detected", False)

        score = 0.0

        if protocol in ["SUBGHZ_FSK_OOK", "UNKNOWN_PROTOCOL"]:
            score += 0.5

        if entropy < 0.4:
            score += 0.2

        if not rolling:
            score += 0.2

        return min(score, 1.0)
