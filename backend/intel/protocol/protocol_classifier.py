# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/protocol/protocol_classifier.py
#
# VERSION:      v8.0.0 (SIGINT TUNED - BALANCED DETECTION ENGINE)
# UPDATED:      2026-03-23
# =============================================================================

import logging

log = logging.getLogger("ghostrecon.protocol")


class ProtocolClassifier:

    VERSION = "8.2.0"

    # -------------------------------------------------------------------------
    # TUNED THRESHOLDS (BASED ON YOUR FFT REALITY)
    # -------------------------------------------------------------------------
    WIFI_MIN_BW = 5.0        # relaxed from 10 → FIXED WIFI LOSS
    BLE_MAX_BW = 3.0         # relaxed for noisy estimates
    ZIGBEE_MAX_BW = 2.5

    ZIGBEE_CHANNELS = [
        2405, 2410, 2415, 2420, 2425, 2430, 2435, 2440,
        2445, 2450, 2455, 2460, 2465, 2470, 2475, 2480
    ]
    BLE_ADV_CHANNELS = [2402.0, 2426.0, 2480.0]
    SUBGHZ_LORA_HINTS = [
        433.175, 433.375, 433.775, 433.92,
        867.1, 867.3, 867.5, 867.7, 867.9,
        868.1, 868.3, 868.5, 869.525,
        903.9, 904.1, 904.3, 904.5, 904.7, 904.9, 905.1, 905.3,
        923.3,
    ]
    WMBUS_HINTS = [868.30, 868.95, 869.525]

    def __init__(self):
        log.info(f"[ProtocolClassifier] Initialized v{self.VERSION}")

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def classify(self, features: dict) -> dict:

        try:
            # ---------------------------------------------------------
            # SAFE EXTRACTION
            # ---------------------------------------------------------
            band = features.get("band") or features.get("rf_band")
            freq = features.get("frequency_mhz") or 0
            bandwidth = features.get("bandwidth_estimate_mhz") or 0
            bandwidth_class = str(features.get("bandwidth_class") or "").lower()
            channel_family = str(features.get("channel_family") or "").lower()
            wifi_channel = features.get("wifi_channel")
            zigbee_channel = features.get("zigbee_channel")
            ble_channel = features.get("ble_channel")

            peak_density = features.get("peak_density") or 0
            signal_density = features.get("signal_density") or 0
            stability = features.get("signal_stability") or 0

            freq_variance = features.get("freq_variance") or 0
            temporal_consistency = features.get("temporal_consistency") or 0
            burst_ratio = features.get("burst_ratio") or 0
            duty_cycle = self._as_float(features.get("rf_duty_cycle"), burst_ratio, default=0.0)
            burst_periodicity = self._as_float(features.get("rf_burst_periodicity"), features.get("periodicity"))
            ble_adv_distance = self._as_float(
                features.get("rf_ble_adv_distance_mhz"),
                self._nearest_distance(freq, self.BLE_ADV_CHANNELS),
            )
            channel_confidence = self._as_float(features.get("channel_confidence"), default=0.0)
            signal_class = str(features.get("rf_signal_class") or features.get("signal_class") or "").lower()
            signal_type = str(features.get("signal_type") or "").lower()
            subghz_profile = str(features.get("rf_subghz_profile") or features.get("subghz_profile") or "").lower()
            exact_ble_adv = ble_channel in {37, 38, 39} and ble_adv_distance is not None and ble_adv_distance <= 0.35
            near_ble_adv = ble_adv_distance is not None and ble_adv_distance <= 0.9
            off_ble_adv = ble_adv_distance is not None and ble_adv_distance > 1.6
            zigbee_distance = self._nearest_distance(freq, self.ZIGBEE_CHANNELS)
            exact_zigbee = zigbee_channel is not None and zigbee_distance is not None and zigbee_distance <= 0.35
            near_zigbee = zigbee_distance is not None and zigbee_distance <= 0.8
            off_zigbee = zigbee_distance is not None and zigbee_distance > 1.5
            lora_distance = self._nearest_distance(freq, self.SUBGHZ_LORA_HINTS)
            exact_lora_center = lora_distance is not None and lora_distance <= 0.18
            near_lora_center = lora_distance is not None and lora_distance <= 0.55
            wmbus_distance = self._nearest_distance(freq, self.WMBUS_HINTS)
            exact_wmbus_center = wmbus_distance is not None and wmbus_distance <= 0.12
            near_wmbus_center = wmbus_distance is not None and wmbus_distance <= 0.35
            continuous_subghz = signal_class == "continuous" or signal_type == "continuous"
            periodic_subghz = signal_type in {"periodic", "burst"} or (burst_periodicity is not None and burst_periodicity >= 0.12)
            high_duty_subghz = duty_cycle >= 0.55 or signal_density >= 10
            dense_subghz = peak_density >= 20
            sparse_subghz = 0 <= peak_density <= 12

            if band == "2.4GHz":
                if exact_ble_adv:
                    return self._result("BLE", 0.9)
                if (channel_family == "ble" or ble_channel is not None) and near_ble_adv:
                    return self._result("BLE", 0.84 if ble_channel is not None else 0.76)
                if exact_zigbee:
                    return self._result("ZIGBEE", 0.86)
                if channel_family == "zigbee" or zigbee_channel is not None:
                    return self._result("ZIGBEE", 0.78 if zigbee_channel is not None else 0.68)
                if channel_family == "wifi" and bandwidth_class in {"medium", "wide"}:
                    return self._result("WIFI", 0.72)

            # ---------------------------------------------------------
            # 🎯 POSSIBILITY LAYERS (SOFT CONSTRAINTS)
            # ---------------------------------------------------------
            wifi_possible = (
                bandwidth >= self.WIFI_MIN_BW
                or bandwidth_class == "wide"
            )

            ble_possible = (
                ble_channel is not None
                or near_ble_adv
                or (
                    bandwidth <= self.BLE_MAX_BW
                    and (
                        freq_variance > 3
                        or peak_density > 15
                        or channel_family == "ble"
                        or signal_class in {"bursty", "packet_radio", "narrowband"}
                    )
                )
            )

            zigbee_possible = (
                zigbee_channel is not None
                or near_zigbee
            )

            lora_possible = (band == "SUB_GHZ")

            # ---------------------------------------------------------
            # SCORE SYSTEM (CORE ENGINE)
            # ---------------------------------------------------------
            scores = {
                "WIFI": 0.0,
                "BLE": 0.0,
                "ZIGBEE": 0.0,
                "LORA": 0.0,
                "SUBGHZ_FSK": 0.0,
                "WIRELESS_MBUS": 0.0,
            }

            # =========================================================
            # 📡 WIFI (RECOVERED + STRONG)
            # =========================================================
            if band in ("2.4GHz", "5GHz"):

                if wifi_possible:
                    scores["WIFI"] += 0.5

                if bandwidth_class == "wide":
                    scores["WIFI"] += 0.3

                if channel_family == "wifi" or wifi_channel is not None:
                    scores["WIFI"] += 0.25

                if stability > 0.4:
                    scores["WIFI"] += 0.2

                if temporal_consistency > 0.5:
                    scores["WIFI"] += 0.2

                if freq_variance < 3:
                    scores["WIFI"] += 0.1

            # =========================================================
            # 📶 BLE (FIXED DETECTION)
            # =========================================================
            if band == "2.4GHz":

                if ble_possible:
                    scores["BLE"] += 0.5

                if channel_family == "ble" or ble_channel is not None:
                    scores["BLE"] += 0.35

                if exact_ble_adv:
                    scores["BLE"] += 0.35
                elif near_ble_adv:
                    scores["BLE"] += 0.2

                if freq_variance > 5:
                    scores["BLE"] += 0.3

                if peak_density > 20:
                    scores["BLE"] += 0.2

                if stability < 0.6:
                    scores["BLE"] += 0.1

                if 0.01 <= duty_cycle <= 0.25:
                    scores["BLE"] += 0.12

                if burst_periodicity is not None and 0.02 <= burst_periodicity <= 2.0:
                    scores["BLE"] += 0.12

                if signal_class in {"bursty", "packet_radio", "narrowband"}:
                    scores["BLE"] += 0.1

                if channel_confidence >= 0.8 and near_ble_adv:
                    scores["BLE"] += 0.08

                if off_ble_adv and ble_channel is None:
                    scores["BLE"] -= 0.28

                if bandwidth > 2.4 and ble_channel is None:
                    scores["BLE"] -= 0.18

                if channel_family == "wifi" and bandwidth_class in {"medium", "wide"}:
                    scores["BLE"] -= 0.45

                if channel_family == "zigbee" and zigbee_channel is not None and ble_channel is None:
                    scores["BLE"] -= 0.25

            # =========================================================
            # 📡 ZIGBEE (CONTROLLED)
            # =========================================================
            if band == "2.4GHz" and zigbee_possible:

                if bandwidth <= self.ZIGBEE_MAX_BW:
                    scores["ZIGBEE"] += 0.5

                if channel_family == "zigbee" or zigbee_channel is not None:
                    scores["ZIGBEE"] += 0.35

                if exact_zigbee:
                    scores["ZIGBEE"] += 0.28
                elif near_zigbee:
                    scores["ZIGBEE"] += 0.14

                if stability > 0.5:
                    scores["ZIGBEE"] += 0.2

                if peak_density < 15:
                    scores["ZIGBEE"] += 0.2

                if 0.8 <= bandwidth <= 2.4:
                    scores["ZIGBEE"] += 0.12

                if signal_class in {"bursty", "packet_radio", "narrowband"}:
                    scores["ZIGBEE"] += 0.08

                if channel_confidence >= 0.75 and near_zigbee:
                    scores["ZIGBEE"] += 0.08

                if off_zigbee and zigbee_channel is None:
                    scores["ZIGBEE"] -= 0.22

                if near_ble_adv and zigbee_channel is None:
                    scores["ZIGBEE"] -= 0.18

                if channel_family == "ble" and ble_channel is not None and zigbee_channel is None:
                    scores["ZIGBEE"] -= 0.30

            # =========================================================
            # 📡 LORA (STRICTLY CONTROLLED)
            # =========================================================
            if lora_possible:

                if bandwidth_class == "narrow":
                    scores["LORA"] += 0.25

                if stability > 0.7:
                    scores["LORA"] += 0.12

                if sparse_subghz:
                    scores["LORA"] += 0.12

                if exact_lora_center:
                    scores["LORA"] += 0.22
                elif near_lora_center:
                    scores["LORA"] += 0.10

                if "lora" in subghz_profile:
                    scores["LORA"] += 0.20
                if any(token in subghz_profile for token in {"eu868", "us915", "ism433", "eu433", "lorawan"}):
                    scores["LORA"] += 0.10

                if periodic_subghz:
                    scores["LORA"] += 0.18

                if 0.01 <= duty_cycle <= 0.35:
                    scores["LORA"] += 0.08

                if signal_type == "burst":
                    scores["LORA"] += 0.06

                if continuous_subghz and burst_periodicity in {None, 0.0}:
                    scores["LORA"] -= 0.18

                if high_duty_subghz:
                    scores["LORA"] -= 0.16

                if dense_subghz:
                    scores["LORA"] -= 0.14

                if "generic_subghz" in subghz_profile:
                    scores["LORA"] -= 0.12

            # HARD BLOCK: LORA in 2.4GHz
            if band == "2.4GHz":
                scores["LORA"] = -999

            # =========================================================
            # 📡 SUBGHZ FSK
            # =========================================================
            if band == "SUB_GHZ":

                if exact_wmbus_center:
                    scores["WIRELESS_MBUS"] += 0.34
                elif near_wmbus_center:
                    scores["WIRELESS_MBUS"] += 0.18

                if bandwidth_class in {"narrow", "medium"}:
                    scores["WIRELESS_MBUS"] += 0.16

                if periodic_subghz:
                    scores["WIRELESS_MBUS"] += 0.18

                if 0.01 <= duty_cycle <= 0.30:
                    scores["WIRELESS_MBUS"] += 0.12

                if any(token in subghz_profile for token in {"meter", "utility", "wireless_mbus", "wmbus"}):
                    scores["WIRELESS_MBUS"] += 0.20

                if exact_lora_center and not exact_wmbus_center:
                    scores["WIRELESS_MBUS"] -= 0.14

                if high_duty_subghz:
                    scores["WIRELESS_MBUS"] -= 0.08

                if bandwidth_class == "medium":
                    scores["SUBGHZ_FSK"] += 0.4
                elif bandwidth_class == "narrow":
                    scores["SUBGHZ_FSK"] += 0.10

                if signal_density > 5:
                    scores["SUBGHZ_FSK"] += 0.3

                if stability > 0.3:
                    scores["SUBGHZ_FSK"] += 0.2

                if peak_density < 10:
                    scores["SUBGHZ_FSK"] += 0.1

                if continuous_subghz:
                    scores["SUBGHZ_FSK"] += 0.22

                if high_duty_subghz:
                    scores["SUBGHZ_FSK"] += 0.16

                if dense_subghz:
                    scores["SUBGHZ_FSK"] += 0.12

                if "generic_subghz" in subghz_profile:
                    scores["SUBGHZ_FSK"] += 0.12

                if periodic_subghz and not high_duty_subghz:
                    scores["SUBGHZ_FSK"] -= 0.08

            # ---------------------------------------------------------
            # NORMALIZATION
            # ---------------------------------------------------------
            positive_scores = {k: max(v, 0) for k, v in scores.items()}
            total = sum(positive_scores.values())

            if total <= 0:
                return self._unknown()

            normalized = {k: v / total for k, v in positive_scores.items()}
            best_protocol = max(normalized, key=normalized.get)
            best_score = normalized[best_protocol]

            # ---------------------------------------------------------
            # CONFIDENCE MODEL (TUNED)
            # ---------------------------------------------------------
            confidence = (
                best_score * 0.5 +
                stability * 0.2 +
                temporal_consistency * 0.2 +
                min(1.0, peak_density / 50) * 0.1
            )

            confidence = max(0.0, min(confidence, 1.0))

            # ---------------------------------------------------------
            # RECOVERY LAYER (KEY FEATURE)
            # Prevent over-UNKNOWN collapse
            # ---------------------------------------------------------
            if confidence < 0.35:

                # try fallback heuristics
                if band == "2.4GHz" and bandwidth > 6:
                    best_protocol = "WIFI"
                    confidence = 0.4

                elif band == "2.4GHz" and freq_variance > 6:
                    best_protocol = "BLE"
                    confidence = 0.4

                else:
                    return self._unknown()

            # ---------------------------------------------------------
            # RF MAP
            # ---------------------------------------------------------
            rf_map = {
                "WIFI": "IEEE_802.11",
                "BLE": "BLUETOOTH_LE",
                "ZIGBEE": "IEEE_802.15.4",
                "LORA": "LORA_PHY",
                "SUBGHZ_FSK": "FSK",
                "WIRELESS_MBUS": "WIRELESS_MBUS",
            }

            return {
                "protocol": best_protocol,
                "rf_protocol": rf_map.get(best_protocol),
                "protocol_confidence": round(confidence, 4),
                "rf_protocol_confidence": round(confidence * 0.95, 4),
            }

        except Exception as e:
            log.error(f"[ProtocolClassifier] Error: {e}")
            return self._unknown()

    @staticmethod
    def _as_float(*values, default=0.0):
        for value in values:
            try:
                if value is None:
                    continue
                return float(value)
            except Exception:
                continue
        return default

    @staticmethod
    def _nearest_distance(freq, centers):
        try:
            freq = float(freq)
        except Exception:
            return None
        if not centers:
            return None
        return min(abs(freq - center) for center in centers)

    # =========================================================================
    # FALLBACK
    # =========================================================================
    def _unknown(self):
        return {
            "protocol": "UNKNOWN_PROTOCOL",
            "rf_protocol": None,
            "protocol_confidence": 0.0,
            "rf_protocol_confidence": 0.0,
        }

    def _result(self, protocol: str, confidence: float) -> dict:
        rf_map = {
            "WIFI": "IEEE_802.11",
            "BLE": "BLUETOOTH_LE",
            "ZIGBEE": "IEEE_802.15.4",
            "LORA": "LORA_PHY",
            "SUBGHZ_FSK": "FSK",
            "WIRELESS_MBUS": "WIRELESS_MBUS",
        }
        return {
            "protocol": protocol,
            "rf_protocol": rf_map.get(protocol),
            "protocol_confidence": round(confidence, 4),
            "rf_protocol_confidence": round(confidence * 0.95, 4),
        }
