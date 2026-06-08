# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF RECON CONFIGURATION
# FILE:         backend/recon/configuration.py
#
# VERSION:      v3.0.0 (PHASE-1 STABLE + BURST FIX + FEATURE SUPPORT)
# UPDATED:      2026-03-14
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# All Recon modules pull configuration values from ReconConfig.
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# PeakDetector
#     ↓
# EmitterCluster
#     ↓
# EmitterTracker
#     ↓
# EmitterLifecycle
#     ↓
# BurstDetector
#     ↓
# FeatureExtractor
#     ↓
# ProtocolClassifier
#     ↓
# SignalEngine
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# ✔ Centralized configuration
# ✔ Tuned for real RF environments
# ✔ Compatible across all recon modules
# ✔ Safe defaults for SDR
# ✔ Profile based environment tuning
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# Responsible for:
#
# • RF detection thresholds
# • burst timing configuration
# • clustering tolerances
# • tracking parameters
# • feature extraction thresholds
#
# Not responsible for:
#
# • SDR control
# • protocol classification logic
#
# =============================================================================


class ReconConfig:

    # -------------------------------------------------------------------------
    # SYSTEM MODE
    # -------------------------------------------------------------------------

    MODE = "LAB"   # LAB / FIELD / HIGH_DENSITY

    # -------------------------------------------------------------------------
    # FFT REQUIREMENTS
    # -------------------------------------------------------------------------

    MIN_FFT_SIZE = 256

    # -------------------------------------------------------------------------
    # PEAK DETECTOR
    # -------------------------------------------------------------------------

    PEAK_BASE_MAX = 64
    PEAK_DENSE_MAX = 200

    PEAK_GROUP_GAP = 8

    DC_SUPPRESSION_BINS = 20

    CFAR_GUARD_CELLS = 6
    CFAR_NOISE_CELLS = 16

    SNR_BASE_THRESHOLD = 3.0

    MIN_SIGNAL_POWER_DB = -110

    MIN_PEAK_SEPARATION_BINS = 3

    MAX_PEAK_DENSITY = 0.35

    # -------------------------------------------------------------------------
    # CLUSTERING
    # -------------------------------------------------------------------------

    MIN_CLUSTER_SIZE = 1

    CLUSTER_FREQ_TOLERANCE_MHZ = 1.5
    CLUSTER_POWER_TOLERANCE_DB = 6

    # -------------------------------------------------------------------------
    # EMITTER TRACKING
    # -------------------------------------------------------------------------

    BASE_FREQ_TOLERANCE_MHZ = 0.6
    MAX_FREQ_TOLERANCE_MHZ = 5.0

    POWER_TOLERANCE_DB = 12
    BANDWIDTH_TOLERANCE_MHZ = 2.0

    MAX_ACTIVE_EMITTERS = 200

    EMITTER_TIMEOUT = 30
    EMITTER_TIMEOUT_SECONDS = 5

    EMITTER_MIN_CONFIDENCE = 0.25

    # -------------------------------------------------------------------------
    # EMITTER SMOOTHING
    # -------------------------------------------------------------------------

    FREQ_SMOOTH = 0.85
    POWER_SMOOTH = 0.75

    CONFIDENCE_DECAY = 0.97

    # -------------------------------------------------------------------------
    # EMITTER PROMOTION
    # -------------------------------------------------------------------------

    EMITTER_PROMOTION_HITS = 3
    PROMOTION_HITS = EMITTER_PROMOTION_HITS

    PERSISTENCE_HIT_LIMIT = 4
    PERSISTENCE_TIME = 1.0

    # -------------------------------------------------------------------------
    # BURST DETECTION
    # -------------------------------------------------------------------------

    POWER_THRESHOLD_DB = -95

    BURST_TIMEOUT = 0.15

    MIN_BURST_FRAMES = 3
    MAX_HISTORY = 50

    MAX_ACTIVE_BURSTS = 200

    BURST_PERIOD_HISTORY = 10

    BURST_MIN_DURATION_MS = 1
    BURST_MAX_DURATION_MS = 10000

    SHORT_BURST_MAX = 0.01
    MEDIUM_BURST_MAX = 0.2
    LONG_BURST_MAX = 1.0

    # -------------------------------------------------------------------------
    # FEATURE EXTRACTION
    # -------------------------------------------------------------------------

    MIN_BURST_OBSERVATIONS = 4

    # spectral thresholds

    SPECTRAL_FLATNESS_OFDM = 0.7
    SPECTRAL_ENTROPY_NOISE = 4.5

    PEAK_DENSITY_OFDM = 0.15

    # -------------------------------------------------------------------------
    # OFDM DETECTION
    # -------------------------------------------------------------------------

    OFDM_FLATNESS_THRESHOLD = 0.7
    OFDM_MIN_BANDWIDTH_HZ = 8_000_000

    # -------------------------------------------------------------------------
    # SPECTRAL CLASSIFICATION
    # -------------------------------------------------------------------------

    WIDEBAND_THRESHOLD_HZ = 1_000_000
    NARROWBAND_THRESHOLD_HZ = 40_000

    # -------------------------------------------------------------------------
    # CHIRP DETECTION
    # -------------------------------------------------------------------------

    CHIRP_SLOPE_THRESHOLD = 0.5

    # -------------------------------------------------------------------------
    # DEVICE BEHAVIOR
    # -------------------------------------------------------------------------

    DEVICE_PERSISTENT_THRESHOLD = 50
    DEVICE_PERIODIC_THRESHOLD = 10

    # -------------------------------------------------------------------------
    # PROTOCOL HEURISTICS
    # -------------------------------------------------------------------------

    WIFI_BAND_MIN = 2400
    WIFI_BAND_MAX = 2500

    BLE_BAND_MIN = 2400
    BLE_BAND_MAX = 2500

    ZIGBEE_BAND_MIN = 2400
    ZIGBEE_BAND_MAX = 2500

    WIFI_CHANNELS = [
        2412, 2437, 2462
    ]

    BLE_CHANNELS = [
        2402, 2426, 2480
    ]

    # -------------------------------------------------------------------------
    # HARDWARE FINGERPRINTING
    # -------------------------------------------------------------------------

    CFO_MAX_HZ = 200000
    PHASE_NOISE_THRESHOLD = 0.2

    # -------------------------------------------------------------------------
    # MACHINE LEARNING
    # -------------------------------------------------------------------------

    ML_CONFIDENCE_THRESHOLD = 0.7

    # -------------------------------------------------------------------------
    # ENVIRONMENT PROFILES
    # -------------------------------------------------------------------------

    ENVIRONMENT_PROFILES = {

        "LAB": {
            "SNR_BASE_THRESHOLD": 3.0,
            "BASE_FREQ_TOLERANCE_MHZ": 0.5,
        },

        "FIELD": {
            "SNR_BASE_THRESHOLD": 5.0,
            "BASE_FREQ_TOLERANCE_MHZ": 0.9,
        },

        "HIGH_DENSITY": {
            "SNR_BASE_THRESHOLD": 7.0,
            "BASE_FREQ_TOLERANCE_MHZ": 1.4,
        }

    }

    # -------------------------------------------------------------------------
    # CONFIG ACCESS
    # -------------------------------------------------------------------------

    @classmethod
    def get_profile(cls):

        profile = cls.ENVIRONMENT_PROFILES.get(cls.MODE)

        if not profile:
            return {}

        return profile

    @classmethod
    def get(cls, key, default=None):

        profile = cls.get_profile()

        if key in profile:
            return profile[key]

        return getattr(cls, key, default)
