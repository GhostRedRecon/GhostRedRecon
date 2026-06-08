# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       PIPELINE VALIDATOR
# FILE:         backend/recon/pipeline_validator.py
#
# VERSION:      v1.0.0 (PIPELINE + CONFIGURATION VALIDATOR)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# PipelineValidator verifies the health of the GhostRecon RF pipeline.
#
# It validates:
#
# • configuration sanity
# • module imports
# • pipeline stage availability
# • configuration parameter ranges
#
# This tool ensures the entire RF intelligence stack is wired correctly
# before running the SDR pipeline.
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. FAIL FAST
# If a critical module is missing the validator should stop immediately.
#
# 2. CONFIGURATION SAFETY
# Incorrect thresholds can break signal detection. These must be validated.
#
# 3. PIPELINE VISIBILITY
# Every stage in the pipeline must be visible in the validation report.
#
# 4. LOW DEPENDENCY
# Validator should not require SDR hardware to run.
#
# =============================================================================


import importlib
import inspect
import sys
from pathlib import Path


class PipelineValidator:

    VERSION = "1.0.0"

    # -------------------------------------------------------------------------
    # PIPELINE STAGES
    # -------------------------------------------------------------------------

    PIPELINE_MODULES = {

        "spectral_environment": "core.spectral_environment",
        "peak_detector": "detection.peak_detector",
        "burst_detector": "detection.burst_detector",
        "emitter_cluster": "detection.emitter_cluster",
        "emitter_tracker": "detection.emitter_tracker",
        "emitter_lifecycle": "detection.emitter_lifecycle",

        "channel_aggregator": "utils.channel_aggregator",
        "signal_refiner": "utils.signal_refiner",

        "feature_extractor": "features.feature_extractor",

        "protocol_classifier": "protocols.protocol_classifier",

        "device_signature": "signatures.device_signature",
        "vendor_signature": "signatures.vendor_signature",
        "product_signature": "signatures.product_signature",

        "device_fusion": "intelligence.device_fusion",
        "network_correlation": "intelligence.network_correlation",
        "activity_heatmap": "intelligence.activity_heatmap",

        "intelligence_formatter": "utils.intelligence_formatter"
    }

    # -------------------------------------------------------------------------
    # CONFIGURATION PARAMETERS TO CHECK
    # -------------------------------------------------------------------------

    CONFIG_CHECKS = {

        "SNR_BASE_THRESHOLD": (0.1, 50),
        "CFAR_GUARD_CELLS": (1, 50),
        "CFAR_NOISE_CELLS": (5, 200),
        "PEAK_GROUP_GAP": (1, 100),
        "BASE_FREQ_TOLERANCE_MHZ": (0.01, 50),
        "MAX_FREQ_TOLERANCE_MHZ": (0.1, 200),
        "EMITTER_TIMEOUT": (1, 600),

    }

    # -------------------------------------------------------------------------
    # VALIDATE ENTIRE PIPELINE
    # -------------------------------------------------------------------------

    def validate(self):

        print("\n===============================")
        print(" GhostRecon Pipeline Validator ")
        print("===============================\n")

        self._validate_configuration()
        self._validate_pipeline_modules()

        print("\nPipeline validation complete.\n")

    # -------------------------------------------------------------------------
    # CONFIGURATION VALIDATION
    # -------------------------------------------------------------------------

    def _validate_configuration(self):

        print("Checking configuration...")

        try:
            from backend.recon.configuration import ReconConfig
        except Exception as e:
            print("❌ Failed to load configuration:", e)
            sys.exit(1)

        errors = 0

        for param, (min_val, max_val) in self.CONFIG_CHECKS.items():

            if not hasattr(ReconConfig, param):

                print(f"❌ Missing config parameter: {param}")
                errors += 1
                continue

            value = getattr(ReconConfig, param)

            if not isinstance(value, (int, float)):

                print(f"❌ Invalid type for {param}: {type(value)}")
                errors += 1
                continue

            if not (min_val <= value <= max_val):

                print(f"⚠ {param} outside recommended range: {value}")

        if errors == 0:
            print("✔ Configuration validation passed\n")
        else:
            print(f"⚠ Configuration issues detected: {errors}\n")

    # -------------------------------------------------------------------------
    # MODULE VALIDATION
    # -------------------------------------------------------------------------

    def _validate_pipeline_modules(self):

        print("Checking pipeline modules...\n")

        for name, module_path in self.PIPELINE_MODULES.items():

            try:

                module = importlib.import_module(f"backend.recon.{module_path}")

                classes = [
                    obj for _, obj in inspect.getmembers(module)
                    if inspect.isclass(obj)
                ]

                if not classes:

                    print(f"⚠ {name}: module loaded but no classes found")

                else:

                    print(f"✔ {name}: OK")

            except Exception as e:

                print(f"❌ {name}: FAILED ({e})")

    # -------------------------------------------------------------------------
    # ENTRY POINT
    # -------------------------------------------------------------------------

    @staticmethod
    def run():

        validator = PipelineValidator()
        validator.validate()


# -----------------------------------------------------------------------------
# CLI ENTRY
# -----------------------------------------------------------------------------

if __name__ == "__main__":

    PipelineValidator.run()
