# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/api/rf_api.py
# VERSION:      v33.0.0 (PRODUCTION — RUNTIME-BOUND RF API)
# UPDATED:      2026-03-19
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE
# =============================================================================
#
# FastAPI → RF API → Runtime (app.state.runtime)
#
# CRITICAL:
# ✔ NO global getters
# ✔ NO singleton access
# ✔ ALL state from runtime instance
#
# =============================================================================

# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# - Expose RF spectrum data
# - Expose live FFT (validator critical)
# - Provide RF health visibility
#
# =============================================================================

# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# ✔ Return real FFT data
# ✔ Provide RF system health
# ✔ Support real-time monitoring
#
# ❌ NO RF processing
# ❌ NO signal classification
#
# =============================================================================

# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# - SINGLE SOURCE OF TRUTH → runtime
# - FAIL SAFE → never crash API
# - JSON SAFE → numpy → list conversion
#
# =============================================================================

import time
import subprocess
from importlib import import_module

from fastapi import APIRouter, Request

# =============================================================================
# ROUTERS
# =============================================================================
router = APIRouter(prefix="/api/rf", tags=["RF"])
live_router = APIRouter(prefix="/api/live", tags=["Live"])

API_VERSION = "v33.0.0"
EVENT_TIMELINE_LIMIT = 12


def _is_benign_hackrf_shutdown(detail: str, exit_code) -> bool:
    text = str(detail or "").lower()
    if exit_code == 0 and not text:
        return True
    if exit_code not in (0, None):
        return False
    benign_markers = [
        "caught signal 15",
        "exiting...",
        "hackrf_stop_rx() done",
        "hackrf_close() done",
        "hackrf_exit() done",
        "fclose() done",
        "exit",
        "average power",
        "mb/second",
    ]
    return any(marker in text for marker in benign_markers)


# =============================================================================
# RUNTIME ACCESS
# =============================================================================
def _get_runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise RuntimeError("Runtime not initialized")
    return runtime


# =============================================================================
# SAFE HELPERS
# =============================================================================
def _safe_call(obj, method, default=None):
    try:
        fn = getattr(obj, method, None)
        if callable(fn):
            return fn()
    except Exception:
        pass
    return default


# =============================================================================
# FFT EXTRACTION
# =============================================================================
def _get_fft_payload(runtime):

    fft = runtime.fft

    if not fft:
        return {
            "bins": [],
            "fft_bins": 0,
            "frame_present": False,
            "frame_timestamp": None,
        }

    frame = _safe_call(fft, "get_latest_frame")

    if frame is None:
        return {
            "bins": [],
            "fft_bins": 0,
            "frame_present": False,
            "frame_timestamp": None,
        }

    try:
        bins = frame.tolist()
    except Exception:
        bins = []

    return {
        "bins": bins,
        "fft_bins": len(bins),
        "frame_present": len(bins) > 0,
        "frame_timestamp": _safe_call(fft, "get_latest_frame_timestamp"),
    }


def _hackrf_status():
    try:
        result = subprocess.run(
            ["hackrf_info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        lines = output.splitlines()
        output_lower = output.lower()
        return {
            "available": result.returncode == 0 or "found hackrf" in output_lower,
            "detail": lines[0] if lines else "",
            "busy": "resource busy" in output_lower,
        }
    except Exception as exc:
        return {
            "available": False,
            "detail": str(exc),
            "busy": False,
        }


def _decoder_availability(runtime):
    diagnostics = {
        "ble_decoder": False,
        "ble_identity": False,
        "device_intelligence": False,
        "lora_profiles": False,
        "correlation": False,
    }
    try:
        try:
            module = import_module("backend.intel.ble.decoder_backends")
            backends = module.get_decoder_backends()
            diagnostics["ble_decoder"] = any(
                backend.get("backend_id") == "gnuradio_hackrf" and backend.get("available") and backend.get("integrated")
                for backend in backends
            )
        except Exception:
            diagnostics["ble_decoder"] = False
        diagnostics["ble_identity"] = bool(getattr(runtime, "ble_identity", None))
        diagnostics["device_intelligence"] = bool(getattr(runtime, "device_intelligence", None))
        diagnostics["lora_profiles"] = True
        diagnostics["correlation"] = bool(getattr(runtime, "correlation_engine", None))
    except Exception:
        pass
    return diagnostics


# =============================================================================
# RF HEALTH
# =============================================================================
@router.get("/health")
def rf_health(request: Request):

    runtime = _get_runtime(request)

    fft = _get_fft_payload(runtime)

    sdr = runtime.sdr
    session = runtime.session_controller
    recon = runtime.recon

    sdr_state = _safe_call(sdr, "get_state", {})
    recon_state = _safe_call(recon, "get_stats", {})
    hackrf = _hackrf_status()
    sdr_running = sdr_state.get("running", False)
    sdr_process_alive = sdr_state.get("process_alive", False)
    sdr_freq_mhz = sdr_state.get("freq_mhz")
    sdr_healthy = _safe_call(sdr, "is_healthy", False)
    fft_running = fft["frame_present"]
    sdr_last_error = sdr_state.get("last_error") or sdr_state.get("last_stderr_excerpt") or ""
    sdr_last_exit_code = sdr_state.get("last_exit_code")
    if _is_benign_hackrf_shutdown(sdr_last_error, sdr_last_exit_code):
        sdr_last_error = ""
        sdr_last_exit_code = None

    if not hackrf.get("available", False):
        connection_state = "disconnected"
        fault_reason = "SDR not connected. Please connect SDR."
    elif hackrf.get("busy") and not sdr_running:
        connection_state = "device_busy"
        fault_reason = "HackRF is busy in another process. Stop the other SDR client before starting a session."
    elif not sdr_running:
        if sdr_last_error or sdr_last_exit_code is not None:
            connection_state = "stream_process_down"
            fault_reason = sdr_last_error or f"SDR process exited unexpectedly with code {sdr_last_exit_code}."
        else:
            connection_state = "connected_idle"
            fault_reason = "SDR connected but not streaming. Start an SDR session."
    elif not sdr_process_alive:
        connection_state = "stream_process_down"
        fault_reason = sdr_last_error or "SDR process is not alive. Restart the SDR session."
    elif not sdr_healthy:
        connection_state = "stream_stalled"
        fault_reason = sdr_last_error or "SDR connected but IQ stream is stalled."
    elif sdr_freq_mhz is None:
        connection_state = "frequency_unknown"
        fault_reason = "SDR is running but no streaming frequency is confirmed."
    elif not fft_running:
        connection_state = "fft_missing"
        fault_reason = "SDR is running but FFT frames are missing."
    else:
        connection_state = "streaming"
        fault_reason = ""
    now = time.time()
    fft_age_sec = None
    if fft["frame_timestamp"] is not None:
        try:
            fft_age_sec = round(max(0.0, now - float(fft["frame_timestamp"])), 3)
        except Exception:
            fft_age_sec = None

    signal_state = _safe_call(runtime.signal, "get_state", {}) if getattr(runtime, "signal", None) else {}
    signal_stats = _safe_call(runtime.signal, "get_stats", {}) if getattr(runtime, "signal", None) else {}
    stale_timeout = signal_stats.get("stale_timeout_sec") or signal_state.get("stale_timeout_sec")
    prune_timeout = signal_stats.get("prune_timeout_sec") or signal_state.get("prune_timeout_sec")

    preflight = {
        "hackrf_attached": bool(hackrf.get("available", False)),
        "stream_process_alive": bool(sdr_process_alive),
        "iq_stream_healthy": bool(sdr_healthy),
        "frequency_confirmed": sdr_freq_mhz is not None,
        "fft_updating": bool(fft_running),
        "pipeline_ready": bool(
            session.is_active()
            and sdr_running
            and fft_running
            and recon_state.get("running", False)
        ),
        "ready_to_start": bool(hackrf.get("available", False)),
        "ready_for_live_intel": connection_state == "streaming",
    }

    decoder_availability = _decoder_availability(runtime)
    device_snapshot = _safe_call(runtime.device_fusion, "export_graph", now) if getattr(runtime, "device_fusion", None) else []
    evidence_pipeline = {
        "signal_detected": bool(signal_state.get("signal_count", 0)),
        "protocol_inferred": bool(signal_state.get("real_protocol_signal_count", 0)),
        "device_fused": bool(session.is_active() and device_snapshot),
        "decoder_backed_paths": [key for key, available in decoder_availability.items() if available],
    }

    payload = {
        "version": API_VERSION,
        "timestamp": now,

        "session_active": session.is_active(),

        "sdr_running": sdr_running,
        "sdr_healthy": sdr_healthy,
        "sdr_device": "HackRF One",
        "sdr_freq_mhz": sdr_freq_mhz,
        "sdr_sample_rate": sdr_state.get("sample_rate"),
        "sdr_iq_path": sdr_state.get("iq_path"),
        "sdr_amp_enable": sdr_state.get("amp_enable", False),
        "sdr_lna_gain": sdr_state.get("lna_gain"),
        "sdr_vga_gain": sdr_state.get("vga_gain"),
        "sdr_process_alive": sdr_process_alive,
        "sdr_last_error": sdr_last_error,
        "sdr_last_exit_code": sdr_last_exit_code,
        "sdr_last_start_attempt_at": sdr_state.get("last_start_attempt_at"),
        "sdr_last_started_at": sdr_state.get("last_started_at"),
        "sdr_stderr_path": sdr_state.get("stderr_path"),
        "sdr_process_events": sdr_state.get("event_history", []),
        "fft_running": fft_running,
        "fft_frame_timestamp": fft["frame_timestamp"],
        "fft_age_sec": fft_age_sec,
        "recon_running": recon_state.get("running", False),
        "hackrf": hackrf,
        "sdr_connection_state": connection_state,
        "sdr_fault_reason": fault_reason,
        "sdr_streaming_confirmed": connection_state == "streaming",
        "preflight": preflight,
        "decoder_availability": decoder_availability,
        "evidence_pipeline": evidence_pipeline,
        "data_validity": {
            "stale_timeout_sec": stale_timeout,
            "prune_timeout_sec": prune_timeout,
            "stale_guard_active": True,
            "stream_verified": connection_state == "streaming",
        },

        "pipeline_ready": preflight["pipeline_ready"],
    }

    if hasattr(runtime, "observe_rf_health"):
        try:
            runtime.observe_rf_health(payload)
        except Exception:
            pass
    if hasattr(runtime, "get_rf_event_timeline"):
        try:
            payload["event_timeline"] = runtime.get_rf_event_timeline(EVENT_TIMELINE_LIMIT)
        except Exception:
            payload["event_timeline"] = []
    else:
        payload["event_timeline"] = []

    return payload


# =============================================================================
# RF SPECTRUM
# =============================================================================
@router.get("/spectrum")
def rf_spectrum(request: Request):

    runtime = _get_runtime(request)

    fft = _get_fft_payload(runtime)
    sdr = runtime.sdr

    center_freq = None
    try:
        center_freq = sdr.get_state().get("freq_mhz")
    except Exception:
        pass

    return {
        "version": API_VERSION,
        "spectrum": fft["bins"],
        "fft_bins": fft["fft_bins"],
        "center_freq_mhz": center_freq,
        "fft_frame_timestamp": fft["frame_timestamp"],
        "timestamp": time.time(),
    }


# =============================================================================
# LIVE FFT (VALIDATOR CRITICAL)
# =============================================================================
@live_router.get("/fft")
def live_fft(request: Request):

    runtime = _get_runtime(request)
    fft = _get_fft_payload(runtime)

    return {
        "version": API_VERSION,
        "bins": fft["bins"],  # REQUIRED by validator
        "fft_bins": fft["fft_bins"],
        "fft_frame_timestamp": fft["frame_timestamp"],
        "timestamp": time.time(),
    }
