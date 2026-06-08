# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/api/system_api.py
# VERSION:      v12.0.0 (PRODUCTION — RUNTIME-BOUND CONTROL PLANE)
# UPDATED:      2026-03-19
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE
# =============================================================================
#
# FastAPI → System API → Runtime (app.state.runtime) → SessionController → Pipeline
#
# CRITICAL:
# ✔ NO global getters
# ✔ NO duplicate instances
# ✔ ALWAYS use runtime from FastAPI
#
# =============================================================================

# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# - Control full RF lifecycle (start / retune / stop)
# - Provide REAL system state (runtime truth)
# - Ensure validator compatibility
#
# =============================================================================

# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# ✔ Trigger session start
# ✔ Trigger retune
# ✔ Provide full system snapshot
#
# ❌ NO RF logic
# ❌ NO signal processing
#
# =============================================================================

# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# - SINGLE SOURCE OF TRUTH → runtime only
# - NO STATIC STATE
# - FAIL SAFE
# - VALIDATOR COMPATIBLE
#
# =============================================================================

# =============================================================================
# 🔧 CHANGES (v12.0.0)
# =============================================================================
#
# ✔ REMOVED get_* global getters (critical bug)
# ✔ BOUND everything to runtime instance
# ✔ FIXED session start not executing
# ✔ FIXED state inconsistency
#
# =============================================================================


from typing import Optional
from pathlib import Path
from importlib import import_module
import json
import os
import shutil
import subprocess
import threading
import time
from fastapi import APIRouter, HTTPException, Request
from backend.config.project_config import get_project_config

router = APIRouter(tags=["system"])

DEFAULT_FREQ = 433.92
ROOT_DIR = Path(__file__).resolve().parents[2]
IDENTITIES_DIR = ROOT_DIR / "identities"


# =============================================================================
# RUNTIME ACCESS
# =============================================================================
def _get_runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)

    if runtime is None:
        raise HTTPException(503, "Runtime not initialized")

    return runtime


# =============================================================================
# SNAPSHOT ENGINE (RUNTIME TRUTH)
# =============================================================================
def _snapshot(runtime):

    try:
        session = runtime.session_controller
        sdr = runtime.sdr
        fft = runtime.fft
        recon = runtime.recon
        signal = runtime.signal

    except Exception:
        return {
            "session_active": False,
            "pipeline_ready": False,
            "sdr_running": False,
            "sdr_healthy": False,
            "fft_running": False,
            "fft_healthy": False,
            "recon_running": False,
            "signal_active": False,
            "signal_count": 0,
            "active_freq_mhz": None,
        }

    sdr_state = sdr.get_state()
    fft_frame = fft.get_latest_frame()
    fft_frame_ts = getattr(fft, "get_latest_frame_timestamp", lambda: None)()
    recon_stats = recon.get_stats()
    signal_stats = signal.get_stats()
    session_telemetry = session.get_telemetry() if hasattr(session, "get_telemetry") else {}
    rf_events = runtime.get_rf_event_timeline(12) if hasattr(runtime, "get_rf_event_timeline") else []
    host_hardware = _host_hardware_summary()
    connected_hardware = _connected_usb_inventory()

    return {
        "session_active": session.is_active(),

        "pipeline_ready": (
            session.is_active()
            and sdr_state.get("running")
            and fft.is_running()
            and fft_frame is not None
            and recon_stats.get("running")
        ),

        "sdr_running": sdr_state.get("running"),
        "sdr_healthy": sdr_state.get("healthy", True),
        "active_freq_mhz": sdr_state.get("freq_mhz"),

        "fft_running": fft.is_running(),
        "fft_healthy": fft_frame is not None,
        "fft_frame_timestamp": fft_frame_ts,

        "recon_running": recon_stats.get("running"),
        "recon_stats": recon_stats,

        "signal_active": signal_stats.get("active_signals", 0) > 0,
        "signal_count": signal_stats.get("active_signals", 0),
        "signal_stats": signal_stats,
        "session_telemetry": session_telemetry,
        "event_timeline": rf_events,
        "host_hardware": host_hardware,
        "connected_hardware": connected_hardware,
    }


def _hackrf_attached() -> bool:
    try:
        result = subprocess.run(["hackrf_info"], capture_output=True, text=True, timeout=5, check=False)
        return result.returncode == 0
    except Exception:
        return False


def _host_hardware_summary() -> dict:
    cpu_model = ""
    logical_cores = os.cpu_count() or 0
    memory_gb = None

    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        for line in cpuinfo.splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[-1].strip()
                break
    except Exception:
        cpu_model = ""

    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore")
        for line in meminfo.splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                kib = int(parts[1]) if len(parts) > 1 else 0
                memory_gb = round(kib / 1024 / 1024, 1)
                break
    except Exception:
        memory_gb = None

    return {
        "processor": cpu_model or "Unknown Processor",
        "logical_cores": int(logical_cores or 0),
        "memory_gb": memory_gb,
    }


def _connected_usb_inventory() -> list[dict]:
    try:
        result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5, check=False)
        lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    except Exception:
        return []

    relevant_keywords = {
        "hackrf", "nordic", "nrf", "bluetooth", "wireless", "intel", "realtek",
        "alfa", "tp-link", "ubiquiti", "rtl", "zigbee", "cc2531", "cc2652",
        "silicon labs", "cp210", "ftdi", "sonoff",
    }
    excluded_keywords = {
        "root hub", "usb hub", "high-speed hub", "superspeed hub",
        "keyboard", "flash drive", "led controller", "cooler", "scope rx",
    }

    inventory: list[dict] = []
    for line in lines:
        if " ID " not in line:
            continue
        left, right = line.split(" ID ", 1)
        right = right.strip()
        if " " in right:
            usb_id, descriptor = right.split(" ", 1)
        else:
            usb_id, descriptor = right, ""
        lowered = descriptor.lower()
        if any(token in lowered for token in excluded_keywords):
            continue
        if relevant_keywords and not any(token in lowered for token in relevant_keywords):
            continue
        left_parts = left.split()
        bus = left_parts[1] if len(left_parts) > 1 else ""
        device = left_parts[3].rstrip(":") if len(left_parts) > 3 else ""
        manufacturer = descriptor
        product = descriptor
        if "," in descriptor:
            manufacturer, product = [part.strip() for part in descriptor.split(",", 1)]
        inventory.append(
            {
                "id": usb_id,
                "bus": bus,
                "device": device,
                "manufacturer": manufacturer or descriptor or "Unknown Manufacturer",
                "product": product or descriptor or "Unknown Device",
                "descriptor": descriptor or "Unknown Device",
                "transport": "USB",
                "connected": True,
            }
        )
    return inventory


def _prepare_ble_handoff(release_wait_seconds: float = 1.2) -> None:
    try:
        from backend.api.intel_api import _stop_ble_worker
        _stop_ble_worker()
    except Exception:
        return
    time.sleep(release_wait_seconds)


def _kill_listeners_on_port(port: int, exclude_pid: Optional[int] = None) -> None:
    try:
        result = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=5, check=False)
    except Exception:
        return
    for line in (result.stdout or "").splitlines():
        if f":{port} " not in line:
            continue
        for token in line.split("pid=")[1:]:
            pid_text = ""
            for ch in token:
                if ch.isdigit():
                    pid_text += ch
                else:
                    break
            if not pid_text:
                continue
            pid = int(pid_text)
            if exclude_pid is not None and pid == exclude_pid:
                continue
            try:
                os.kill(pid, 9)
            except Exception:
                pass


def _schedule_backend_restart() -> None:
    config = get_project_config()
    backend_cfg = config.get("network", {}).get("backend", {})
    host = backend_cfg.get("host", "127.0.0.1")
    port = int(backend_cfg.get("port", 8100))
    app_dir = str(ROOT_DIR)
    current_pid = os.getpid()
    launcher = str(ROOT_DIR / "scripts" / "start_backend_service.sh")
    helper_code = (
        "import os,subprocess,time;"
        f"os.environ['BACKEND_HOST']={host!r};"
        f"os.environ['BACKEND_PORT']={str(port)!r};"
        f"time.sleep(0.8);"
        "out=subprocess.run(['ss','-ltnp'],capture_output=True,text=True,check=False).stdout;"
        f"port=':{port} ';"
        "pids=[];"
        "\n"
        "for line in out.splitlines():\n"
        "    if port not in line:\n"
        "        continue\n"
        "    for token in line.split('pid=')[1:]:\n"
        "        pid=''\n"
        "        for ch in token:\n"
        "            if ch.isdigit(): pid += ch\n"
        "            else: break\n"
        "        if pid: pids.append(int(pid))\n"
        f"exclude={current_pid};"
        "\n"
        "for pid in set(pids):\n"
        "    if pid != exclude:\n"
        "        try: os.kill(pid, 9)\n"
        "        except Exception: pass\n"
        f"subprocess.Popen(['bash', {launcher!r}], cwd={app_dir!r}, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True);"
    )
    subprocess.Popen(
        ["python3", "-c", helper_code],
        cwd=app_dir,
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )

    def _exit_current() -> None:
        time.sleep(1.2)
        os._exit(0)

    threading.Thread(target=_exit_current, daemon=True).start()


def _is_ble_freq(freq_mhz: Optional[float]) -> bool:
    try:
        return 2400.0 <= float(freq_mhz) <= 2485.0
    except Exception:
        return False


def _sync_ble_decoder(runtime, freq_mhz: Optional[float]) -> None:
    try:
        from backend.api.intel_api import _stop_ble_worker
    except Exception:
        return
    if not _is_ble_freq(freq_mhz):
        _stop_ble_worker()


def _sync_ble_capture_profile(runtime, freq_mhz: Optional[float]) -> None:
    sdr = getattr(runtime, "sdr", None)
    if sdr is None or not hasattr(sdr, "configure_runtime"):
        return
    if not _is_ble_freq(freq_mhz):
        if hasattr(sdr, "reset_runtime_profile"):
            sdr.reset_runtime_profile()
        return
    try:
        from backend.api.intel_api import _get_ble_capture_profile
    except Exception:
        return
    profile = _get_ble_capture_profile(freq_mhz) or {}
    sdr.configure_runtime(
        sample_rate=profile.get("sample_rate"),
        amp_enable=profile.get("amp_enable"),
        lna_gain=profile.get("lna_gain"),
        vga_gain=profile.get("vga_gain"),
        profile_id=profile.get("id") or "ble_balanced",
        profile_label=profile.get("label") or "BLE Adaptive",
        profile_reason=profile.get("reason") or "ble_adaptive_capture",
    )


def _command_status(command: str, args: list[str] | None = None) -> dict:
    args = args or ["--version"]
    path = shutil.which(command)
    installed = path is not None
    output = ""
    ok = False
    if installed:
      try:
          result = subprocess.run([command, *args], capture_output=True, text=True, timeout=5, check=False)
          output = (result.stdout or result.stderr or "").strip().splitlines()[0] if (result.stdout or result.stderr) else ""
          ok = result.returncode == 0
      except Exception as exc:
          output = str(exc)
    return {
        "command": command,
        "installed": installed,
        "path": path,
        "ok": ok,
        "output": output,
    }


def _import_status(module_path: str, attr_name: str | None = None) -> dict:
    target = module_path if attr_name is None else f"{module_path}:{attr_name}"
    try:
        module = import_module(module_path)
        if attr_name:
            getattr(module, attr_name)
        return {
            "target": target,
            "available": True,
            "detail": "import ok",
        }
    except Exception as exc:
        return {
            "target": target,
            "available": False,
            "detail": str(exc),
        }



def _list_identities() -> list[dict]:
    identities = []
    for path in sorted(IDENTITIES_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        identities.append(
            {
                "name": path.name,
                "path": str(path),
                "device_uuid": payload.get("device_uuid"),
                "confidence": payload.get("confidence"),
                "last_seen": payload.get("last_seen"),
                "fingerprint_vector_length": len(payload.get("fingerprint_vector", []) or []),
            }
        )
    return identities


def _system_diagnostics(runtime) -> dict:
    project_config = get_project_config()
    return {
        "project_config": project_config,
        "active_sdr_config": project_config.get("sdr", {}),
        "runtime": _snapshot(runtime),
        "dependencies": {
            "python": _command_status("python3", ["--version"]),
            "uvicorn": _command_status("python3", ["-m", "uvicorn", "--version"]),
            "npm": _command_status("npm", ["--version"]),
            "hackrf_info": _command_status("hackrf_info"),
            "hackrf_transfer": _command_status("hackrf_transfer"),
            "gnuradio_companion": _command_status("gnuradio-companion", ["--help"]),
        },
        "optional_modules": {
            "protocol_fingerprint": _import_status(
                "backend.recon.protocols.protocol_fingerprint",
                "ProtocolFingerprintEngine",
            ),
            "behavior_engine": _import_status(
                "backend.recon.intelligence.behavior_engine",
                "RFBehaviorEngine",
            ),
            "ble_identity_engine": _import_status(
                "backend.intel.identity.ble_identity_engine",
                "BLEIdentityEngine",
            ),
            "rf_identity_resolver": _import_status(
                "backend.intel.identity.rf_identity_resolver",
                "RFIdentityResolver",
            ),
            "ble_decoder_worker": _import_status(
                "backend.intel.ble.ble_decoder_worker",
                "BLEDecoderWorker",
            ),
        },
        "artifacts": {
            "identities": len(_list_identities()),
        },
    }


# =============================================================================
# HEALTH
# =============================================================================
@router.get("/health")
def health(request: Request):

    runtime = _get_runtime(request)

    return {
        "status": "healthy",
        "pipeline": _snapshot(runtime),
    }


# =============================================================================
# STATE
# =============================================================================
@router.get("/state")
def state(request: Request):

    runtime = _get_runtime(request)

    return _snapshot(runtime)


@router.get("/config")
def project_config(request: Request):

    _get_runtime(request)

    return get_project_config()


@router.get("/diagnostics")
def diagnostics(request: Request):

    runtime = _get_runtime(request)

    return _system_diagnostics(runtime)


@router.get("/events")
def events(request: Request):
    runtime = _get_runtime(request)
    return {
        "count": len(runtime.get_rf_event_timeline(80)) if hasattr(runtime, "get_rf_event_timeline") else 0,
        "events": runtime.get_rf_event_timeline(80) if hasattr(runtime, "get_rf_event_timeline") else [],
    }


@router.get("/identities")
def identities(request: Request):

    _get_runtime(request)

    return {
        "identity_count": len(_list_identities()),
        "identities": _list_identities(),
    }


# =============================================================================
# START (FIXED — REAL EXECUTION)
# =============================================================================
@router.post("/start")
def start(request: Request, freq_mhz: Optional[float] = None):

    runtime = _get_runtime(request)
    session = runtime.session_controller

    if freq_mhz is None:
        freq_mhz = DEFAULT_FREQ

    if not _hackrf_attached():
        raise HTTPException(503, "SDR not connected. Please connect SDR.")

    if session.is_active():
        return {
            "status": "already_running",
            "message": "Session already active. Use /retune for frequency changes.",
            "pipeline": _snapshot(runtime),
        }

    try:
        _sync_ble_capture_profile(runtime, freq_mhz)
        _prepare_ble_handoff()
        result = session.start(freq_mhz=freq_mhz)
        _sync_ble_decoder(runtime, freq_mhz)

        if str(result.get("status") or "").lower() not in {"started", "already_running"}:
            raise RuntimeError(result.get("error") or result.get("status") or "Unknown SDR start failure")

        return {
            "status": result.get("status"),
            "pipeline": _snapshot(runtime),
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =============================================================================
# RETUNE
# =============================================================================
@router.post("/retune")
def retune(request: Request, freq_mhz: float):

    runtime = _get_runtime(request)
    session = runtime.session_controller

    if not session.is_active():
        raise HTTPException(400, "Session not active")
    if not _hackrf_attached():
        raise HTTPException(503, "SDR not connected. Please connect SDR.")

    current_freq = None
    try:
        current_freq = float(runtime.sdr.get_state().get("freq_mhz"))
    except Exception:
        current_freq = None

    if current_freq is not None and abs(current_freq - float(freq_mhz)) < 0.0001:
        return {
            "status": "already_tuned",
            "freq_mhz": current_freq,
            "pipeline": _snapshot(runtime),
        }

    try:
        _sync_ble_capture_profile(runtime, freq_mhz)
        _prepare_ble_handoff()
        result = session.retune(freq_mhz)
        _sync_ble_decoder(runtime, freq_mhz)

        return {
            "status": "retuned",
            "freq_mhz": result.get("freq_mhz"),
            "pipeline": _snapshot(runtime),
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =============================================================================
# STOP
# =============================================================================
@router.post("/stop")
def stop(request: Request):

    runtime = _get_runtime(request)
    session = runtime.session_controller

    session.stop()

    return {"status": "stopped"}


@router.post("/restart_backend")
def restart_backend(request: Request):
    runtime = _get_runtime(request)
    try:
        runtime.session_controller.stop()
    except Exception:
        pass
    _schedule_backend_restart()
    return {"status": "restarting"}
