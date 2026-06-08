from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List


def get_decoder_backends() -> List[Dict[str, Any]]:
    backends = [
        {
            "backend_id": "btle_r",
            "label": "BTLE-R external decoder",
            "available": _btle_r_available(),
            "integrated": False,
            "mode": "live_sdr",
            "requires": ["BTLE-R"],
        },
        {
            "backend_id": "gnuradio_hackrf",
            "label": "GNU Radio HackRF BLE demod",
            "available": _gnuradio_available(),
            "integrated": True,
            "mode": "live_sdr",
            "requires": ["gnuradio", "osmosdr"],
        },
        {
            "backend_id": "btle_rx",
            "label": "BTLE SDR decoder",
            "available": shutil.which("btle_rx") is not None,
            "integrated": False,
            "mode": "live_sdr",
            "requires": ["btle_rx", "hackrf_or_bladerf"],
        },
        {
            "backend_id": "ubertooth",
            "label": "Ubertooth BLE sniffer",
            "available": shutil.which("ubertooth-btle") is not None,
            "integrated": False,
            "mode": "dedicated_sniffer",
            "requires": ["ubertooth-btle", "ubertooth_hardware"],
        },
        {
            "backend_id": "tshark_pcap",
            "label": "TShark BLE PCAP decoder",
            "available": shutil.which("tshark") is not None,
            "integrated": False,
            "mode": "offline_or_extcap",
            "requires": ["tshark"],
        },
    ]
    return backends


def preferred_backend_id() -> str | None:
    preferred = (os.getenv("GHOSTRECON_BLE_BACKEND") or "").strip().lower()
    if preferred:
        for backend in get_decoder_backends():
            if backend["available"] and backend["backend_id"] == preferred:
                return preferred
    for backend in get_decoder_backends():
        if backend["available"] and backend.get("integrated") and backend["backend_id"] in {"gnuradio_hackrf"}:
            return backend["backend_id"]
    return None


def _gnuradio_available() -> bool:
    try:
        import gnuradio  # noqa: F401
        import osmosdr  # noqa: F401
        return True
    except Exception:
        return False


def _btle_r_available() -> bool:
    candidates = [
        "BTLE-R",
        "BTLE-R.py",
        "btle-r",
        "btler",
    ]
    return any(shutil.which(candidate) is not None for candidate in candidates)
