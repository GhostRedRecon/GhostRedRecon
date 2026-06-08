# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/ble_advertisement_parser.py
# VERSION:      v1.0.0 (SIGINT BLE IDENTITY EXTRACTION ENGINE)
# UPDATED:      2026-03-24
# =============================================================================

from __future__ import annotations

from typing import Dict, Any, Optional


class BLEAdvertisementParser:
    """
    BLE Advertisement Parser (SIGINT Level)

    PURPOSE:
    --------
    Extract BLE identity fields from signals.

    OUTPUT:
    -------
    Adds:
        mac_address
        ble_address_type
        device_name
        manufacturer
        manufacturer_data
        ble_adv_type
        tx_power
    """

    VERSION = "1.0.0"

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def process(self, signal: Dict[str, Any]) -> Dict[str, Any]:

        if not isinstance(signal, dict):
            return signal

        protocol = str(signal.get("protocol", "")).upper()

        if protocol != "BLE":
            return signal

        try:
            return self._parse_ble(signal)
        except Exception:
            return signal

    # =========================================================================
    # BLE PARSING
    # =========================================================================
    def _parse_ble(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        # ---------------------------------------------------------
        # RAW METADATA (FUTURE: real decoded packets)
        # ---------------------------------------------------------
        metadata = sig.get("ble_metadata") or {}

        # ---------------------------------------------------------
        # MAC ADDRESS EXTRACTION
        # ---------------------------------------------------------
        mac = (
            metadata.get("mac_address")
            or sig.get("mac_address")
            or sig.get("ble_address")
        )

        if mac:
            sig["mac_address"] = mac.upper()

        # ---------------------------------------------------------
        # ADDRESS TYPE
        # ---------------------------------------------------------
        addr_type = metadata.get("address_type")

        if addr_type:
            sig["ble_address_type"] = addr_type

        # ---------------------------------------------------------
        # DEVICE NAME
        # ---------------------------------------------------------
        name = metadata.get("device_name")

        if name:
            sig["device_name"] = name

        # ---------------------------------------------------------
        # MANUFACTURER DATA
        # ---------------------------------------------------------
        mfg_data = metadata.get("manufacturer_data")

        if isinstance(mfg_data, dict):

            sig["manufacturer_data"] = mfg_data

            # Extract vendor hint
            vendor = mfg_data.get("company")

            if vendor:
                sig["vendor"] = sig.get("vendor") or vendor
                sig["identity_source"] = "ble_manufacturer_data"

        # ---------------------------------------------------------
        # TX POWER
        # ---------------------------------------------------------
        tx_power = metadata.get("tx_power")

        if tx_power is not None:
            sig["tx_power"] = tx_power

        # ---------------------------------------------------------
        # ADV TYPE
        # ---------------------------------------------------------
        adv_type = metadata.get("adv_type")

        if adv_type:
            sig["ble_adv_type"] = adv_type

        return sig
