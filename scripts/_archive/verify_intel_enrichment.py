from backend.intel.signal_engine import SignalEngine
from backend.intel.correlation.multiband_correlation_engine import MultiBandCorrelationEngine


def main() -> None:
    try:
        from backend.intel.ble.ble_decoder_worker import BLEDecoderWorker

        ble = BLEDecoderWorker()
        ble.device_cache["AA:BB:CC:DD:EE:FF"] = {
            "vendor": "TestVendor",
            "device_name": "Beacon",
            "device_hint": "tracker",
            "manufacturer_id": "004C",
            "service_uuids": ["180D"],
            "channels": {37, 38},
            "first_seen": 1.0,
            "last_seen": 2.0,
            "seen_count": 3,
            "last_frequency_mhz": 2402.0,
            "last_rssi": -52,
        }
        snapshot = ble.get_device_snapshot(limit=1)
        assert snapshot and snapshot[0]["channels"] == [37, 38]
    except ModuleNotFoundError:
        pass

    signal = SignalEngine()
    signal.start()
    signal.update_signal(
        "sid-1",
        2437.0,
        -42.0,
        {"protocol": "WIFI", "rf_band": "wifi_2.4", "temporal_consistency": 0.8},
    )
    signal.update_signal(
        "sid-2",
        868.1,
        -83.0,
        {"protocol": "LORA", "rf_band": "subghz", "periodicity": 1.2, "burst_ratio": 0.7, "signal_type": "periodic"},
    )
    live = signal.get_live_signals(5)
    assert any(item.get("wifi_channel") == 6 for item in live)
    assert any(item.get("burst_recurrence_score", 0.0) > 0 for item in live)
    assert any(item.get("lora_role_hint") for item in live if item.get("protocol") == "LORA")

    correlation = MultiBandCorrelationEngine()
    entities = correlation.process(
        live,
        [
            {
                "device_id": "BLE-AA:BB:CC:DD:EE:FF",
                "protocols": ["BLE", "IOT"],
                "frequencies": [2402.0],
                "vendor": "TestVendor",
                "mac_address": "AA:BB:CC:DD:EE:FF",
            },
            {
                "device_id": "LORA-1",
                "protocols": ["LORA"],
                "frequencies": [868.1],
                "vendor": "TestVendor",
                "device_type": "Gateway",
            },
        ],
    )
    assert entities
    assert any(entity.get("cross_protocol") for entity in entities)

    print("verify_intel_enrichment: ok")


if __name__ == "__main__":
    main()
