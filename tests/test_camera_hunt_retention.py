from backend.integrations.wifi_mk7.pipeline_controller import WiFiCameraPipelineController


def test_retains_cloud_camera_client_family_near_threshold():
    retained = WiFiCameraPipelineController._should_retain_camera_lead(
        lead_kind="client",
        score=44.0,
        camera={
            "detected": False,
            "vendor_role_state": "vendor_family_plus_cloud_camera",
            "family_match": "xiaomi_mi_imilab_mijia",
            "vendor_family": "xiaomi_mi_imilab_mijia",
        },
        item={"service_exposure": {"protocols": ["TLS", "HTTP"]}},
        role_duel={"winner_role": "camera", "margin": 10.0},
    )

    assert retained is True


def test_retains_xiaomi_cloud_camera_client_before_role_converges():
    retained = WiFiCameraPipelineController._should_retain_camera_lead(
        lead_kind="client",
        score=35.0,
        camera={
            "detected": False,
            "vendor_role_state": "vendor_family_plus_cloud_camera",
            "family_match": "xiaomi_mi_imilab_mijia",
            "vendor_family": "xiaomi_mi_imilab_mijia",
        },
        item={"service_exposure": {"protocols": ["TLS", "HTTP"]}},
        role_duel={"winner_role": "client", "margin": 4.0},
    )

    assert retained is True


def test_retains_associated_cloud_camera_client_at_lower_score():
    retained = WiFiCameraPipelineController._should_retain_camera_lead(
        lead_kind="client",
        score=29.0,
        camera={
            "detected": False,
            "vendor_role_state": "vendor_family_plus_cloud_camera",
            "family_match": "xiaomi_mi_imilab_mijia",
            "vendor_family": "xiaomi_mi_imilab_mijia",
        },
        item={
            "associated_bssid": "aa:bb:cc:dd:ee:ff",
            "service_exposure": {"protocols": ["TLS", "DNS"]},
        },
        role_duel={"winner_role": "client", "margin": 2.0},
    )

    assert retained is True


def test_drops_router_network_without_local_camera_discriminator():
    retained = WiFiCameraPipelineController._should_retain_camera_lead(
        lead_kind="network",
        score=72.0,
        camera={
            "detected": True,
            "vendor_role_state": "unresolved",
            "family_match": "",
            "vendor_family": "",
        },
        item={"service_exposure": {"protocols": ["TLS", "HTTP"]}},
        role_duel={"winner_role": "router", "margin": 12.0},
    )

    assert retained is False


def test_supplements_airodump_client_for_zhen_shi_xiaomi_vendor(tmp_path):
    controller = WiFiCameraPipelineController(tmp_path)

    supplemental = controller._supplemental_airodump_clients(
        airodump_clients={
            "78:8b:2a:64:60:b9": {
                "mac": "78:8b:2a:64:60:b9",
                "bssid": "aa:bb:cc:dd:ee:ff",
                "power": "-54",
                "packets": "7",
            }
        },
        airodump_aps={"aa:bb:cc:dd:ee:ff": {"channel": "6"}},
        existing_client_macs=set(),
    )

    assert len(supplemental) == 1
    assert supplemental[0]["mac"] == "78:8b:2a:64:60:b9"
    assert supplemental[0]["vendor"] == "Zhen Shi Information Technology (Shanghai) Co., Ltd."
    assert supplemental[0]["channel"] == 6
    assert supplemental[0]["packet_count"] == 7


def test_supplements_neighbor_table_xiaomi_client(monkeypatch, tmp_path):
    controller = WiFiCameraPipelineController(tmp_path)
    monkeypatch.setattr(
        WiFiCameraPipelineController,
        "_neighbor_table_rows",
        staticmethod(lambda: [{"ip": "192.168.0.29", "mac": "78:8b:2a:64:60:b9", "source": "/proc/net/arp"}]),
    )

    supplemental = controller._supplemental_neighbor_clients(existing_client_macs=set())

    assert len(supplemental) == 1
    assert supplemental[0]["mac"] == "78:8b:2a:64:60:b9"
    assert supplemental[0]["ip_addresses"] == ["192.168.0.29"]
    assert supplemental[0]["service_exposure"]["exposures"] == ["local_neighbor_observed"]
    assert supplemental[0]["camera_detection"]["family_match"] == "xiaomi_mi_imilab_mijia"
    assert supplemental[0]["fingerprint"]["device_family"] == "camera"


def test_fused_neighbor_xiaomi_client_surfaces_as_camera_near_miss(monkeypatch, tmp_path):
    controller = WiFiCameraPipelineController(tmp_path)
    monkeypatch.setattr(
        WiFiCameraPipelineController,
        "_neighbor_table_rows",
        staticmethod(lambda: [{"ip": "192.168.0.29", "mac": "78:8b:2a:64:60:b9", "source": "/proc/net/arp"}]),
    )

    item = controller._supplemental_neighbor_clients(existing_client_macs=set())[0]
    fused = controller._fuse_item(item, "client", {}, {}, {}, {}, {}, {})

    assert fused is not None
    assert fused["camera_detection"]["family_match"] == "xiaomi_mi_imilab_mijia"
    assert fused["pipeline_score"] >= 25.0
    assert fused["camera_detection"]["retained"] is False
    assert controller._allow_camera_near_miss(fused) is True
