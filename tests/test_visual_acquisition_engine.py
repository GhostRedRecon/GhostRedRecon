from backend.integrations.wifi_mk7.visual_acquisition_engine import VisualAcquisitionEngine


def test_visual_acquisition_marks_visual_proof_recovered_from_snapshot():
    engine = VisualAcquisitionEngine()
    lead = {
        "vendor": "Generic Camera",
        "video_evidence": {
            "local_stream_available": "yes",
            "artifact_possible": "yes",
        },
    }
    active_probe = {
        "summary": {"snapshot_hits": 1, "onvif_hits": 1, "rtsp_hits": 0},
        "probes": [
            {
                "ip": "192.168.0.50",
                "snapshot": {
                    "findings": [
                        {
                            "saved_path": "/tmp/camera.jpg",
                            "scheme": "http",
                            "path": "/snapshot.jpg",
                        }
                    ]
                },
                "rtsp": {},
            }
        ],
    }
    hard_audit = {
        "camera_packet_evidence": {},
        "decrypt_followup": {},
        "video_truth": {},
        "decode_constraints": {},
        "xiaomi_cloud_capture": {},
    }
    validation_report = {"evidence": {"protocol": [], "exposure": []}}

    result = engine.run(
        lead=lead,
        active_probe=active_probe,
        hard_audit=hard_audit,
        validation_report=validation_report,
        analysis={},
    )

    assert result["outcome_class"] == "visual_proof_recovered"
    assert result["inputs"]["onvif_snapshot"]["status"] in {"recovered", "available"}
    assert result["evidence_policy"]["counts"]["visual_evidence"] == 1


def test_visual_acquisition_marks_encrypted_cloud_relay_for_xiaomi_family():
    engine = VisualAcquisitionEngine()
    lead = {
        "vendor": "Zhen Shi Information Technology (Shanghai) Co., Ltd.",
        "camera_detection": {"family_match": "xiaomi_mi_imilab_mijia"},
        "video_evidence": {
            "cloud_stream_detected": "yes",
            "artifact_possible": "no",
            "artifact_reason": "ENCRYPTED_CLOUD_TRANSPORT",
            "correlation": {"summary": "Live view triggered camera uplink spike."},
        },
    }
    active_probe = {"summary": {"snapshot_hits": 0, "onvif_hits": 0, "rtsp_hits": 0}, "probes": []}
    hard_audit = {
        "camera_packet_evidence": {
            "ok": True,
            "target_ip": "192.168.0.29",
            "pcapng_path": "/tmp/camera.pcapng",
            "pcap_path": "/tmp/camera.pcap",
            "summary_path": "/tmp/camera.json",
            "packet_count": 48,
            "file_size_bytes": 4096,
            "summary": {"assessment": "encrypted_camera_relay_likely"},
        },
        "decrypt_followup": {},
        "video_truth": {},
        "decode_constraints": {"likely_cloud_relay": True, "summary": "Cloud relay blocks passive decode."},
        "xiaomi_cloud_capture": {"matched": True, "likely_cloud_relay": True, "summary": "Xiaomi live view is cloud-relayed."},
    }
    validation_report = {"evidence": {"protocol": [], "exposure": []}}

    result = engine.run(
        lead=lead,
        active_probe=active_probe,
        hard_audit=hard_audit,
        validation_report=validation_report,
        analysis={},
    )

    assert result["outcome_class"] == "encrypted_cloud_relay_only"
    assert result["vendor_profile"]["plugin_id"] == "xiaomi"
    assert result["inputs"]["webrtc_hls_bridge"]["status"] == "candidate"
    assert result["evidence_policy"]["counts"]["packet_evidence"] >= 1
    assert result["evidence_policy"]["counts"]["owner_assisted_evidence"] >= 1


def test_visual_acquisition_marks_stream_path_recovered_but_decode_blocked():
    engine = VisualAcquisitionEngine()
    lead = {
        "vendor": "Reolink",
        "camera_detection": {"family_match": "reolink"},
        "video_evidence": {
            "local_stream_available": "yes",
            "artifact_possible": "yes",
            "artifact_reason": "RTSP available",
        },
    }
    active_probe = {
        "summary": {"snapshot_hits": 0, "onvif_hits": 0, "rtsp_hits": 1},
        "probes": [{"ip": "192.168.0.91", "rtsp": {"ok": True, "status_line": "RTSP/1.0 200 OK"}, "snapshot": {}}],
    }
    hard_audit = {
        "camera_packet_evidence": {},
        "decrypt_followup": {},
        "video_truth": {},
        "decode_constraints": {},
        "xiaomi_cloud_capture": {},
        "pipeline": {"artifact_decision": {"artifact_possible": True, "reason": "RTSP available"}},
    }
    validation_report = {"evidence": {"protocol": [], "exposure": []}}

    result = engine.run(
        lead=lead,
        active_probe=active_probe,
        hard_audit=hard_audit,
        validation_report=validation_report,
        analysis={},
    )

    assert result["outcome_class"] == "stream_path_recovered_but_decode_blocked"
    assert result["vendor_profile"]["plugin_id"] == "reolink"
    assert result["inputs"]["rtsp"]["status"] == "available"
