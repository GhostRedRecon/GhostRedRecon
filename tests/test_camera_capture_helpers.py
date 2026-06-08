from backend.integrations.wifi_mk7.active_fingerprint_engine import ActiveFingerprintEngine


def test_extract_visual_payload_carves_jpeg_from_multipart_stream():
    engine = ActiveFingerprintEngine(root_dir=None)
    jpeg = b"\xff\xd8\xff\xdbdemo-frame\xff\xd9"
    payload = (
        b"--frame\r\n"
        b"Content-Type: image/jpeg\r\n\r\n"
        + jpeg
        + b"\r\n--frame--\r\n"
    )

    extracted = engine._extract_visual_payload(payload, "multipart/x-mixed-replace; boundary=frame")

    assert extracted == jpeg


def test_rtsp_candidate_urls_prioritize_vendor_paths():
    engine = ActiveFingerprintEngine(root_dir=None)

    urls = engine._rtsp_candidate_urls(
        ip="192.168.1.40",
        port=554,
        matched_families=[{"family": "hikvision", "score": 10, "tokens": ["hikvision"]}],
        root_describe_ok=False,
    )

    assert urls[0] == "rtsp://192.168.1.40:554/Streaming/Channels/101"
    assert "rtsp://192.168.1.40:554/" in urls
