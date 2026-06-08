from backend.integrations.wifi_mk7.mk7_controller import WiFiMK7Controller


def test_camera_packet_limit_reduces_packet_budget_for_oversized_capture():
    limit = WiFiMK7Controller._camera_packet_limit(
        packet_count=1000,
        file_size_bytes=40 * 1024 * 1024,
        max_bytes=20 * 1024 * 1024,
    )

    assert 0 < limit < 1000


def test_camera_packet_summary_marks_stream_like_media():
    summary = WiFiMK7Controller._camera_packet_summary_from_rows(
        [
            {
                "timestamp": "1.0",
                "frame_len": "1200",
                "protocols": "eth:ip:tcp:rtsp",
                "ip_src": "192.168.1.50",
                "ip_dst": "52.1.1.1",
                "tcp_srcport": "554",
                "tcp_dstport": "49152",
                "udp_srcport": "",
                "udp_dstport": "",
                "dns_name": "",
                "tls_sni": "",
                "http_host": "",
                "rtsp_url": "rtsp://192.168.1.50:554/Streaming/Channels/101",
            },
            {
                "timestamp": "2.0",
                "frame_len": "1400",
                "protocols": "eth:ip:udp:rtp:h264",
                "ip_src": "192.168.1.50",
                "ip_dst": "52.1.1.1",
                "tcp_srcport": "",
                "tcp_dstport": "",
                "udp_srcport": "5004",
                "udp_dstport": "5004",
                "dns_name": "",
                "tls_sni": "",
                "http_host": "",
                "rtsp_url": "",
            },
        ],
        "192.168.1.50",
    )

    assert summary["stream_detected"] is True
    assert summary["assessment"] == "stream_like_media_detected"
    assert "rtsp" in summary["protocols_seen"]
    assert 554 in summary["ports_seen"]
