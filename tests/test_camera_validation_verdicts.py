from backend.integrations.wifi_mk7.camera_validation_engine import CameraValidationEngine


def test_camera_validation_marks_unauthenticated_media_access_as_unsafe(tmp_path):
    engine = CameraValidationEngine(tmp_path)

    verdict = engine._build_verdict(
        {
            "authentication": [{"evidence_type": "unauthenticated_snapshot_access"}],
            "control_surface": [],
            "stream": [],
            "behavior": [],
            "negative": [],
            "inconclusive": [],
        }
    )

    assert verdict["classification"] == "unsafe"
    assert verdict["recommended_action"] == "isolate_shutdown_or_replace"
    assert verdict["audit_basis"] == "non_authenticated_exposure"
    assert "No login is required" in verdict["operator_guidance"]


def test_camera_validation_marks_pre_auth_management_exposure_as_weak_enforcement(tmp_path):
    engine = CameraValidationEngine(tmp_path)

    verdict = engine._build_verdict(
        {
            "authentication": [{"evidence_type": "onvif_pre_auth_response"}],
            "control_surface": [],
            "stream": [],
            "behavior": [],
            "negative": [],
            "inconclusive": [],
        }
    )

    assert verdict["classification"] == "weak_enforcement"
    assert verdict["recommended_action"] == "segment_disable_services_or_replace"
    assert verdict["audit_basis"] == "pre_auth_management_exposure"
    assert "Recommend isolation" in verdict["operator_guidance"]


def test_camera_validation_marks_high_cloud_leakage_as_privacy_risk(tmp_path):
    engine = CameraValidationEngine(tmp_path)

    verdict = engine._build_verdict(
        {
            "authentication": [],
            "control_surface": [],
            "stream": [],
            "behavior": [
                {
                    "evidence_type": "cloud_leakage_audit",
                    "risk_level": "HIGH",
                    "quality": "corroborated",
                }
            ],
            "negative": [],
            "inconclusive": [],
        }
    )

    assert verdict["classification"] == "privacy_risk"
    assert verdict["recommended_action"] == "segment_restrict_cloud_egress_or_replace"
    assert verdict["audit_basis"] == "cloud_metadata_or_plaintext_leakage"
