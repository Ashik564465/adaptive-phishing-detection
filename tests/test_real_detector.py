from src.pipeline.real_detector import (
    RealDetectionInput,
    RealPhishingDetector,
)


def test_real_detector_email_without_optional_layers():
    detector = RealPhishingDetector(
        sender_profiles=None,
        relationship_profiles=None,
    )

    message = RealDetectionInput(
        message_id="integration-email-001",
        channel="EMAIL",
        sender="sender@example.com",
        receiver="user@example.com",
        subject="Urgent account verification required",
        body=(
            "Your account requires immediate verification. "
            "Please verify your account to avoid suspension."
        ),
    )

    result = detector.detect(message)

    assert result.message_id == "integration-email-001"
    assert result.channel == "EMAIL"

    assert 0.0 <= result.phishing_probability <= 1.0
    assert result.identity_risk == 0.0
    assert result.behavioral_risk == 0.0
    assert result.historical_risk == 0.0

    assert 0.0 <= result.risk_score <= 100.0

    assert result.classification in {
        "SAFE",
        "SUSPICIOUS",
        "PHISHING",
    }


def test_real_detector_sms_without_metadata():
    detector = RealPhishingDetector(
        sender_profiles=None,
        relationship_profiles=None,
    )

    message = RealDetectionInput(
        message_id="integration-sms-001",
        channel="SMS",
        body=(
            "Team meeting is scheduled for tomorrow "
            "at 10 AM."
        ),
    )

    result = detector.detect(message)

    assert result.message_id == "integration-sms-001"
    assert result.channel == "SMS"

    assert 0.0 <= result.phishing_probability <= 1.0
    assert result.identity_risk == 0.0
    assert result.behavioral_risk == 0.0
    assert result.historical_risk == 0.0

    assert result.classification in {
        "SAFE",
        "SUSPICIOUS",
        "PHISHING",
    }