from src.layer1_identity.email_authentication import (
    parse_eml_text,
)

from src.layer1_identity.email_identity_features import (
    build_identity_features,
)

from src.layer1_identity.identity_scorer import (
    score_email_identity,
)

from src.layer1_identity.sms_sender_features import (
    build_sms_sender_features,
)


def test_missing_authentication_is_unknown():

    result = parse_eml_text(
        """
From: Example User <user@example.com>
To: victim@example.com
Subject: Test

Hello.
"""
    )

    assert result.spf == "unknown"
    assert result.dkim == "unknown"
    assert result.dmarc == "unknown"


def test_authentication_results_are_parsed():

    result = parse_eml_text(
        """
From: Example User <user@example.com>
Reply-To: user@example.com
Return-Path: <user@example.com>
Authentication-Results: mx.example;
    spf=pass;
    dkim=pass;
    dmarc=pass

Subject: Test

Hello.
"""
    )

    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"


def test_reply_to_mismatch_is_detected():

    result = parse_eml_text(
        """
From: Example User <user@example.com>
Reply-To: attacker@evil.example
Subject: Test

Hello.
"""
    )

    assert (
        result.from_reply_to_consistent
        == "fail"
    )


def test_identity_risk_increases_for_failures():

    result = parse_eml_text(
        """
From: Example User <user@example.com>
Reply-To: attacker@evil.example
Authentication-Results: mx.example;
    spf=fail;
    dkim=fail;
    dmarc=fail

Subject: Test

Hello.
"""
    )

    features = build_identity_features(
        result
    )

    risk = score_email_identity(
        features
    )

    assert risk.evidence_available is True
    assert risk.risk_score > 0
    assert len(risk.reasons) > 0


def test_sms_without_metadata_is_unknown():

    features = build_sms_sender_features()

    assert features.sender_available == 0
    assert features.sender_known is None
    assert features.sender_history_available == 0
    assert features.sender_reputation_available == 0