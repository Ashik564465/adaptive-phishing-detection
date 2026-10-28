from src.fusion.risk_fusion import (
    RiskFusion,
    RiskFusionInput,
)


def test_high_risk_message_is_phishing():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=0.95,
        identity_risk=0.90,
        behavioral_risk=0.85,
        historical_risk=0.90,
    )

    result = fusion.fuse(evidence)

    assert result.risk_score >= 70.0
    assert result.classification == "PHISHING"


def test_low_risk_message_is_safe():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=0.05,
        identity_risk=0.05,
        behavioral_risk=0.10,
        historical_risk=0.05,
    )

    result = fusion.fuse(evidence)

    assert result.risk_score < 40.0
    assert result.classification == "SAFE"


def test_medium_risk_message_is_suspicious():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=0.55,
        identity_risk=0.40,
        behavioral_risk=0.45,
        historical_risk=0.50,
    )

    result = fusion.fuse(evidence)

    assert 40.0 <= result.risk_score < 70.0
    assert result.classification == "SUSPICIOUS"


def test_invalid_probability_is_rejected():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=1.5,
        identity_risk=0.5,
        behavioral_risk=0.5,
        historical_risk=0.5,
    )

    try:
        fusion.fuse(evidence)
    except ValueError:
        return

    raise AssertionError(
        "Invalid probability should raise ValueError."
    )


def test_invalid_thresholds_are_rejected():
    try:
        RiskFusion(
            suspicious_threshold=80,
            phishing_threshold=70,
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid thresholds should raise ValueError."
    )