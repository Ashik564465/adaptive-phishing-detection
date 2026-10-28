from src.fusion.risk_explanation import build_risk_explanation
from src.fusion.risk_fusion import (
    RiskFusion,
    RiskFusionInput,
)


def test_high_risk_explanation_contains_multiple_reasons():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=0.95,
        identity_risk=0.90,
        behavioral_risk=0.85,
        historical_risk=0.90,
    )

    result = fusion.fuse(evidence)

    explanation = build_risk_explanation(
        evidence,
        result,
    )

    assert explanation.classification == "PHISHING"
    assert explanation.risk_score >= 70.0
    assert len(explanation.evidence) >= 4


def test_low_risk_explanation():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=0.05,
        identity_risk=0.05,
        behavioral_risk=0.10,
        historical_risk=0.05,
    )

    result = fusion.fuse(evidence)

    explanation = build_risk_explanation(
        evidence,
        result,
    )

    assert explanation.classification == "SAFE"
    assert explanation.risk_score < 40.0
    assert len(explanation.evidence) >= 1


def test_moderate_evidence_is_reported():
    fusion = RiskFusion()

    evidence = RiskFusionInput(
        nlp_phishing_probability=0.55,
        identity_risk=0.45,
        behavioral_risk=0.50,
        historical_risk=0.45,
    )

    result = fusion.fuse(evidence)

    explanation = build_risk_explanation(
        evidence,
        result,
    )

    assert explanation.classification == "SUSPICIOUS"
    assert any(
        "moderate" in reason.lower()
        for reason in explanation.evidence
    )