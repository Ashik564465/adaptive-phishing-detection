from __future__ import annotations

from dataclasses import dataclass

from src.fusion.risk_fusion import (
    RiskFusionInput,
    RiskFusionResult,
)


@dataclass(frozen=True)
class RiskExplanation:
    classification: str
    risk_score: float
    evidence: list[str]


def build_risk_explanation(
    evidence: RiskFusionInput,
    result: RiskFusionResult,
) -> RiskExplanation:
    reasons: list[str] = []

    if evidence.nlp_phishing_probability >= 0.70:
        reasons.append(
            "Transformer NLP model detected strong phishing evidence."
        )
    elif evidence.nlp_phishing_probability >= 0.40:
        reasons.append(
            "Transformer NLP model detected moderate phishing evidence."
        )
    else:
        reasons.append(
            "Transformer NLP model detected limited phishing evidence."
        )

    if evidence.identity_risk >= 0.70:
        reasons.append(
            "Identity and authentication evidence indicates high risk."
        )
    elif evidence.identity_risk >= 0.40:
        reasons.append(
            "Identity and authentication evidence indicates moderate risk."
        )

    if evidence.behavioral_risk >= 0.70:
        reasons.append(
            "Behavioral analysis indicates strong anomalous activity."
        )
    elif evidence.behavioral_risk >= 0.40:
        reasons.append(
            "Behavioral analysis indicates moderate anomalous activity."
        )

    if evidence.historical_risk >= 0.70:
        reasons.append(
            "Historical threat memory contains strongly relevant evidence."
        )
    elif evidence.historical_risk >= 0.40:
        reasons.append(
            "Historical threat memory contains moderately relevant evidence."
        )

    return RiskExplanation(
        classification=result.classification,
        risk_score=result.risk_score,
        evidence=reasons,
    )