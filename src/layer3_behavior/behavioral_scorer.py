from __future__ import annotations

from dataclasses import dataclass

from src.layer3_behavior.behavioral_features import BehavioralFeatures
from src.layer3_behavior.anomaly_detector import TemporalAnomalyResult
from src.layer3_behavior.campaign_similarity import SimilarityResult


@dataclass(frozen=True)
class BehavioralRiskResult:
    risk_score: float
    reasons: list[str]


def calculate_behavioral_risk(
    features: BehavioralFeatures,
    temporal: TemporalAnomalyResult | None = None,
    similarity: SimilarityResult | None = None,
) -> BehavioralRiskResult:
    """
    Convert Layer 3 behavioral evidence into a normalized 0-1 risk score.

    These are initial engineering weights, not scientifically optimized
    weights. They should be calibrated later using validation data.
    """

    score = 0.0
    reasons: list[str] = []

    # Unknown sender
    if not features.sender_known:
        score += 0.25
        reasons.append("Sender is unknown in historical communication data.")

    # Sender has historical phishing activity
    if features.sender_known and features.sender_phishing_rate > 0:
        contribution = min(
            features.sender_phishing_rate * 0.30,
            0.30,
        )
        score += contribution
        reasons.append(
            "Sender has historical phishing-associated activity."
        )

    # New sender-recipient relationship
    if features.relationship_novelty:
        score += 0.20
        reasons.append(
            "Sender-recipient relationship is historically novel."
        )

    # Existing relationship with phishing history
    if (
        features.relationship_known
        and features.relationship_phishing_rate > 0
    ):
        contribution = min(
            features.relationship_phishing_rate * 0.15,
            0.15,
        )
        score += contribution
        reasons.append(
            "This communication relationship has historical phishing activity."
        )

    # Temporal anomaly
    if temporal is not None and temporal.available and temporal.anomaly:
        score += 0.10
        reasons.append(
            "Message arrived at an unusual time for this sender."
        )

    # Historical message similarity
    if similarity is not None and similarity.available:
        if similarity.max_similarity >= similarity.threshold:
            score += 0.10
            reasons.append(
                "Message is highly similar to historical messages."
            )

    score = max(0.0, min(1.0, score))

    return BehavioralRiskResult(
        risk_score=score,
        reasons=reasons,
    )