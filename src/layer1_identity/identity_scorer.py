from __future__ import annotations

from dataclasses import dataclass

from src.layer1_identity.email_identity_features import (
    EmailIdentityFeatures,
)


@dataclass(frozen=True)
class IdentityRiskResult:
    risk_score: float
    evidence_available: bool
    reasons: tuple[str, ...]


def _add_reason(
    reasons: list[str],
    reason: str,
) -> None:

    if reason not in reasons:
        reasons.append(reason)


def score_email_identity(
    features: EmailIdentityFeatures,
) -> IdentityRiskResult:
    """
    Calculate an identity risk score from available
    authentication/header evidence.

    This is an interpretable Layer 1 score.
    It is NOT a trained machine-learning model.
    """

    score = 0.0
    reasons = []

    evidence_available = (
        features.authentication_available == 1
        or features.from_reply_to_mismatch
        is not None
        or features.from_return_path_mismatch
        is not None
        or features.display_name_anomaly
        is not None
    )

    # ---------------------------------------------------------
    # SPF
    # ---------------------------------------------------------

    if features.spf_fail == 1:

        score += 20

        _add_reason(
            reasons,
            "SPF authentication failed",
        )

    elif features.spf_pass == 1:

        score -= 5

    # ---------------------------------------------------------
    # DKIM
    # ---------------------------------------------------------

    if features.dkim_fail == 1:

        score += 20

        _add_reason(
            reasons,
            "DKIM authentication failed",
        )

    elif features.dkim_pass == 1:

        score -= 5

    # ---------------------------------------------------------
    # DMARC
    # ---------------------------------------------------------

    if features.dmarc_fail == 1:

        score += 25

        _add_reason(
            reasons,
            "DMARC authentication failed",
        )

    elif features.dmarc_pass == 1:

        score -= 10

    # ---------------------------------------------------------
    # From / Reply-To
    # ---------------------------------------------------------

    if (
        features.from_reply_to_mismatch
        == 1
    ):

        score += 15

        _add_reason(
            reasons,
            "From and Reply-To domains differ",
        )

    # ---------------------------------------------------------
    # From / Return-Path
    # ---------------------------------------------------------

    if (
        features.from_return_path_mismatch
        == 1
    ):

        score += 10

        _add_reason(
            reasons,
            "From and Return-Path domains differ",
        )

    # ---------------------------------------------------------
    # Display name
    # ---------------------------------------------------------

    if (
        features.display_name_anomaly
        == 1
    ):

        score += 10

        _add_reason(
            reasons,
            "Display-name consistency anomaly detected",
        )

    # ---------------------------------------------------------
    # Clamp score
    # ---------------------------------------------------------

    score = max(
        0.0,
        min(
            100.0,
            score,
        ),
    )

    return IdentityRiskResult(
        risk_score=round(
            score,
            2,
        ),
        evidence_available=(
            evidence_available
        ),
        reasons=tuple(
            reasons
        ),
    )


def identity_result_to_dict(
    result: IdentityRiskResult,
) -> dict:

    return {
        "identity_risk": result.risk_score,
        "identity_evidence_available": (
            result.evidence_available
        ),
        "identity_reasons": list(
            result.reasons
        ),
    }