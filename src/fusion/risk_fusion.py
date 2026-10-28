from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskFusionInput:
    """
    Evidence supplied by the detection layers.
    """

    nlp_phishing_probability: float
    identity_risk: float
    behavioral_risk: float
    historical_risk: float


@dataclass(frozen=True)
class RiskFusionResult:
    """
    Final fused phishing risk.
    """

    risk_score: float
    classification: str


class RiskFusion:
    """
    Combines independent detection-layer evidence.

    Default weights are the initial engineering configuration.

    Calibrated weights can be supplied explicitly after
    validation-based calibration.
    """

    NLP_WEIGHT = 0.50
    IDENTITY_WEIGHT = 0.20
    BEHAVIORAL_WEIGHT = 0.20
    HISTORICAL_WEIGHT = 0.10

    def __init__(
        self,
        suspicious_threshold: float = 40.0,
        phishing_threshold: float = 70.0,
        nlp_weight: float | None = None,
        identity_weight: float | None = None,
        behavioral_weight: float | None = None,
        historical_weight: float | None = None,
    ):
        if not 0 <= suspicious_threshold <= 100:
            raise ValueError(
                "suspicious_threshold must be between 0 and 100."
            )

        if not 0 <= phishing_threshold <= 100:
            raise ValueError(
                "phishing_threshold must be between 0 and 100."
            )

        if suspicious_threshold >= phishing_threshold:
            raise ValueError(
                "suspicious_threshold must be lower than "
                "phishing_threshold."
            )

        weights = {
            "nlp": (
                self.NLP_WEIGHT
                if nlp_weight is None
                else nlp_weight
            ),
            "identity": (
                self.IDENTITY_WEIGHT
                if identity_weight is None
                else identity_weight
            ),
            "behavioral": (
                self.BEHAVIORAL_WEIGHT
                if behavioral_weight is None
                else behavioral_weight
            ),
            "historical": (
                self.HISTORICAL_WEIGHT
                if historical_weight is None
                else historical_weight
            ),
        }

        for name, value in weights.items():

            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name}_weight must be between 0.0 and 1.0."
                )

        total_weight = sum(
            weights.values()
        )

        if not abs(total_weight - 1.0) <= 1e-9:
            raise ValueError(
                "Fusion weights must sum to 1.0."
            )

        self.nlp_weight = weights["nlp"]
        self.identity_weight = weights["identity"]
        self.behavioral_weight = weights["behavioral"]
        self.historical_weight = weights["historical"]

        self.suspicious_threshold = (
            suspicious_threshold
        )

        self.phishing_threshold = (
            phishing_threshold
        )

    @staticmethod
    def _validate_score(
        value: float,
        name: str,
    ) -> None:

        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"{name} must be between 0.0 and 1.0."
            )

    def fuse(
        self,
        evidence: RiskFusionInput,
    ) -> RiskFusionResult:

        self._validate_score(
            evidence.nlp_phishing_probability,
            "nlp_phishing_probability",
        )

        self._validate_score(
            evidence.identity_risk,
            "identity_risk",
        )

        self._validate_score(
            evidence.behavioral_risk,
            "behavioral_risk",
        )

        self._validate_score(
            evidence.historical_risk,
            "historical_risk",
        )

        normalized_score = (
            evidence.nlp_phishing_probability
            * self.nlp_weight
            + evidence.identity_risk
            * self.identity_weight
            + evidence.behavioral_risk
            * self.behavioral_weight
            + evidence.historical_risk
            * self.historical_weight
        )

        risk_score = round(
            normalized_score * 100.0,
            2,
        )

        if (
            risk_score
            >= self.phishing_threshold
        ):

            classification = "PHISHING"

        elif (
            risk_score
            >= self.suspicious_threshold
        ):

            classification = "SUSPICIOUS"

        else:

            classification = "SAFE"

        return RiskFusionResult(
            risk_score=risk_score,
            classification=classification,
        )