from dataclasses import dataclass
import math
import os


@dataclass(frozen=True)
class RiskPolicy:
    """Provisional raw-score thresholds; not calibrated probability cutoffs."""

    ml_review_threshold: float = 0.85
    ml_strong_threshold: float = 0.95
    ml_benign_threshold: float = 0.15

    @classmethod
    def from_environment(cls) -> "RiskPolicy":
        values = {
            "ml_review_threshold": os.getenv(
                "RISK_ML_REVIEW_THRESHOLD",
                "0.85",
            ),
            "ml_strong_threshold": os.getenv(
                "RISK_ML_STRONG_THRESHOLD",
                "0.95",
            ),
            "ml_benign_threshold": os.getenv(
                "RISK_ML_BENIGN_THRESHOLD",
                "0.15",
            ),
        }
        try:
            parsed = {
                name: float(value)
                for name, value in values.items()
            }
        except ValueError as exc:
            raise ValueError(
                "Risk ML thresholds must be numeric values in [0, 1]"
            ) from exc
        if any(
            not math.isfinite(value) or not 0.0 <= value <= 1.0
            for value in parsed.values()
        ):
            raise ValueError(
                "Risk ML thresholds must be finite values in [0, 1]"
            )
        if (
            parsed["ml_benign_threshold"]
            >= parsed["ml_review_threshold"]
            or parsed["ml_review_threshold"]
            > parsed["ml_strong_threshold"]
        ):
            raise ValueError(
                "Risk thresholds must satisfy benign < review <= strong"
            )
        return cls(**parsed)


DEFAULT_RISK_POLICY = RiskPolicy.from_environment()
