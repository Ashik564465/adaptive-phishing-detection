from __future__ import annotations

from dataclasses import dataclass

from src.fusion.risk_explanation import (
    RiskExplanation,
    build_risk_explanation,
)
from src.fusion.risk_fusion import (
    RiskFusion,
    RiskFusionInput,
)
from src.rag.context_builder import (
    ThreatContext,
    build_threat_context,
)
from src.rag.gemini_adapter import (
    GeminiAdapter,
)


@dataclass(frozen=True)
class DetectionResult:
    message_id: str
    channel: str
    phishing_probability: float
    identity_risk: float
    behavioral_risk: float
    historical_risk: float
    risk_score: float
    classification: str
    explanation: RiskExplanation
    retrieved_threat_count: int
    gemini_used: bool


class DetectionPipeline:
    """
    End-to-end phishing detection orchestrator.

    This class coordinates the outputs of the detection layers.
    Individual models remain independently testable.

    Missing metadata is represented as unavailable evidence rather
    than fabricated values.
    """

    def __init__(
        self,
        risk_fusion: RiskFusion,
        gemini_adapter: GeminiAdapter | None = None,
    ):
        self.risk_fusion = risk_fusion
        self.gemini_adapter = gemini_adapter

    def detect(
        self,
        message_id: str,
        channel: str,
        phishing_probability: float,
        identity_risk: float = 0.0,
        behavioral_risk: float = 0.0,
        threat_context: ThreatContext | None = None,
    ) -> DetectionResult:

        channel = channel.upper()

        if channel not in {"EMAIL", "SMS"}:
            raise ValueError(
                "channel must be EMAIL or SMS."
            )

        if not message_id.strip():
            raise ValueError(
                "message_id cannot be empty."
            )

        self._validate_probability(
            phishing_probability,
            "phishing_probability",
        )

        self._validate_probability(
            identity_risk,
            "identity_risk",
        )

        self._validate_probability(
            behavioral_risk,
            "behavioral_risk",
        )

        if threat_context is None:
            threat_context = build_threat_context(
                query_channel=channel,
                retrieved_threats=[],
            )

        historical_risk = self._calculate_historical_risk(
            threat_context
        )

        gemini_used = False

        if (
            self.gemini_adapter is not None
            and threat_context.retrieved_count > 0
        ):
            gemini_result = self.gemini_adapter.analyze(
                threat_context
            )

            historical_risk = self._combine_historical_evidence(
                historical_risk=historical_risk,
                gemini_result=gemini_result,
                context=threat_context,
            )

            gemini_used = gemini_result.gemini_used

        fusion_input = RiskFusionInput(
            nlp_phishing_probability=phishing_probability,
            identity_risk=identity_risk,
            behavioral_risk=behavioral_risk,
            historical_risk=historical_risk,
        )

        fusion_result = self.risk_fusion.fuse(
            fusion_input
        )

        explanation = build_risk_explanation(
            fusion_input,
            fusion_result,
        )

        return DetectionResult(
            message_id=message_id,
            channel=channel,
            phishing_probability=phishing_probability,
            identity_risk=identity_risk,
            behavioral_risk=behavioral_risk,
            historical_risk=historical_risk,
            risk_score=fusion_result.risk_score,
            classification=fusion_result.classification,
            explanation=explanation,
            retrieved_threat_count=(
                threat_context.retrieved_count
            ),
            gemini_used=gemini_used,
        )

    @staticmethod
    def _calculate_historical_risk(
        context: ThreatContext,
    ) -> float:
        """
        Calculate phishing risk from retrieved historical evidence.

        Legitimate-only evidence contributes zero phishing risk.

        Mixed evidence is weighted by:
            phishing evidence proportion × similarity.

        This prevents legitimate historical messages from becoming
        a positive phishing signal.
        """

        if context.retrieved_count == 0:
            return 0.0

        total = (
            context.similar_phishing_count
            + context.similar_legitimate_count
        )

        if total == 0:
            return 0.0

        phishing_ratio = (
            context.similar_phishing_count / total
        )

        # Legitimate-only historical evidence must not
        # produce phishing risk.
        if phishing_ratio == 0.0:
            return 0.0

        similarity = max(
            0.0,
            min(1.0, context.average_similarity),
        )

        historical_risk = (
            phishing_ratio * similarity
        )

        return max(
            0.0,
            min(1.0, historical_risk),
        )

    @staticmethod
    def _combine_historical_evidence(
        historical_risk: float,
        gemini_result,
        context: ThreatContext,
    ) -> float:
        """
        Combine retrieval evidence with Gemini contextual reasoning.

        Gemini can strengthen evidence that is already supported by
        retrieved phishing examples.

        Gemini cannot turn legitimate-only retrieved evidence into
        phishing risk.
        """

        if context.retrieved_count == 0:
            return 0.0

        total = (
            context.similar_phishing_count
            + context.similar_legitimate_count
        )

        if total == 0:
            return 0.0

        # If there are no retrieved phishing examples, there is no
        # historical phishing signal to strengthen.
        if context.similar_phishing_count == 0:
            return 0.0

        phishing_ratio = (
            context.similar_phishing_count / total
        )

        gemini_signal = (
            gemini_result.context_relevance
            * gemini_result.confidence
            * phishing_ratio
        )

        combined = (
            historical_risk + gemini_signal
        ) / 2.0

        return max(
            0.0,
            min(1.0, combined),
        )

    @staticmethod
    def _validate_probability(
        value: float,
        field_name: str,
    ) -> None:
        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"{field_name} must be between 0.0 and 1.0."
            )