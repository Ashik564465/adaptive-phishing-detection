from __future__ import annotations

from dataclasses import dataclass
import logging

import httpx
from google.genai import errors as genai_errors
from google.genai._gaos.lib import compat_errors as genai_compat_errors

from src.rag.context_builder import ThreatContext


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GeminiReasoningResult:
    context_relevance: float
    historical_phishing_evidence: int
    historical_legitimate_evidence: int
    reasoning: str
    confidence: float
    gemini_used: bool = False


class GeminiAdapter:
    """
    Adapter boundary for Gemini-based contextual reasoning.

    Gemini does not replace the primary Transformer classifier.
    It receives structured historical threat context and produces
    contextual reasoning that can later be consumed by risk fusion.
    """

    def __init__(self, provider=None):
        self.provider = provider

    def analyze(self, context: ThreatContext) -> GeminiReasoningResult:
        if self.provider is None:
            return self._local_fallback(context)

        try:
            result = self.provider.analyze(context)
        except (
            genai_compat_errors.GeminiNextGenAPIClientError,
            genai_errors.UnknownApiResponseError,
            httpx.HTTPError,
            ConnectionError,
            OSError,
            TimeoutError,
            ValueError,
        ) as error:
            logger.warning(
                "Gemini provider unavailable; using local fallback (%s).",
                type(error).__name__,
            )
            return self._local_fallback(context)

        if not isinstance(result, GeminiReasoningResult):
            raise TypeError(
                "Gemini provider must return GeminiReasoningResult."
            )

        return GeminiReasoningResult(
            context_relevance=result.context_relevance,
            historical_phishing_evidence=(
                result.historical_phishing_evidence
            ),
            historical_legitimate_evidence=(
                result.historical_legitimate_evidence
            ),
            reasoning=result.reasoning,
            confidence=result.confidence,
            gemini_used=True,
        )

    @staticmethod
    def _local_fallback(
        context: ThreatContext,
    ) -> GeminiReasoningResult:
        """
        Deterministic fallback used during local development.

        This does not call Gemini and does not perform independent
        phishing classification.
        """

        if context.retrieved_count == 0:
            return GeminiReasoningResult(
                context_relevance=0.0,
                historical_phishing_evidence=0,
                historical_legitimate_evidence=0,
                reasoning="No historical threat context was retrieved.",
                confidence=0.0,
                gemini_used=False,
            )

        return GeminiReasoningResult(
            context_relevance=min(
                max(context.average_similarity, 0.0),
                1.0,
            ),
            historical_phishing_evidence=(
                context.similar_phishing_count
            ),
            historical_legitimate_evidence=(
                context.similar_legitimate_count
            ),
            reasoning=(
                "Historical messages were retrieved and summarized "
                "for contextual reasoning."
            ),
            confidence=min(
                max(context.average_similarity, 0.0),
                1.0,
            ),
            gemini_used=False,
        )