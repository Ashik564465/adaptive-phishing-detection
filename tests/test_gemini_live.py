import os

import httpx
import pytest
from google.genai import errors as genai_errors
from google.genai._gaos.lib import compat_errors as genai_compat_errors

from src.rag.context_builder import build_threat_context
from src.rag.gemini_adapter import (
    GeminiAdapter,
    GeminiReasoningResult,
)
from src.rag.gemini_provider import GeminiProvider
from src.rag.retriever import RetrievedThreat

@pytest.mark.skipif(
    os.getenv("RUN_LIVE_GEMINI") != "1",
    reason="Live Gemini API test disabled by default.",
)


def test_live_gemini_reasoning():
    threats = [
        RetrievedThreat(
            document_id="synthetic-phishing-001",
            channel="EMAIL",
            label="phishing",
            text="Your account requires immediate verification.",
            similarity=0.94,
            sender=None,
            receiver=None,
        ),
        RetrievedThreat(
            document_id="synthetic-legitimate-001",
            channel="EMAIL",
            label="legitimate",
            text="The team meeting is scheduled for tomorrow.",
            similarity=0.78,
            sender=None,
            receiver=None,
        ),
    ]

    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=threats,
    )

    try:
        provider = GeminiProvider()
        result = GeminiAdapter(provider=provider).analyze(context)
    except (
        genai_compat_errors.GeminiNextGenAPIClientError,
        genai_errors.UnknownApiResponseError,
        httpx.HTTPError,
        ConnectionError,
        OSError,
        TimeoutError,
        ValueError,
    ) as error:
        pytest.skip(
            "Live Gemini unavailable "
            f"({type(error).__name__})."
        )

    if not result.gemini_used:
        pytest.skip(
            "Live Gemini unavailable; adapter returned deterministic fallback."
        )

    assert isinstance(result, GeminiReasoningResult)

    assert 0.0 <= result.context_relevance <= 1.0
    assert 0.0 <= result.confidence <= 1.0

    assert result.historical_phishing_evidence >= 0
    assert result.historical_legitimate_evidence >= 0

    assert isinstance(result.reasoning, str)
    assert result.reasoning.strip()
    assert result.gemini_used is True

    print("\nGemini reasoning result:")
    print(result)