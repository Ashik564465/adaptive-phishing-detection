from __future__ import annotations

import httpx
import pytest

from src.rag.context_builder import build_threat_context
from src.rag.gemini_adapter import (
    GeminiAdapter,
    GeminiReasoningResult,
)


def _make_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://example.invalid/gemini")
    response = httpx.Response(status_code=status_code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {status_code}",
        request=request,
        response=response,
    )


def test_gemini_adapter_no_provider_uses_deterministic_fallback():
    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=[],
    )

    result = GeminiAdapter().analyze(context)

    assert isinstance(result, GeminiReasoningResult)
    assert result.context_relevance == 0.0
    assert result.historical_phishing_evidence == 0
    assert result.historical_legitimate_evidence == 0
    assert result.confidence == 0.0
    assert result.gemini_used is False


def test_gemini_adapter_uses_provider_result():
    class FakeProvider:
        def analyze(self, context):
            return GeminiReasoningResult(
                context_relevance=0.92,
                historical_phishing_evidence=3,
                historical_legitimate_evidence=1,
                reasoning="Historical phishing evidence is relevant.",
                confidence=0.90,
            )

    context = build_threat_context(
        query_channel="SMS",
        retrieved_threats=[],
    )

    result = GeminiAdapter(provider=FakeProvider()).analyze(context)

    assert result.context_relevance == 0.92
    assert result.historical_phishing_evidence == 3
    assert result.historical_legitimate_evidence == 1
    assert result.confidence == 0.90
    assert result.gemini_used is True


def test_gemini_adapter_rejects_invalid_provider_result():
    class BadProvider:
        def analyze(self, context):
            return {"confidence": 0.9}

    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=[],
    )

    adapter = GeminiAdapter(provider=BadProvider())

    with pytest.raises(TypeError, match="GeminiReasoningResult"):
        adapter.analyze(context)


@pytest.mark.parametrize(
    "error",
    [
        _make_http_status_error(429),
        _make_http_status_error(503),
        httpx.ReadTimeout("request timed out"),
        ConnectionError("network unavailable"),
        TimeoutError("request timed out"),
        ValueError("invalid response"),
    ],
)
def test_gemini_adapter_falls_back_for_provider_failures(error):
    class FailingProvider:
        def analyze(self, context):
            raise error

    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=[],
    )

    result = GeminiAdapter(provider=FailingProvider()).analyze(context)

    assert isinstance(result, GeminiReasoningResult)
    assert result.context_relevance == 0.0
    assert result.historical_phishing_evidence == 0
    assert result.historical_legitimate_evidence == 0
    assert result.confidence == 0.0
    assert result.gemini_used is False


def test_gemini_adapter_empty_context_fallback_is_safe():
    context = build_threat_context(
        query_channel="SMS",
        retrieved_threats=[],
    )

    result = GeminiAdapter().analyze(context)

    assert result.reasoning == "No historical threat context was retrieved."
    assert result.context_relevance == 0.0
    assert result.historical_phishing_evidence == 0
    assert result.historical_legitimate_evidence == 0
    assert result.confidence == 0.0
    assert result.gemini_used is False
