import pytest

from src.rag.gemini_provider import GeminiProvider


def test_gemini_provider_accepts_environment_key():
    provider = GeminiProvider(
        model_name="gemini-3.6-flash",
    )

    assert provider.api_key
    assert provider.model_name == "gemini-3.6-flash"


def test_gemini_provider_accepts_explicit_key():
    provider = GeminiProvider(
        api_key="test-key",
        model_name="gemini-3.6-flash",
    )

    assert provider.model_name == "gemini-3.6-flash"
    assert provider.api_key == "test-key"


def test_gemini_provider_rejects_missing_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    # Explicitly pass an empty key so the environment cannot provide one.
    with pytest.raises(ValueError):
        GeminiProvider(api_key="")