from __future__ import annotations

import requests
import pytest

from ui.api_client import ApiClient, ApiClientError


class FakeResponse:
    def __init__(self, payload=None, status_code=200, json_error=None):
        self._payload = payload
        self.status_code = status_code
        self._json_error = json_error

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._payload


def test_successful_health_request(monkeypatch):
    monkeypatch.setattr(
        requests,
        "request",
        lambda *args, **kwargs: FakeResponse(
            {"status": "ok", "adaptive_memory_documents": 3}
        ),
    )
    assert ApiClient("http://api").get_health()["status"] == "ok"


def test_health_connection_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.ConnectionError()

    monkeypatch.setattr(requests, "request", fail)
    with pytest.raises(ApiClientError, match="not running"):
        ApiClient("http://api").get_health()


def test_successful_detection(monkeypatch):
    monkeypatch.setattr(
        requests,
        "request",
        lambda *args, **kwargs: FakeResponse(
            {"classification": "PHISHING", "gemini_used": False}
        ),
    )
    result = ApiClient("http://api").detect_message(
        message_id="message-1",
        channel="EMAIL",
        body="Synthetic message",
    )
    assert result["classification"] == "PHISHING"
    assert result["gemini_used"] is False


def test_detection_http_error(monkeypatch):
    monkeypatch.setattr(
        requests,
        "request",
        lambda *args, **kwargs: FakeResponse(
            {"detail": "bad request"},
            status_code=400,
        ),
    )
    with pytest.raises(ApiClientError, match="HTTP 400"):
        ApiClient("http://api").detect_message(
            message_id="message-1",
            channel="EMAIL",
            body="Synthetic message",
        )


def test_detection_timeout(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(requests, "request", fail)
    with pytest.raises(ApiClientError, match="timed out"):
        ApiClient("http://api").detect_message(
            message_id="message-1",
            channel="EMAIL",
            body="Synthetic message",
        )


def test_successful_feedback(monkeypatch):
    monkeypatch.setattr(
        requests,
        "request",
        lambda *args, **kwargs: FakeResponse(
            {"knowledge_updated": True, "adaptive_memory_documents": 4}
        ),
    )
    result = ApiClient("http://api").submit_feedback(
        message_id="message-1",
        feedback_type="confirmed_phishing",
        corrected_label="phishing",
        channel="EMAIL",
        body="Synthetic message",
    )
    assert result["knowledge_updated"] is True
    assert result["adaptive_memory_documents"] == 4


def test_feedback_http_error(monkeypatch):
    monkeypatch.setattr(
        requests,
        "request",
        lambda *args, **kwargs: FakeResponse(
            {"detail": "invalid feedback"},
            status_code=422,
        ),
    )
    with pytest.raises(ApiClientError, match="HTTP 422"):
        ApiClient("http://api").submit_feedback(
            message_id="message-1",
            feedback_type="confirmed_phishing",
            corrected_label="phishing",
            channel="EMAIL",
            body="Synthetic message",
        )


def test_malformed_api_response(monkeypatch):
    monkeypatch.setattr(
        requests,
        "request",
        lambda *args, **kwargs: FakeResponse(["unexpected"]),
    )
    with pytest.raises(ApiClientError, match="response shape"):
        ApiClient("http://api").get_health()
