from __future__ import annotations

from typing import Any

import requests


class ApiClientError(RuntimeError):
    """Friendly error raised when the FastAPI backend cannot be used."""


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        try:
            response = requests.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                **kwargs,
            )
            response.raise_for_status()
        except requests.Timeout as error:
            raise ApiClientError(
                "The FastAPI backend timed out. Please try again."
            ) from error
        except requests.ConnectionError as error:
            raise ApiClientError(
                "FastAPI backend is not running. Start it with "
                "uvicorn src.api.main:app --reload --port 8000."
            ) from error
        except requests.HTTPError as error:
            status = error.response.status_code if error.response else "unknown"
            detail = ""
            try:
                payload = error.response.json()
                detail = str(payload.get("detail", "")).strip()
            except (ValueError, AttributeError):
                detail = ""
            suffix = f": {detail}" if detail else ""
            raise ApiClientError(
                f"FastAPI request failed with HTTP {status}{suffix}."
            ) from error
        except requests.RequestException as error:
            raise ApiClientError(
                "The FastAPI request could not be completed."
            ) from error

        try:
            payload = response.json()
        except ValueError as error:
            raise ApiClientError(
                "FastAPI returned a malformed JSON response."
            ) from error

        if not isinstance(payload, dict):
            raise ApiClientError(
                "FastAPI returned an unexpected response shape."
            )

        return payload

    def get_health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def detect_message(
        self,
        *,
        message_id: str,
        channel: str,
        body: str,
        subject: str = "",
        sender: str | None = None,
        receiver: str | None = None,
        timestamp: str | None = None,
        raw_email: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/detect",
            json={
                "message_id": message_id,
                "channel": channel,
                "body": body,
                "subject": subject,
                "sender": sender,
                "receiver": receiver,
                "timestamp": timestamp,
                "raw_email": raw_email,
            },
        )

    def submit_feedback(
        self,
        *,
        message_id: str,
        feedback_type: str,
        corrected_label: str | None,
        channel: str,
        body: str,
        subject: str = "",
        sender: str | None = None,
        receiver: str | None = None,
        source: str = "streamlit_ui",
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/feedback",
            json={
                "message_id": message_id,
                "feedback_type": feedback_type,
                "corrected_label": corrected_label,
                "source": source,
                "channel": channel,
                "body": body,
                "subject": subject,
                "sender": sender,
                "receiver": receiver,
            },
        )


def get_health(base_url: str, timeout: float = 30.0) -> dict[str, Any]:
    return ApiClient(base_url, timeout=timeout).get_health()


def detect_message(
    base_url: str,
    *,
    message_id: str,
    channel: str,
    body: str,
    subject: str = "",
    sender: str | None = None,
    receiver: str | None = None,
    timestamp: str | None = None,
    raw_email: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    return ApiClient(base_url, timeout=timeout).detect_message(
        message_id=message_id,
        channel=channel,
        body=body,
        subject=subject,
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        raw_email=raw_email,
    )


def submit_feedback(
    base_url: str,
    *,
    message_id: str,
    feedback_type: str,
    corrected_label: str | None,
    channel: str,
    body: str,
    subject: str = "",
    sender: str | None = None,
    receiver: str | None = None,
    source: str = "streamlit_ui",
    timeout: float = 30.0,
) -> dict[str, Any]:
    return ApiClient(base_url, timeout=timeout).submit_feedback(
        message_id=message_id,
        feedback_type=feedback_type,
        corrected_label=corrected_label,
        channel=channel,
        body=body,
        subject=subject,
        sender=sender,
        receiver=receiver,
        source=source,
    )
