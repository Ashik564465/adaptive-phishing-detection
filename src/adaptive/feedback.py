from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


VALID_FEEDBACK_TYPES = {
    "confirmed_phishing",
    "confirmed_legitimate",
    "incorrect_prediction",
    "unknown",
}


@dataclass(frozen=True)
class FeedbackRecord:
    message_id: str
    feedback_type: str
    corrected_label: str | None
    source: str
    timestamp: str


def create_feedback_record(
    message_id: str,
    feedback_type: str,
    source: str,
    corrected_label: str | None = None,
    timestamp: str | None = None,
) -> FeedbackRecord:
    if not message_id.strip():
        raise ValueError("message_id cannot be empty.")

    if feedback_type not in VALID_FEEDBACK_TYPES:
        raise ValueError(
            f"Unsupported feedback type: {feedback_type}"
        )

    if not source.strip():
        raise ValueError("source cannot be empty.")

    if corrected_label is not None:
        if corrected_label not in {
            "phishing",
            "legitimate",
        }:
            raise ValueError(
                "corrected_label must be phishing or legitimate."
            )

    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    return FeedbackRecord(
        message_id=message_id,
        feedback_type=feedback_type,
        corrected_label=corrected_label,
        source=source,
        timestamp=timestamp,
    )