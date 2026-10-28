from __future__ import annotations

from dataclasses import dataclass

from src.adaptive.feedback import FeedbackRecord
from src.embeddings.document_chunker import (
    ThreatMemoryDocument,
    build_memory_document,
)


@dataclass(frozen=True)
class KnowledgeUpdate:
    accepted: bool
    document: ThreatMemoryDocument | None
    reason: str


def update_knowledge_from_feedback(
    feedback: FeedbackRecord,
    channel: str,
    text: str,
    sender: str | None = None,
    receiver: str | None = None,
) -> KnowledgeUpdate:
    """
    Convert validated feedback into a threat-memory document.

    Only feedback containing a confirmed/corrected label is added
    to the knowledge base.

    This function does not retrain the Transformer model.
    """

    if feedback.corrected_label is None:
        return KnowledgeUpdate(
            accepted=False,
            document=None,
            reason="Feedback does not contain a validated label.",
        )

    if feedback.feedback_type not in {
        "confirmed_phishing",
        "confirmed_legitimate",
        "incorrect_prediction",
    }:
        return KnowledgeUpdate(
            accepted=False,
            document=None,
            reason="Feedback type is not eligible for knowledge update.",
        )

    document = build_memory_document(
        message_id=feedback.message_id,
        channel=channel,
        label=feedback.corrected_label,
        text=text,
        sender=sender,
        receiver=receiver,
    )

    return KnowledgeUpdate(
        accepted=True,
        document=document,
        reason="Validated feedback added to threat memory.",
    )