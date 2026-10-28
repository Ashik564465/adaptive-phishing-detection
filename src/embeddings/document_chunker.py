from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatMemoryDocument:
    document_id: str
    channel: str
    label: str
    text: str
    sender: str | None = None
    receiver: str | None = None


def build_memory_document(
    message_id,
    channel,
    label,
    text,
    sender=None,
    receiver=None,
) -> ThreatMemoryDocument:
    """
    Convert one validated message into a threat-memory document.

    The stored text contains message content only.
    URL values are not added as detection features.
    """

    document_id = str(message_id).strip()
    normalized_channel = str(channel).strip().upper()
    normalized_label = str(label).strip().lower()
    normalized_text = str(text).strip()

    if not document_id:
        raise ValueError("message_id cannot be empty.")

    if normalized_channel not in {"EMAIL", "SMS"}:
        raise ValueError(
            f"Unsupported channel: {normalized_channel}"
        )

    if normalized_label not in {"legitimate", "phishing"}:
        raise ValueError(
            f"Unsupported label: {normalized_label}"
        )

    if not normalized_text:
        raise ValueError("text cannot be empty.")

    normalized_sender = (
        str(sender).strip()
        if sender is not None
        else None
    )

    normalized_receiver = (
        str(receiver).strip()
        if receiver is not None
        else None
    )

    return ThreatMemoryDocument(
        document_id=document_id,
        channel=normalized_channel,
        label=normalized_label,
        text=normalized_text,
        sender=normalized_sender or None,
        receiver=normalized_receiver or None,
    )