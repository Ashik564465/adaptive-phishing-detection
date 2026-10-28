from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SMSSenderFeatures:
    """
    Sender identity features for SMS.

    The current SMS dataset is text-only, so these values
    remain unknown until sender metadata is supplied.
    """

    sender_available: int
    sender_known: Optional[int]
    sender_history_available: int
    sender_reputation_available: int


def build_sms_sender_features(
    sender: Optional[str] = None,
    known_sender: Optional[bool] = None,
    history_available: bool = False,
    reputation_available: bool = False,
) -> SMSSenderFeatures:

    sender_available = int(
        sender is not None
        and str(sender).strip() != ""
    )

    if known_sender is None:

        sender_known = None

    else:

        sender_known = int(
            known_sender
        )

    return SMSSenderFeatures(
        sender_available=sender_available,
        sender_known=sender_known,
        sender_history_available=int(
            history_available
        ),
        sender_reputation_available=int(
            reputation_available
        ),
    )


def sms_sender_features_to_dict(
    features: SMSSenderFeatures,
) -> dict:

    return {
        "sender_available": (
            features.sender_available
        ),
        "sender_known": (
            features.sender_known
        ),
        "sender_history_available": (
            features.sender_history_available
        ),
        "sender_reputation_available": (
            features.sender_reputation_available
        ),
    }