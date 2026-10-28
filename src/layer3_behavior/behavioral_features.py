from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from src.layer3_behavior.sender_profile import (
    get_sender_profile,
)

from src.layer3_behavior.relationship_graph import (
    get_relationship_profile,
)


@dataclass(frozen=True)
class BehavioralFeatures:
    sender_known: int
    sender_message_count: int | None
    sender_phishing_rate: float | None

    relationship_known: int
    relationship_interaction_count: int | None
    relationship_phishing_rate: float | None

    relationship_novelty: int


def build_behavioral_features(
    sender_profiles: pd.DataFrame,
    relationship_profiles: pd.DataFrame,
    sender: str | None,
    receiver: str | None,
) -> BehavioralFeatures:
    """
    Convert historical sender and relationship profiles
    into behavioral detection features.

    Unknown metadata is represented explicitly rather than
    being fabricated.
    """

    sender_profile = None

    if sender:
        sender_profile = get_sender_profile(
            sender_profiles,
            sender,
        )

    relationship_profile = None

    if sender and receiver:
        relationship_profile = get_relationship_profile(
            relationship_profiles,
            sender,
            receiver,
        )

    sender_known = (
        1 if sender_profile is not None else 0
    )

    relationship_known = (
        1 if relationship_profile is not None else 0
    )

    sender_message_count = (
        sender_profile.message_count
        if sender_profile is not None
        else None
    )

    sender_phishing_rate = (
        sender_profile.phishing_rate
        if sender_profile is not None
        else None
    )

    relationship_interaction_count = (
        relationship_profile.interaction_count
        if relationship_profile is not None
        else None
    )

    relationship_phishing_rate = (
        relationship_profile.phishing_rate
        if relationship_profile is not None
        else None
    )

    # A sender may be historically known while the
    # sender-recipient relationship is completely new.
    relationship_novelty = (
        1
        if sender_profile is not None
        and sender
        and receiver
        and relationship_profile is None
        else 0
    )

    return BehavioralFeatures(
        sender_known=sender_known,
        sender_message_count=sender_message_count,
        sender_phishing_rate=sender_phishing_rate,
        relationship_known=relationship_known,
        relationship_interaction_count=(
            relationship_interaction_count
        ),
        relationship_phishing_rate=(
            relationship_phishing_rate
        ),
        relationship_novelty=relationship_novelty,
    )