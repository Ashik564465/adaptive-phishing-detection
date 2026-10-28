from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class RelationshipProfile:
    sender: str
    recipient: str
    interaction_count: int
    legitimate_count: int
    phishing_count: int
    phishing_rate: float


def build_relationship_profiles(
    events: pd.DataFrame,
) -> pd.DataFrame:
    """
    Build sender-recipient communication relationship profiles.

    Required columns:
        sender
        receiver
        label

    Missing sender/receiver values are not fabricated.
    """

    required = {
        "sender",
        "receiver",
        "label",
    }

    missing = required - set(events.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    frame = events.copy()

    frame["sender"] = (
        frame["sender"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    frame["receiver"] = (
        frame["receiver"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    frame["label"] = (
        frame["label"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    # A relationship cannot be established without
    # both endpoints.
    frame = frame[
        (frame["sender"] != "")
        & (frame["receiver"] != "")
    ].copy()

    if frame.empty:
        return pd.DataFrame(
            columns=[
                "sender",
                "receiver",
                "interaction_count",
                "legitimate_count",
                "phishing_count",
                "phishing_rate",
            ]
        )

    grouped = (
        frame.groupby(
            ["sender", "receiver"],
            dropna=False,
        )
        .agg(
            interaction_count=("sender", "size"),
            legitimate_count=(
                "label",
                lambda values: int(
                    (values == "legitimate").sum()
                ),
            ),
            phishing_count=(
                "label",
                lambda values: int(
                    (values == "phishing").sum()
                ),
            ),
        )
        .reset_index()
    )

    grouped["phishing_rate"] = (
        grouped["phishing_count"]
        / grouped["interaction_count"]
    )

    return grouped[
        [
            "sender",
            "receiver",
            "interaction_count",
            "legitimate_count",
            "phishing_count",
            "phishing_rate",
        ]
    ].sort_values(
        [
            "interaction_count",
            "sender",
            "receiver",
        ],
        ascending=[False, True, True],
    ).reset_index(drop=True)


def get_relationship_profile(
    profiles: pd.DataFrame,
    sender: str,
    receiver: str,
) -> RelationshipProfile | None:
    """
    Retrieve the historical relationship between
    one sender and one recipient.
    """

    required = {
        "sender",
        "receiver",
    }

    missing = required - set(profiles.columns)

    if missing:
        raise ValueError(
            f"profiles missing columns: {sorted(missing)}"
        )

    sender = str(sender).strip()
    receiver = str(receiver).strip()

    matches = profiles[
        (profiles["sender"].astype(str).str.strip() == sender)
        & (
            profiles["receiver"]
            .astype(str)
            .str.strip()
            == receiver
        )
    ]

    if matches.empty:
        return None

    row = matches.iloc[0]

    return RelationshipProfile(
        sender=str(row["sender"]),
        recipient=str(row["receiver"]),
        interaction_count=int(
            row["interaction_count"]
        ),
        legitimate_count=int(
            row["legitimate_count"]
        ),
        phishing_count=int(
            row["phishing_count"]
        ),
        phishing_rate=float(
            row["phishing_rate"]
        ),
    )