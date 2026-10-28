from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pandas as pd


@dataclass(frozen=True)
class SenderProfile:
    sender: str
    message_count: int
    legitimate_count: int
    phishing_count: int
    phishing_rate: float
    first_seen: Any
    last_seen: Any


def build_sender_profiles(events: pd.DataFrame) -> pd.DataFrame:
    """
    Build historical sender-level behavioral profiles.

    Expected columns:
        sender
        label
        timestamp

    The function does not invent missing sender or timestamp values.
    """

    required = {"sender", "label", "timestamp"}

    missing = required - set(events.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    frame = events.copy()

    frame["sender"] = frame["sender"].fillna("").astype(str).str.strip()
    frame["label"] = (
        frame["label"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"],
        errors="coerce",
    )

    # Sender history requires an actual sender.
    frame = frame[frame["sender"] != ""].copy()

    if frame.empty:
        return pd.DataFrame(
            columns=[
                "sender",
                "message_count",
                "legitimate_count",
                "phishing_count",
                "phishing_rate",
                "first_seen",
                "last_seen",
            ]
        )

    grouped = (
        frame.groupby("sender", dropna=False)
        .agg(
            message_count=("sender", "size"),
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
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )

    grouped["phishing_rate"] = (
        grouped["phishing_count"]
        / grouped["message_count"]
    )

    return grouped[
        [
            "sender",
            "message_count",
            "legitimate_count",
            "phishing_count",
            "phishing_rate",
            "first_seen",
            "last_seen",
        ]
    ].sort_values(
        ["message_count", "sender"],
        ascending=[False, True],
    ).reset_index(drop=True)


def get_sender_profile(
    profiles: pd.DataFrame,
    sender: str,
) -> SenderProfile | None:
    """
    Retrieve one sender's historical profile.
    """

    if "sender" not in profiles.columns:
        raise ValueError(
            "profiles must contain a 'sender' column"
        )

    sender = str(sender).strip()

    matches = profiles[
        profiles["sender"].astype(str).str.strip()
        == sender
    ]

    if matches.empty:
        return None

    row = matches.iloc[0]

    return SenderProfile(
        sender=str(row["sender"]),
        message_count=int(row["message_count"]),
        legitimate_count=int(row["legitimate_count"]),
        phishing_count=int(row["phishing_count"]),
        phishing_rate=float(row["phishing_rate"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )