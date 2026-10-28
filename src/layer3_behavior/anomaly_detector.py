from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class TemporalAnomalyResult:
    available: bool
    anomaly: int
    historical_message_count: int
    current_hour: int | None
    typical_hours: tuple[int, ...]


def detect_temporal_anomaly(
    events: pd.DataFrame,
    sender: str | None,
    current_timestamp,
) -> TemporalAnomalyResult:
    """
    Detect whether the current message time is unusual
    compared with the sender's historical sending hours.

    Required event columns:
        sender
        timestamp

    The detector does not fabricate timestamps or sender IDs.
    """

    required = {"sender", "timestamp"}

    missing = required - set(events.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    if not sender or current_timestamp is None:
        return TemporalAnomalyResult(
            available=False,
            anomaly=0,
            historical_message_count=0,
            current_hour=None,
            typical_hours=(),
        )

    frame = events.copy()

    frame["sender"] = (
        frame["sender"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"],
        errors="coerce",
    )

    sender = str(sender).strip()

    history = frame[
        (frame["sender"] == sender)
        & frame["timestamp"].notna()
    ].copy()

    current_time = pd.to_datetime(
        current_timestamp,
        errors="coerce",
    )

    if pd.isna(current_time):
        return TemporalAnomalyResult(
            available=False,
            anomaly=0,
            historical_message_count=len(history),
            current_hour=None,
            typical_hours=(),
        )

    if history.empty:
        return TemporalAnomalyResult(
            available=False,
            anomaly=0,
            historical_message_count=0,
            current_hour=int(current_time.hour),
            typical_hours=(),
        )

    historical_hours = (
        history["timestamp"]
        .dt.hour
        .value_counts()
    )

    typical_hours = tuple(
        sorted(
            int(hour)
            for hour, count in historical_hours.items()
            if count >= 1
        )
    )

    current_hour = int(current_time.hour)

    anomaly = (
        0
        if current_hour in typical_hours
        else 1
    )

    return TemporalAnomalyResult(
        available=True,
        anomaly=anomaly,
        historical_message_count=len(history),
        current_hour=current_hour,
        typical_hours=typical_hours,
    )