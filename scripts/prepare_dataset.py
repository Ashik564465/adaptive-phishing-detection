from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.settings import (
    EMAIL_INPUT_PATH,
    EMAIL_LABEL_MAPPING,
    METADATA_PATH,
    PROCESSED_DATA_PATH,
    SMS_INPUT_PATH,
)
from src.ingestion.unified_loader import load_and_process, pseudonymize


def _write_behavioral_metadata(email: pd.DataFrame, output_dir) -> None:
    events = pd.DataFrame(
        {
            "message_id": email["message_id"],
            "sender_id": email["sender"].map(lambda value: pseudonymize(value, "sender")),
            "recipient_id": email["recipient"].map(lambda value: pseudonymize(value, "recipient")),
            "timestamp": email["timestamp"],
            "channel": email["channel"],
            "label": email["label"],
            "source_dataset": email["source_dataset"],
        }
    )
    events.to_csv(output_dir / "email_communication_events.csv", index=False)

    profiles = events.dropna(subset=["sender_id"]).groupby("sender_id", as_index=False).agg(
        message_count=("message_id", "count"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        legitimate_count=("label", lambda values: int((values == "legitimate").sum())),
        phishing_count=("label", lambda values: int((values == "phishing").sum())),
    )
    profiles["phishing_ratio"] = profiles["phishing_count"] / profiles["message_count"]
    profiles.to_csv(output_dir / "email_sender_profiles.csv", index=False)

    relationships = events.dropna(subset=["sender_id", "recipient_id"])
    relationships = relationships.groupby(["sender_id", "recipient_id"], as_index=False).agg(
        message_count=("message_id", "count"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        legitimate_count=("label", lambda values: int((values == "legitimate").sum())),
        phishing_count=("label", lambda values: int((values == "phishing").sum())),
    )
    relationships.to_csv(output_dir / "email_relationship_profiles.csv", index=False)


def run_pipeline() -> dict:
    if EMAIL_LABEL_MAPPING is None:
        raise RuntimeError(
            "Pipeline stopped: configure EMAIL_LABEL_MAPPING in "
            "src/config/settings.py before writing processed outputs."
        )

    email, sms, stats = load_and_process(
        EMAIL_INPUT_PATH,
        SMS_INPUT_PATH,
        email_label_mapping=EMAIL_LABEL_MAPPING,
    )
    PROCESSED_DATA_PATH.mkdir(parents=True, exist_ok=True)
    METADATA_PATH.mkdir(parents=True, exist_ok=True)
    email.to_parquet(PROCESSED_DATA_PATH / "email_processed.parquet", index=False)
    sms.to_parquet(PROCESSED_DATA_PATH / "sms_processed.parquet", index=False)
    pd.concat([email, sms], ignore_index=True).to_parquet(
        PROCESSED_DATA_PATH / "unified_messages.parquet", index=False
    )
    _write_behavioral_metadata(email, METADATA_PATH)
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare unified email and SMS data.")
    parser.parse_args()
    print(run_pipeline())