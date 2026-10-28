import pandas as pd
import pytest

from src.config.labels import normalize_email_label, normalize_sms_label
from src.ingestion.unified_loader import process_email_frame, process_sms_frame, pseudonymize


def email_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "sender": [" Alice@example.com ", "Alice@example.com"],
            "receiver": ["Bob@example.com", "Bob@example.com"],
            "date": ["Tue, 05 Aug 2008 16:31:02 -0700"] * 2,
            "subject": ["  Hello  ", "  Hello  "],
            "body": ["<p>World</p>", "<p>World</p>"],
            "label": ["0", "0"],
        }
    )


def test_email_schema_and_duplicate_handling():
    processed, stats = process_email_frame(
        email_frame(),
        source_dataset="email_combined.xlsx",
        email_label_mapping={"0": "legitimate", "1": "phishing"},
    )
    assert {"message_id", "channel", "sender", "recipient", "timestamp", "subject", "body", "label", "original_label", "source_dataset"}.issubset(processed.columns)
    assert len(processed) == 1
    assert stats["exact_duplicate_excess_rows"] == 1


def test_label_normalization_and_mapping_guard():
    assert normalize_sms_label("ham") == "legitimate"
    assert normalize_sms_label("spam") == "phishing"
    assert normalize_email_label("0", {"0": "legitimate", "1": "phishing"}) == "legitimate"
    with pytest.raises(ValueError):
        normalize_email_label("0", None)


def test_timestamp_parsing_and_text_normalization():
    processed, _ = process_email_frame(
        email_frame(),
        source_dataset="email_combined.xlsx",
        email_label_mapping={"0": "legitimate", "1": "phishing"},
    )
    assert str(processed.loc[0, "timestamp"].tz) == "UTC"
    assert processed.loc[0, "body"] == "World"
    assert processed.loc[0, "subject"] == "Hello"


def test_sms_null_handling_and_label_normalization():
    processed, _ = process_sms_frame(
        pd.DataFrame({"label": ["ham", "spam"], "text": [" hello ", "bad"]}),
        source_dataset="sms_combined.csv",
    )
    assert processed["sender"].isna().all()
    assert processed["recipient"].isna().all()
    assert processed["timestamp"].isna().all()
    assert processed["label"].tolist() == ["legitimate", "phishing"]


def test_nan_values_remain_null():
    frame = email_frame()
    frame.loc[0, "sender"] = float("nan")
    processed, _ = process_email_frame(
        frame,
        source_dataset="email_combined.xlsx",
        email_label_mapping={"0": "legitimate", "1": "phishing"},
    )
    assert pd.isna(processed.loc[0, "sender"])


def test_url_exclusion_and_pseudonymization():
    processed, _ = process_email_frame(
        email_frame(),
        source_dataset="email_combined.xlsx",
        email_label_mapping={"0": "legitimate", "1": "phishing"},
    )
    assert "urls" not in processed.columns
    assert pseudonymize("Alice@example.com", "sender") == pseudonymize(" Alice@example.com ", "sender")
    assert "Alice@example.com" not in pseudonymize("Alice@example.com", "sender")