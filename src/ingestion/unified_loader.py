from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from src.config.labels import normalize_email_label, normalize_sms_label
from src.preprocessing.text_normalizer import normalize_text


BASE_COLUMNS = [
    "message_id",
    "channel",
    "sender",
    "recipient",
    "timestamp",
    "subject",
    "body",
    "label",
    "original_label",
    "source_dataset",
]
EMAIL_COLUMNS = ["sender", "receiver", "date", "subject", "body", "label"]


def _stable_id(prefix: str, values: list[object]) -> str:
    payload = "\x1f".join("" if value is None else str(value) for value in values)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


def pseudonymize(value: object, prefix: str) -> str | None:
    normalized = normalize_text(value)
    if normalized is None:
        return None
    digest = hashlib.sha256(normalized.casefold().encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


def _parse_timestamp(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", utc=True, format="mixed")


def _near_duplicate_analysis(frame: pd.DataFrame) -> dict[str, int]:
    blocks: defaultdict[tuple[str, int], list[str]] = defaultdict(list)
    for row in frame.itertuples(index=False):
        text = " ".join(value for value in (row.subject, row.body) if value)
        if not text:
            continue
        blocks[(text[:80].casefold(), len(text) // 100)].append(text)
    candidate_groups = sum(1 for values in blocks.values() if len(values) > 1)
    candidate_rows = sum(len(values) for values in blocks.values() if len(values) > 1)
    return {
        "near_duplicate_candidate_groups": candidate_groups,
        "near_duplicate_candidate_rows": candidate_rows,
    }


def process_email_frame(
    frame: pd.DataFrame,
    *,
    source_dataset: str,
    email_label_mapping: dict[str, str] | None,
) -> tuple[pd.DataFrame, dict[str, int]]:
    missing = sorted(set(EMAIL_COLUMNS) - set(frame.columns))
    if missing:
        raise ValueError(f"Email input is missing columns: {missing}")

    processed = pd.DataFrame(index=frame.index)
    processed["sender"] = frame["sender"].map(normalize_text)
    processed["recipient"] = frame["receiver"].map(normalize_text)
    processed["timestamp_original"] = frame["date"].map(normalize_text)
    processed["timestamp"] = _parse_timestamp(processed["timestamp_original"])
    processed["subject"] = frame["subject"].map(normalize_text)
    processed["body"] = frame["body"].map(lambda value: normalize_text(value, html_cleanup=True))
    processed["original_label"] = frame["label"].map(lambda value: str(value).strip())
    processed["label"] = frame["label"].map(
        lambda value: normalize_email_label(value, email_label_mapping)
    )
    processed["channel"] = "EMAIL"
    processed["source_dataset"] = source_dataset
    processed["message_id"] = [
        _stable_id("email", [source_dataset, *processed.loc[index, BASE_COLUMNS[1:]].tolist()])
        for index in processed.index
    ]
    dedup_columns = [column for column in BASE_COLUMNS if column != "message_id"]
    processed = processed.drop_duplicates(subset=dedup_columns, keep="first").reset_index(drop=True)
    duplicate_stats = {
        "input_rows": len(frame),
        "exact_duplicate_excess_rows": len(frame) - len(processed),
        "output_rows": len(processed),
        "timestamp_parse_failures": int(processed["timestamp"].isna().sum()),
        **_near_duplicate_analysis(processed),
    }
    return processed[BASE_COLUMNS + ["timestamp_original"]], duplicate_stats


def process_sms_frame(frame: pd.DataFrame, *, source_dataset: str) -> tuple[pd.DataFrame, dict[str, int]]:
    required = {"label", "text"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"SMS input is missing columns: {missing}")

    processed = pd.DataFrame(index=frame.index)
    processed["channel"] = "SMS"
    processed["sender"] = pd.NA
    processed["recipient"] = pd.NA
    processed["timestamp"] = pd.NaT
    processed["subject"] = pd.NA
    processed["body"] = frame["text"].map(normalize_text)
    processed["original_label"] = frame["label"].map(lambda value: str(value).strip())
    processed["label"] = frame["label"].map(normalize_sms_label)
    processed["source_dataset"] = source_dataset
    dedup_columns = [column for column in BASE_COLUMNS if column != "message_id"]
    processed = processed.drop_duplicates(subset=dedup_columns, keep="first").reset_index(drop=True)
    processed["message_id"] = [
        _stable_id("sms", [source_dataset, index, body])
        for index, body in zip(processed.index, processed["body"])
    ]
    return processed[BASE_COLUMNS], {
        "input_rows": len(frame),
        "exact_duplicate_excess_rows": len(frame) - len(processed),
        "output_rows": len(processed),
    }


def load_and_process(
    email_path: Path,
    sms_path: Path,
    *,
    email_label_mapping: dict[str, str] | None,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    email = pd.read_excel(email_path, engine="openpyxl")
    sms = pd.read_csv(sms_path)
    email_processed, email_stats = process_email_frame(
        email,
        source_dataset=email_path.name,
        email_label_mapping=email_label_mapping,
    )
    sms_processed, sms_stats = process_sms_frame(sms, source_dataset=sms_path.name)
    return email_processed, sms_processed, {"email": email_stats, "sms": sms_stats}