from __future__ import annotations

from pathlib import Path
import re
import hashlib

import pandas as pd
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = (
    ROOT
    / "data"
    / "processed"
    / "unified_messages.parquet"
)

REPORT_PATH = (
    ROOT
    / "reports"
    / "layer2_leakage_audit.md"
)

RANDOM_SEED = 42
SIMILARITY_THRESHOLD = 0.85

# Sample size for approximate near-duplicate analysis.
# The exact duplicate/group audit is exhaustive.
MAX_SAMPLE_PER_SPLIT = 500


LABEL_TO_ID = {
    "legitimate": 0,
    "phishing": 1,
}


def normalize_text(text):
    """Normalize text for comparison."""

    if pd.isna(text):
        return ""

    text = str(text)

    text = text.casefold()

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


def build_input_text(row):
    """
    Reproduce the exact Layer 2 text construction
    used by transformer_classifier.py.
    """

    channel = str(
        row["channel"]
    ).upper()

    body = (
        ""
        if pd.isna(row.get("body"))
        else str(row.get("body"))
    )

    if channel == "EMAIL":

        subject = (
            ""
            if pd.isna(row.get("subject"))
            else str(row.get("subject"))
        )

        return (
            f"[CHANNEL] EMAIL "
            f"[SUBJECT] {subject} "
            f"[BODY] {body}"
        ).strip()

    if channel == "SMS":

        return (
            f"[CHANNEL] SMS "
            f"[BODY] {body}"
        ).strip()

    raise ValueError(
        f"Unsupported channel: {channel!r}"
    )


def message_group(text):
    """
    Reproduce the exact duplicate grouping logic
    from transformer_classifier.py.
    """

    return normalize_text(text)


def text_hash(text):
    """Create a deterministic SHA-256 hash."""

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def prepare_dataset(frame):
    """
    Reproduce the important preparation steps from
    transformer_classifier.py.
    """

    required = {
        "message_id",
        "channel",
        "sender",
        "recipient",
        "timestamp",
        "subject",
        "body",
        "label",
    }

    missing = required - set(frame.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    prepared = frame.copy()

    prepared["text"] = prepared.apply(
        build_input_text,
        axis=1,
    )

    prepared["target"] = prepared["label"].map(
        LABEL_TO_ID
    )

    if prepared["target"].isna().any():

        bad_labels = sorted(
            prepared.loc[
                prepared["target"].isna(),
                "label",
            ]
            .astype(str)
            .unique()
            .tolist()
        )

        raise ValueError(
            "Layer 2 labels must be exactly "
            f"legitimate/phishing. Found: {bad_labels}"
        )

    return prepared


def split_groups(
    values,
    test_size,
):
    """
    Reproduce the exact split_groups() logic from
    transformer_classifier.py.
    """

    if len(values) < 2:

        return (
            values.iloc[:0].copy(),
            values.copy(),
        )

    counts = values["target"].value_counts()

    stratify = (
        values["target"]
        if (
            len(counts) > 1
            and counts.min() >= 2
        )
        else None
    )

    return train_test_split(
        values,
        test_size=test_size,
        random_state=RANDOM_SEED,
        stratify=stratify,
    )


def split_dataset_exact(frame):
    """
    Reproduce split_dataset() from
    transformer_classifier.py as exactly as possible.
    """

    prepared = prepare_dataset(frame).copy()

    prepared["duplicate_group"] = (
        prepared["text"]
        .str.casefold()
        .str.replace(
            r"\s+",
            " ",
            regex=True,
        )
        .str.strip()
    )

    groups = prepared[
        [
            "duplicate_group",
            "target",
        ]
    ].drop_duplicates()

    train_groups, heldout_groups = split_groups(
        groups,
        0.30,
    )

    validation_groups, test_groups = split_groups(
        heldout_groups,
        0.50,
    )

    assignments = {
        "train": set(
            train_groups["duplicate_group"]
        ),
        "validation": set(
            validation_groups["duplicate_group"]
        ),
        "test": set(
            test_groups["duplicate_group"]
        ),
    }

    splits = {}

    for name in (
        "train",
        "validation",
        "test",
    ):

        partition = (
            prepared[
                prepared[
                    "duplicate_group"
                ].isin(assignments[name])
            ]
            .drop(
                columns="duplicate_group"
            )
            .reset_index(
                drop=True
            )
        )

        splits[name] = partition

    return (
        splits["train"],
        splits["validation"],
        splits["test"],
    )


def valid_values(series):
    """Return normalized non-empty values."""

    return {
        str(value)
        .strip()
        .lower()

        for value in series

        if (
            pd.notna(value)
            and str(value).strip()
        )
    }


def overlap_count(a, b):
    """Count overlap between two sets."""

    return len(
        set(a) & set(b)
    )


def sample_frame(frame):
    """Create deterministic sample for near-duplicate analysis."""

    if len(frame) <= MAX_SAMPLE_PER_SPLIT:

        return frame.copy()

    return frame.sample(
        n=MAX_SAMPLE_PER_SPLIT,
        random_state=RANDOM_SEED,
    ).copy()


def prepare_similarity_records(frame):
    """
    Precompute token sets once so that the nested
    comparison loop is efficient.
    """

    records = []

    for _, row in frame.iterrows():

        text = normalize_text(
            row["text"]
        )

        if not text:
            continue

        records.append(
            {
                "message_id": row[
                    "message_id"
                ],
                "channel": row[
                    "channel"
                ],
                "words": set(
                    text.split()
                ),
            }
        )

    return records


def jaccard_words(
    a_words,
    b_words,
):
    """Calculate token-set Jaccard similarity."""

    if not a_words and not b_words:
        return 1.0

    if not a_words or not b_words:
        return 0.0

    intersection = len(
        a_words & b_words
    )

    union = len(
        a_words | b_words
    )

    if union == 0:
        return 0.0

    return intersection / union


def near_duplicate_count(
    left_df,
    right_df,
):
    """
    Perform sampled near-duplicate analysis.

    This is intentionally approximate.
    Exact duplicate/group leakage is checked separately
    across the complete dataset.
    """

    left_records = (
        prepare_similarity_records(
            left_df
        )
    )

    right_records = (
        prepare_similarity_records(
            right_df
        )
    )

    if not left_records or not right_records:

        return 0, []

    count = 0
    examples = []

    for left in left_records:

        best_score = 0.0
        best_match = None

        for right in right_records:

            score = jaccard_words(
                left["words"],
                right["words"],
            )

            if score > best_score:

                best_score = score
                best_match = right

        if (
            best_score
            >= SIMILARITY_THRESHOLD
        ):

            count += 1

            if len(examples) < 10:

                examples.append(
                    {
                        "message_id": (
                            left[
                                "message_id"
                            ]
                        ),
                        "matched_message_id": (
                            best_match[
                                "message_id"
                            ]
                            if best_match
                            else "N/A"
                        ),
                        "similarity": round(
                            best_score,
                            4,
                        ),
                        "channel": left[
                            "channel"
                        ],
                    }
                )

    return count, examples


def parse_timestamp_column(frame):
    """Parse timestamps safely."""

    frame = frame.copy()

    frame[
        "timestamp_parsed"
    ] = pd.to_datetime(
        frame["timestamp"],
        errors="coerce",
        utc=True,
    )

    return frame


def time_range(frame):
    """Return minimum and maximum timestamps."""

    values = (
        frame[
            "timestamp_parsed"
        ]
        .dropna()
    )

    if values.empty:

        return (
            "N/A",
            "N/A",
        )

    return (
        str(values.min()),
        str(values.max()),
    )


def normalize_label_name(label):
    """Convert labels into project terminology."""

    label_name = (
        str(label)
        .strip()
        .lower()
    )

    if label_name in {
        "0",
        "legitimate",
    }:

        return "legitimate"

    if label_name in {
        "1",
        "phishing",
    }:

        return "phishing"

    return (
        f"unknown ({label})"
    )


def distribution(frame):
    """Create label/channel distribution."""

    return {
        "samples": len(frame),

        "legitimate": int(
            (
                frame["target"] == 0
            ).sum()
        ),

        "phishing": int(
            (
                frame["target"] == 1
            ).sum()
        ),
    }


def main():

    # =========================================================
    # 1. LOAD
    # =========================================================

    if not DATA_PATH.exists():

        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    frame = pd.read_parquet(
        DATA_PATH
    )

    print(
        f"Loaded {len(frame):,} rows"
    )

    # =========================================================
    # 2. REPRODUCE EXACT TRAINING SPLIT
    # =========================================================

    print(
        "Reproducing exact train/validation/test split..."
    )

    train, validation, test = (
        split_dataset_exact(frame)
    )

    print(
        f"Train: {len(train):,}"
    )

    print(
        f"Validation: {len(validation):,}"
    )

    print(
        f"Test: {len(test):,}"
    )

    # =========================================================
    # 3. BUILD HASHES
    # =========================================================

    for partition in (
        train,
        validation,
        test,
    ):

        partition["_normalized_text"] = (
            partition["text"]
            .map(normalize_text)
        )

        partition["_text_hash"] = (
            partition[
                "_normalized_text"
            ]
            .map(text_hash)
        )

    # =========================================================
    # 4. EXACT DUPLICATE ISOLATION
    # =========================================================

    print(
        "Checking exact duplicate isolation..."
    )

    train_hashes = set(
        train["_text_hash"]
    )

    validation_hashes = set(
        validation["_text_hash"]
    )

    test_hashes = set(
        test["_text_hash"]
    )

    exact_train_test = len(
        train_hashes
        & test_hashes
    )

    exact_train_validation = len(
        train_hashes
        & validation_hashes
    )

    exact_validation_test = len(
        validation_hashes
        & test_hashes
    )

    # =========================================================
    # 5. DUPLICATE GROUP ANALYSIS
    # =========================================================

    prepared_all = prepare_dataset(
        frame
    )

    prepared_all[
        "_normalized_text"
    ] = prepared_all[
        "text"
    ].map(
        normalize_text
    )

    prepared_all[
        "_text_hash"
    ] = prepared_all[
        "_normalized_text"
    ].map(
        text_hash
    )

    duplicate_mask = (
        prepared_all[
            "_text_hash"
        ]
        .duplicated(
            keep=False
        )
    )

    duplicate_rows = int(
        duplicate_mask.sum()
    )

    duplicate_groups = int(
        prepared_all.loc[
            duplicate_mask,
            "_text_hash",
        ].nunique()
    )

    # =========================================================
    # 6. SENDER / RECIPIENT OVERLAP
    # =========================================================

    print(
        "Checking sender and recipient overlap..."
    )

    train_senders = valid_values(
        train["sender"]
    )

    validation_senders = valid_values(
        validation["sender"]
    )

    test_senders = valid_values(
        test["sender"]
    )

    train_recipients = valid_values(
        train["recipient"]
    )

    validation_recipients = valid_values(
        validation["recipient"]
    )

    test_recipients = valid_values(
        test["recipient"]
    )

    # =========================================================
    # 7. CHANNEL DISTRIBUTION
    # =========================================================

    channel_counts = {}

    for name, partition in (
        ("train", train),
        ("validation", validation),
        ("test", test),
    ):

        channel_counts[name] = (
            partition[
                "channel"
            ]
            .value_counts()
            .to_dict()
        )

    # =========================================================
    # 8. LABEL DISTRIBUTION
    # =========================================================

    label_counts = {}

    for name, partition in (
        ("train", train),
        ("validation", validation),
        ("test", test),
    ):

        label_counts[name] = (
            partition[
                "label"
            ]
            .value_counts()
            .to_dict()
        )

    # =========================================================
    # 9. TEMPORAL COVERAGE
    # =========================================================

    print(
        "Checking temporal coverage..."
    )

    train = parse_timestamp_column(
        train
    )

    validation = (
        parse_timestamp_column(
            validation
        )
    )

    test = parse_timestamp_column(
        test
    )

    train_min, train_max = (
        time_range(train)
    )

    validation_min, validation_max = (
        time_range(validation)
    )

    test_min, test_max = (
        time_range(test)
    )

    # =========================================================
    # 10. NEAR-DUPLICATE ANALYSIS
    # =========================================================

    print(
        "Running sampled near-duplicate analysis..."
    )

    train_sample = sample_frame(
        train
    )

    validation_sample = sample_frame(
        validation
    )

    test_sample = sample_frame(
        test
    )

    train_test_near, train_test_examples = (
        near_duplicate_count(
            train_sample,
            test_sample,
        )
    )

    print(
        "Train/Test near-duplicate analysis complete."
    )

    train_validation_near, train_validation_examples = (
        near_duplicate_count(
            train_sample,
            validation_sample,
        )
    )

    print(
        "Train/Validation near-duplicate analysis complete."
    )

    validation_test_near, validation_test_examples = (
        near_duplicate_count(
            validation_sample,
            test_sample,
        )
    )

    print(
        "Validation/Test near-duplicate analysis complete."
    )

    # =========================================================
    # 11. SENDER LABEL CONSISTENCY
    # =========================================================

    email_df = prepared_all[
        (
            prepared_all[
                "channel"
            ]
            .astype(str)
            .str.upper()
            == "EMAIL"
        )
        & prepared_all[
            "sender"
        ].notna()
    ].copy()

    sender_label_conflicts = 0

    if not email_df.empty:

        sender_label_groups = (
            email_df
            .groupby(
                "sender"
            )["target"]
            .nunique()
        )

        sender_label_conflicts = int(
            (
                sender_label_groups
                > 1
            ).sum()
        )

    # =========================================================
    # 12. TEST SET PREDICTION ARTIFACT
    # =========================================================

    prediction_path = (
        ROOT
        / "models"
        / "phishing_classifier"
        / "test_predictions.csv"
    )

    prediction_exists = (
        prediction_path.exists()
    )

    prediction_count = 0

    if prediction_exists:

        try:

            predictions = pd.read_csv(
                prediction_path
            )

            prediction_count = len(
                predictions
            )

        except Exception:

            prediction_count = 0

    # =========================================================
    # 13. WRITE REPORT
    # =========================================================

    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = []

    lines.append(
        "# Layer 2 Leakage and Generalization Audit"
    )

    lines.append("")

    lines.append(
        "## 1. Purpose"
    )

    lines.append("")

    lines.append(
        "This audit reproduces the exact "
        "train/validation/test split used "
        "by the Layer 2 Transformer and "
        "checks duplicate isolation, sampled "
        "near-duplicate similarity, sender/"
        "recipient overlap, label consistency, "
        "channel distribution, and temporal coverage."
    )

    lines.append("")

    lines.append(
        "## 2. Dataset"
    )

    lines.append("")

    lines.append(
        f"- Total processed messages: "
        f"{len(frame):,}"
    )

    lines.append(
        f"- Exact duplicate text rows: "
        f"{duplicate_rows:,}"
    )

    lines.append(
        f"- Exact duplicate text groups: "
        f"{duplicate_groups:,}"
    )

    lines.append(
        "- Label 0: legitimate"
    )

    lines.append(
        "- Label 1: phishing"
    )

    lines.append("")

    lines.append(
        "## 3. Exact Training Split Reproduction"
    )

    lines.append("")

    lines.append(
        f"- Train: {len(train):,}"
    )

    lines.append(
        f"- Validation: {len(validation):,}"
    )

    lines.append(
        f"- Test: {len(test):,}"
    )

    lines.append(
        f"- Random seed: {RANDOM_SEED}"
    )

    lines.append(
        "- First split: 70% train / 30% held-out"
    )

    lines.append(
        "- Second split: 50% validation / "
        "50% test from held-out data"
    )

    lines.append(
        "- Stratification: enabled when both "
        "labels have at least two groups"
    )

    lines.append(
        "- Grouping: normalized Layer 2 message text"
    )

    lines.append("")

    lines.append(
        "The split implementation reproduces "
        "the logic in "
        "`src/layer2_nlp/transformer_classifier.py`."
    )

    lines.append("")

    lines.append(
        "## 4. Exact Duplicate Isolation"
    )

    lines.append("")

    lines.append(
        f"- Train/Test overlap: "
        f"{exact_train_test}"
    )

    lines.append(
        f"- Train/Validation overlap: "
        f"{exact_train_validation}"
    )

    lines.append(
        f"- Validation/Test overlap: "
        f"{exact_validation_test}"
    )

    lines.append("")

    lines.append(
        "Because the training split groups identical "
        "normalized messages together, exact duplicate "
        "groups should remain isolated between partitions."
    )

    lines.append("")

    lines.append(
        "## 5. Near-Duplicate Analysis"
    )

    lines.append("")

    lines.append(
        "- Method: sampled token-set Jaccard similarity"
    )

    lines.append(
        f"- Threshold: "
        f"{SIMILARITY_THRESHOLD}"
    )

    lines.append(
        f"- Maximum sample per split: "
        f"{MAX_SAMPLE_PER_SPLIT:,}"
    )

    lines.append(
        f"- Sampled Train/Test near-duplicates: "
        f"{train_test_near:,}"
    )

    lines.append(
        f"- Sampled Train/Validation "
        f"near-duplicates: "
        f"{train_validation_near:,}"
    )

    lines.append(
        f"- Sampled Validation/Test "
        f"near-duplicates: "
        f"{validation_test_near:,}"
    )

    lines.append("")

    lines.append(
        "### Train/Test Examples"
    )

    lines.append("")

    if train_test_examples:

        for item in train_test_examples:

            lines.append(
                f"- `{item['message_id']}` ↔ "
                f"`{item['matched_message_id']}` | "
                f"channel={item['channel']} | "
                f"similarity={item['similarity']}"
            )

    else:

        lines.append(
            "No sampled Train/Test pairs exceeded "
            "the similarity threshold."
        )

    lines.append("")

    lines.append(
        "### Train/Validation Examples"
    )

    lines.append("")

    if train_validation_examples:

        for item in train_validation_examples:

            lines.append(
                f"- `{item['message_id']}` ↔ "
                f"`{item['matched_message_id']}` | "
                f"channel={item['channel']} | "
                f"similarity={item['similarity']}"
            )

    else:

        lines.append(
            "No sampled Train/Validation pairs "
            "exceeded the similarity threshold."
        )

    lines.append("")

    lines.append(
        "### Validation/Test Examples"
    )

    lines.append("")

    if validation_test_examples:

        for item in validation_test_examples:

            lines.append(
                f"- `{item['message_id']}` ↔ "
                f"`{item['matched_message_id']}` | "
                f"channel={item['channel']} | "
                f"similarity={item['similarity']}"
            )

    else:

        lines.append(
            "No sampled Validation/Test pairs "
            "exceeded the similarity threshold."
        )

    lines.append("")

    lines.append(
        "## 6. Email Sender Overlap"
    )

    lines.append("")

    lines.append(
        f"- Unique train senders: "
        f"{len(train_senders):,}"
    )

    lines.append(
        f"- Unique validation senders: "
        f"{len(validation_senders):,}"
    )

    lines.append(
        f"- Unique test senders: "
        f"{len(test_senders):,}"
    )

    lines.append(
        f"- Train/Test sender overlap: "
        f"{overlap_count(train_senders, test_senders):,}"
    )

    lines.append(
        f"- Train/Validation sender overlap: "
        f"{overlap_count(train_senders, validation_senders):,}"
    )

    lines.append(
        f"- Validation/Test sender overlap: "
        f"{overlap_count(validation_senders, test_senders):,}"
    )

    lines.append("")

    lines.append(
        "## 7. Email Recipient Overlap"
    )

    lines.append("")

    lines.append(
        f"- Unique train recipients: "
        f"{len(train_recipients):,}"
    )

    lines.append(
        f"- Unique validation recipients: "
        f"{len(validation_recipients):,}"
    )

    lines.append(
        f"- Unique test recipients: "
        f"{len(test_recipients):,}"
    )

    lines.append(
        f"- Train/Test recipient overlap: "
        f"{overlap_count(train_recipients, test_recipients):,}"
    )

    lines.append(
        f"- Train/Validation recipient overlap: "
        f"{overlap_count(train_recipients, validation_recipients):,}"
    )

    lines.append(
        f"- Validation/Test recipient overlap: "
        f"{overlap_count(validation_recipients, test_recipients):,}"
    )

    lines.append("")

    lines.append(
        "## 8. Channel Distribution"
    )

    lines.append("")

    for split_name, counts in channel_counts.items():

        lines.append(
            f"### {split_name}"
        )

        for channel, count in counts.items():

            lines.append(
                f"- {channel}: {count:,}"
            )

        lines.append("")

    lines.append(
        "## 9. Label Distribution"
    )

    lines.append("")

    for split_name, counts in label_counts.items():

        lines.append(
            f"### {split_name}"
        )

        for label, count in sorted(
            counts.items(),
            key=lambda item: str(
                item[0]
            ),
        ):

            lines.append(
                f"- {normalize_label_name(label)}: "
                f"{count:,}"
            )

        lines.append("")

    lines.append(
        "## 10. Sender Label Consistency"
    )

    lines.append("")

    lines.append(
        f"- Email senders associated with both "
        f"labels: {sender_label_conflicts:,}"
    )

    lines.append("")

    lines.append(
        "## 11. Temporal Coverage"
    )

    lines.append("")

    lines.append(
        f"- Train: "
        f"{train_min} → {train_max}"
    )

    lines.append(
        f"- Validation: "
        f"{validation_min} → {validation_max}"
    )

    lines.append(
        f"- Test: "
        f"{test_min} → {test_max}"
    )

    lines.append("")

    lines.append(
        "## 12. Test Prediction Artifact"
    )

    lines.append("")

    if prediction_exists:

        lines.append(
            f"- Prediction file found: "
            f"`{prediction_path}`"
        )

        lines.append(
            f"- Prediction rows: "
            f"{prediction_count:,}"
        )

        lines.append(
            f"- Exact test split rows: "
            f"{len(test):,}"
        )

        if prediction_count == len(test):

            lines.append(
                "- Prediction row count matches "
                "the reproduced test split."
            )

        else:

            lines.append(
                "- WARNING: prediction row count "
                "does not match the reproduced "
                "test split."
            )

    else:

        lines.append(
            "- Prediction artifact was not found."
        )

    lines.append("")

    lines.append(
        "## 13. Interpretation"
    )

    lines.append("")

    lines.append(
        "The train/validation/test split in this "
        "audit reproduces the grouping and "
        "stratified splitting logic used by "
        "the Layer 2 training implementation."
    )

    lines.append("")

    lines.append(
        "Exact normalized-message groups are "
        "isolated between partitions. Therefore, "
        "identical messages are not intentionally "
        "placed into different partitions."
    )

    lines.append("")

    lines.append(
        "Sampled near-duplicate matches can still "
        "occur because different messages may share "
        "common templates or campaign wording. "
        "These matches are not automatically proof "
        "of leakage."
    )

    lines.append("")

    lines.append(
        "Sender and recipient overlap is reported "
        "descriptively. It is not automatically "
        "classified as leakage because the Layer 2 "
        "model input does not include sender or "
        "recipient identity."
    )

    lines.append("")

    lines.append(
        "The resulting evaluation should still be "
        "interpreted as performance on this dataset "
        "distribution. It does not by itself establish "
        "performance on future or previously unseen "
        "phishing campaigns."
    )

    lines.append("")

    lines.append(
        "## 14. URL Exclusion"
    )

    lines.append("")

    lines.append(
        "URLs are not used as detection features, "
        "reputation signals, domain features, "
        "WHOIS information, or model inputs."
    )

    REPORT_PATH.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    # =========================================================
    # 15. CONSOLE SUMMARY
    # =========================================================

    print("")
    print(
        "=================================================="
    )
    print(
        "Layer 2 Leakage Audit Completed"
    )
    print(
        "=================================================="
    )

    print(
        f"Report: {REPORT_PATH}"
    )

    print(
        f"Exact split sizes:"
    )

    print(
        f"  Train:      {len(train):,}"
    )

    print(
        f"  Validation: {len(validation):,}"
    )

    print(
        f"  Test:       {len(test):,}"
    )

    print("")

    print(
        "Exact duplicate overlap:"
    )

    print(
        f"  Train/Test:        "
        f"{exact_train_test}"
    )

    print(
        f"  Train/Validation:  "
        f"{exact_train_validation}"
    )

    print(
        f"  Validation/Test:   "
        f"{exact_validation_test}"
    )

    print("")

    print(
        "Sampled near-duplicates:"
    )

    print(
        f"  Train/Test:        "
        f"{train_test_near}"
    )

    print(
        f"  Train/Validation:  "
        f"{train_validation_near}"
    )

    print(
        f"  Validation/Test:   "
        f"{validation_test_near}"
    )

    print(
        "=================================================="
    )


if __name__ == "__main__":
    main()