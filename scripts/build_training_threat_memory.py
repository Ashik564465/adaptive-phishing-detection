from __future__ import annotations

import pickle
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.settings import RANDOM_SEED
from src.embeddings.document_chunker import build_memory_document
from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)
from src.embeddings.vector_store import InMemoryVectorStore
from src.layer2_nlp.transformer_classifier import split_dataset


EMAIL_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "email_processed.parquet"
)

SMS_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "sms_processed.parquet"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory_train_only.pkl"
)

SAMPLES_PER_GROUP = 500


def build_model_text(row: pd.Series) -> str:
    """
    Reproduce the same text representation used by Layer 2.
    """

    channel = str(row["channel"]).upper()

    if channel == "EMAIL":
        subject = str(row.get("subject", "") or "")
        body = str(row.get("body", "") or "")

        return (
            f"[CHANNEL] EMAIL "
            f"[SUBJECT] {subject} "
            f"[BODY] {body}"
        )

    if channel == "SMS":
        body = str(row.get("body", "") or "")

        return (
            f"[CHANNEL] SMS "
            f"[BODY] {body}"
        )

    raise ValueError(
        f"Unsupported channel: {channel}"
    )


def load_unified_dataset() -> pd.DataFrame:
    email_df = pd.read_parquet(EMAIL_PATH)
    sms_df = pd.read_parquet(SMS_PATH)

    frame = pd.concat(
        [email_df, sms_df],
        ignore_index=True,
    )

    return frame


def select_training_memory(
    train_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Select a balanced threat-memory sample from TRAIN only.

    500 examples are selected for each:
        EMAIL legitimate
        EMAIL phishing
        SMS legitimate
        SMS phishing
    """

    required_groups = [
        ("EMAIL", "legitimate"),
        ("EMAIL", "phishing"),
        ("SMS", "legitimate"),
        ("SMS", "phishing"),
    ]

    selected = []

    for channel, label in required_groups:
        group = train_df[
            (train_df["channel"] == channel)
            & (train_df["label"] == label)
        ]

        if len(group) < SAMPLES_PER_GROUP:
            raise RuntimeError(
                f"Not enough training examples for "
                f"{channel}/{label}: "
                f"{len(group)} available."
            )

        sample = group.sample(
            n=SAMPLES_PER_GROUP,
            random_state=RANDOM_SEED,
        )

        selected.append(sample)

        print(
            f"{channel:5s} {label:11s}: "
            f"{len(sample)}"
        )

    return pd.concat(
        selected,
        ignore_index=True,
    )


def build_memory(
    memory_df: pd.DataFrame,
) -> tuple[InMemoryVectorStore, list]:
    embedder = HuggingFaceEmbedder(
        EmbeddingConfig(
            max_length=256
        )
    )

    documents = []

    texts = []

    for _, row in memory_df.iterrows():
        text = build_model_text(row)

        document = build_memory_document(
            message_id=str(row["message_id"]),
            channel=str(row["channel"]),
            label=str(row["label"]),
            text=text,
            sender=(
                str(row["sender"])
                if pd.notna(row.get("sender"))
                and str(row["sender"]).strip()
                else None
            ),
            receiver=(
                str(row["receiver"])
                if pd.notna(row.get("receiver"))
                and str(row["receiver"]).strip()
                else None
            ),
        )

        documents.append(document)
        texts.append(text)

    print()
    print(
        f"Generating embeddings for "
        f"{len(texts)} training-only messages..."
    )

    embeddings = embedder.encode(
        texts,
        batch_size=4,
    )

    print(
        f"Embedding matrix shape: "
        f"{embeddings.shape}"
    )

    store = InMemoryVectorStore()

    for document, embedding in zip(
        documents,
        embeddings,
    ):
        store.add(
            document=document,
            embedding=embedding,
        )

    return store, documents


def main() -> None:
    print("Loading processed datasets...")

    frame = load_unified_dataset()

    print(
        f"Total dataset rows: {len(frame)}"
    )

    print()
    print("Creating the same duplicate-aware split used by Layer 2...")

    train_df, validation_df, test_df = split_dataset(
        frame,
        seed=RANDOM_SEED,
    )

    print(
        f"Training rows:   {len(train_df)}"
    )
    print(
        f"Validation rows: {len(validation_df)}"
    )
    print(
        f"Test rows:       {len(test_df)}"
    )

    print()
    print(
        "Building threat memory from TRAIN ONLY..."
    )

    memory_df = select_training_memory(
        train_df
    )

    print()
    print(
        f"Training-only memory rows: "
        f"{len(memory_df)}"
    )

    store, documents = build_memory(
        memory_df
    )

    payload = {
        "store": store,
        "documents": documents,
        "source": "training_only",
        "seed": RANDOM_SEED,
        "samples_per_group": SAMPLES_PER_GROUP,
        "total_documents": len(documents),
    }

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_PATH,
        "wb",
    ) as file:
        pickle.dump(
            payload,
            file,
            protocol=pickle.HIGHEST_PROTOCOL,
        )

    print()
    print(
        f"Vector store contains "
        f"{len(store)} documents."
    )

    print()
    print(
        "Training-only threat memory saved to:"
    )
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()