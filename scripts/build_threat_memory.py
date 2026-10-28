from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pickle
from pathlib import Path

import pandas as pd

from src.config.settings import PROCESSED_DATA_PATH
from src.embeddings.document_chunker import (
    build_memory_document,
)
from src.embeddings.embedding_model import (
    HuggingFaceEmbedder,
)
from src.embeddings.vector_store import (
    InMemoryVectorStore,
)


OUTPUT_PATH = (
    Path(PROCESSED_DATA_PATH)
    / "threat_memory.pkl"
)

SAMPLES_PER_GROUP = 500


def load_data() -> pd.DataFrame:
    email_path = (
        Path(PROCESSED_DATA_PATH)
        / "email_processed.parquet"
    )

    sms_path = (
        Path(PROCESSED_DATA_PATH)
        / "sms_processed.parquet"
    )

    email = pd.read_parquet(email_path)
    sms = pd.read_parquet(sms_path)

    email["channel"] = "EMAIL"
    sms["channel"] = "SMS"

    columns = [
        "message_id",
        "channel",
        "sender",
        "recipient",
        "subject",
        "body",
        "label",
    ]

    email = email[columns]
    sms = sms[columns]

    return pd.concat(
        [email, sms],
        ignore_index=True,
    )


def prepare_sample(
    data: pd.DataFrame,
) -> pd.DataFrame:

    groups = []

    for channel in ["EMAIL", "SMS"]:
        for label in ["legitimate", "phishing"]:

            subset = data[
                (data["channel"] == channel)
                & (data["label"] == label)
            ].copy()

            if len(subset) < SAMPLES_PER_GROUP:
                raise ValueError(
                    f"Not enough rows for "
                    f"{channel}/{label}. "
                    f"Found {len(subset)}."
                )

            sampled = subset.sample(
                n=SAMPLES_PER_GROUP,
                random_state=42,
            )

            groups.append(sampled)

    result = pd.concat(
        groups,
        ignore_index=True,
    )

    return result


def build_memory(
    data: pd.DataFrame,
) -> InMemoryVectorStore:

    embedder = HuggingFaceEmbedder()

    vector_store = InMemoryVectorStore()

    texts = []

    documents = []

    for _, row in data.iterrows():

        channel = row["channel"]

        subject = (
            str(row["subject"]).strip()
            if pd.notna(row["subject"])
            else ""
        )

        body = (
            str(row["body"]).strip()
            if pd.notna(row["body"])
            else ""
        )

        if channel == "EMAIL":
            text = (
                "[CHANNEL] EMAIL "
                f"[SUBJECT] {subject} "
                f"[BODY] {body}"
            )
        else:
            text = (
                "[CHANNEL] SMS "
                f"[BODY] {body}"
            )

        sender = (
            str(row["sender"]).strip()
            if pd.notna(row["sender"])
            else None
        )

        receiver = (
            str(row["recipient"]).strip()
            if pd.notna(row["recipient"])
            else None
        )

        document = build_memory_document(
            message_id=row["message_id"],
            channel=channel,
            label=row["label"],
            text=text,
            sender=sender,
            receiver=receiver,
        )

        documents.append(document)
        texts.append(text)

    print(
        f"Generating embeddings for "
        f"{len(texts)} messages..."
    )

    embeddings = embedder.encode(texts)

    print(
        f"Embedding matrix shape: "
        f"{embeddings.shape}"
    )

    for document, embedding in zip(
        documents,
        embeddings,
    ):
        vector_store.add(
            document=document,
            embedding=embedding,
        )

    return vector_store


def main() -> None:

    print("Loading processed datasets...")

    data = load_data()

    print(
        f"Total available messages: "
        f"{len(data)}"
    )

    sample = prepare_sample(data)

    print(
        "\nThreat memory sample:"
    )

    print(
        sample.groupby(
            ["channel", "label"]
        ).size()
    )

    vector_store = build_memory(
        sample
    )

    print(
        f"\nVector store contains "
        f"{len(vector_store)} documents."
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_PATH,
        "wb",
    ) as file:
        pickle.dump(
            vector_store,
            file,
        )

    print(
        f"Threat memory saved to:\n"
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()