from __future__ import annotations

import pickle
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.adaptive.adaptive_memory import AdaptiveMemory
from src.adaptive.feedback import create_feedback_record
from src.adaptive.knowledge_updater import (
    update_knowledge_from_feedback,
)
from src.embeddings.embedding_model import HuggingFaceEmbedder
from src.rag.context_builder import build_threat_context
from src.rag.retriever import ThreatRetriever


MEMORY_PATH = Path(
    "data/processed/threat_memory_train_only.pkl"
)


def build_model_input(
    channel: str,
    subject: str,
    body: str,
) -> str:

    channel = channel.upper()

    if channel == "EMAIL":
        return (
            "[CHANNEL] EMAIL "
            f"[SUBJECT] {subject} "
            f"[BODY] {body}"
        )

    if channel == "SMS":
        return (
            "[CHANNEL] SMS "
            f"[BODY] {body}"
        )

    raise ValueError(
        "channel must be EMAIL or SMS."
    )


def print_context(
    title: str,
    context,
    results,
) -> None:

    print("\n" + "-" * 70)
    print(title)
    print("-" * 70)

    print(
        f"Retrieved threats: "
        f"{context.retrieved_count}"
    )

    print(
        f"Phishing evidence: "
        f"{context.similar_phishing_count}"
    )

    print(
        f"Legitimate evidence: "
        f"{context.similar_legitimate_count}"
    )

    print(
        f"Average similarity: "
        f"{context.average_similarity:.4f}"
    )

    print("\nTop retrieved evidence:")

    for item in results[:5]:
        print(
            f"  - {item.document_id} | "
            f"{item.label} | "
            f"similarity={item.similarity:.4f}"
        )


def main() -> None:

    print("=" * 70)
    print("ADAPTIVE SEMANTIC GENERALIZATION TEST")
    print("=" * 70)

    print("\nLoading embedding model...")
    embedder = HuggingFaceEmbedder()

    print("Loading training-only threat memory...")

    with MEMORY_PATH.open("rb") as file:
        memory_data = pickle.load(file)

    store = memory_data["store"]

    adaptive_memory = AdaptiveMemory(
        embedder=embedder,
        vector_store=store,
    )

    retriever = ThreatRetriever(
        vector_store=store,
        similarity_threshold=0.60,
    )

    # ----------------------------------------------------------
    # MESSAGE A
    # This message will receive validated feedback.
    # ----------------------------------------------------------

    learned_message = build_model_input(
        channel="EMAIL",
        subject="Security verification required",
        body=(
            "Your company account requires immediate security "
            "verification. Confirm your password now to prevent "
            "account suspension."
        ),
    )

    # ----------------------------------------------------------
    # MESSAGE B
    # Different wording, same semantic attack pattern.
    # This is the actual generalization test.
    # ----------------------------------------------------------

    future_message = build_model_input(
        channel="EMAIL",
        subject="Corporate account security notice",
        body=(
            "Your workplace account is about to be disabled. "
            "Please verify your password immediately to keep "
            "access to your account."
        ),
    )

    # ----------------------------------------------------------
    # BEFORE LEARNING
    # ----------------------------------------------------------

    before_embedding = embedder.encode(
        future_message
    )

    before_results = retriever.retrieve(
        query_embedding=before_embedding,
        top_k=5,
    )

    before_context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=before_results,
    )

    print_context(
        "BEFORE ADAPTIVE LEARNING",
        before_context,
        before_results,
    )

    # ----------------------------------------------------------
    # VALIDATED FEEDBACK FOR MESSAGE A
    # ----------------------------------------------------------

    print("\n" + "-" * 70)
    print("ADDING VALIDATED KNOWLEDGE")
    print("-" * 70)

    feedback = create_feedback_record(
        message_id="adaptive-generalization-source-001",
        feedback_type="confirmed_phishing",
        corrected_label="phishing",
        source="admin",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text=learned_message,
        sender="security-alert@example.com",
        receiver=None,
    )

    print(
        f"Knowledge update accepted: "
        f"{update.accepted}"
    )

    print(
        f"Update reason: "
        f"{update.reason}"
    )

    if not update.accepted:
        raise RuntimeError(
            "Validated feedback was not accepted."
        )

    adaptive_memory.add_document(
        update.document
    )

    print(
        "Validated phishing example added "
        "to adaptive threat memory."
    )

    # ----------------------------------------------------------
    # AFTER LEARNING
    # ----------------------------------------------------------

    after_embedding = embedder.encode(
        future_message
    )

    after_results = retriever.retrieve(
        query_embedding=after_embedding,
        top_k=5,
    )

    after_context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=after_results,
    )

    print_context(
        "AFTER ADAPTIVE LEARNING",
        after_context,
        after_results,
    )

    # ----------------------------------------------------------
    # CHECK WHETHER THE NEWLY LEARNED MESSAGE WAS RETRIEVED
    # ----------------------------------------------------------

    learned_result = None

    for result in after_results:

        if (
            result.document_id
            == "adaptive-generalization-source-001"
        ):
            learned_result = result
            break

    print("\n" + "-" * 70)
    print("GENERALIZATION RESULT")
    print("-" * 70)

    if learned_result is None:

        print(
            "Newly learned phishing example was "
            "not among the top retrieved results."
        )

    else:

        print(
            "Newly learned phishing example was retrieved."
        )

        print(
            f"Similarity to future message: "
            f"{learned_result.similarity:.4f}"
        )

    similarity_change = (
        after_context.average_similarity
        - before_context.average_similarity
    )

    print(
        f"\nAverage similarity change: "
        f"{similarity_change:+.4f}"
    )

    print("\n" + "=" * 70)
    print("ADAPTIVE SEMANTIC GENERALIZATION TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()