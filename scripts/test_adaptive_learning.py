from __future__ import annotations
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pickle
from pathlib import Path

from src.adaptive.adaptive_memory import AdaptiveMemory
from src.adaptive.feedback import create_feedback_record
from src.adaptive.knowledge_updater import (
    update_knowledge_from_feedback,
)
from src.embeddings.embedding_model import HuggingFaceEmbedder
from src.embeddings.vector_store import InMemoryVectorStore
from src.rag.retriever import ThreatRetriever
from src.rag.context_builder import build_threat_context


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


def main() -> None:

    print("=" * 70)
    print("ADAPTIVE THREAT MEMORY TEST")
    print("=" * 70)

    print("\nLoading embedding model...")
    embedder = HuggingFaceEmbedder()

    print("Loading existing training-only threat memory...")

    with MEMORY_PATH.open("rb") as file:
        memory_data = pickle.load(file)

    store = memory_data["store"]

    print(
        "Existing threat memory loaded successfully."
    )

    adaptive_memory = AdaptiveMemory(
        embedder=embedder,
        vector_store=store,
    )

    retriever = ThreatRetriever(
        vector_store=store,
        similarity_threshold=0.60,
    )

    # ----------------------------------------------------------
    # NEW VALIDATED PHISHING MESSAGE
    # ----------------------------------------------------------

    message_id = "adaptive-feedback-001"

    channel = "EMAIL"

    subject = "Security verification required"

    body = (
        "Your company account requires immediate security "
        "verification. Confirm your password now to prevent "
        "account suspension."
    )

    message_text = build_model_input(
        channel=channel,
        subject=subject,
        body=body,
    )

    # ----------------------------------------------------------
    # BEFORE FEEDBACK
    # ----------------------------------------------------------

    print("\n" + "-" * 70)
    print("BEFORE ADAPTIVE FEEDBACK")
    print("-" * 70)

    before_embedding = embedder.encode(
        message_text
    )

    before_results = retriever.retrieve(
        query_embedding=before_embedding,
        top_k=5,
    )

    before_context = build_threat_context(
        query_channel=channel,
        retrieved_threats=before_results,
    )

    print(
        f"Retrieved threats: "
        f"{before_context.retrieved_count}"
    )

    print(
        f"Historical phishing evidence: "
        f"{before_context.similar_phishing_count}"
    )

    print(
        f"Historical legitimate evidence: "
        f"{before_context.similar_legitimate_count}"
    )

    print(
        f"Average similarity: "
        f"{before_context.average_similarity:.4f}"
    )

    # ----------------------------------------------------------
    # USER / ADMIN CONFIRMS PHISHING
    # ----------------------------------------------------------

    print("\n" + "-" * 70)
    print("ADDING VALIDATED FEEDBACK")
    print("-" * 70)

    feedback = create_feedback_record(
        message_id=message_id,
        feedback_type="confirmed_phishing",
        corrected_label="phishing",
        source="admin",
    )

    print(
        f"Feedback type: {feedback.feedback_type}"
    )

    print(
        f"Corrected label: {feedback.corrected_label}"
    )

    # ----------------------------------------------------------
    # CONVERT FEEDBACK INTO THREAT MEMORY
    # ----------------------------------------------------------

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel=channel,
        text=message_text,
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
            "Adaptive knowledge update was rejected."
        )

    # ----------------------------------------------------------
    # ADD TO VECTOR MEMORY
    # ----------------------------------------------------------

    adaptive_memory.add_document(
        update.document
    )

    print(
        "New validated threat added to adaptive memory."
    )

    # ----------------------------------------------------------
    # AFTER FEEDBACK
    # ----------------------------------------------------------

    print("\n" + "-" * 70)
    print("AFTER ADAPTIVE FEEDBACK")
    print("-" * 70)

    after_embedding = embedder.encode(
        message_text
    )

    after_results = retriever.retrieve(
        query_embedding=after_embedding,
        top_k=5,
    )

    after_context = build_threat_context(
        query_channel=channel,
        retrieved_threats=after_results,
    )

    print(
        f"Retrieved threats: "
        f"{after_context.retrieved_count}"
    )

    print(
        f"Historical phishing evidence: "
        f"{after_context.similar_phishing_count}"
    )

    print(
        f"Historical legitimate evidence: "
        f"{after_context.similar_legitimate_count}"
    )

    print(
        f"Average similarity: "
        f"{after_context.average_similarity:.4f}"
    )

    print("\nRetrieved evidence:")

    for item in after_results:

        print(
            f"  - {item.document_id} | "
            f"{item.label} | "
            f"similarity={item.similarity:.4f}"
        )

    print("\n" + "=" * 70)
    print("ADAPTIVE LEARNING TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()