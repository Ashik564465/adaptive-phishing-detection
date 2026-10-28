from __future__ import annotations

import csv
import json
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

OUTPUT_DIR = Path(
    "models/adaptive_evaluation"
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


def evaluate_query(
    retriever: ThreatRetriever,
    embedder: HuggingFaceEmbedder,
    message: str,
    channel: str,
):
    embedding = embedder.encode(message)

    results = retriever.retrieve(
        query_embedding=embedding,
        top_k=5,
    )

    context = build_threat_context(
        query_channel=channel,
        retrieved_threats=results,
    )

    return context, results


def main() -> None:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 70)
    print("FORMAL ADAPTIVE LEARNING EVALUATION")
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
    # VALIDATED SOURCE MESSAGE
    # ----------------------------------------------------------

    source_message = build_model_input(
        channel="EMAIL",
        subject="Security verification required",
        body=(
            "Your company account requires immediate security "
            "verification. Confirm your password now to prevent "
            "account suspension."
        ),
    )

    source_message_id = (
        "adaptive-evaluation-source-001"
    )

    # ----------------------------------------------------------
    # DIFFERENT FUTURE MESSAGE
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

    print("\nEvaluating future message BEFORE learning...")

    before_context, before_results = evaluate_query(
        retriever=retriever,
        embedder=embedder,
        message=future_message,
        channel="EMAIL",
    )

    # ----------------------------------------------------------
    # VALIDATED FEEDBACK
    # ----------------------------------------------------------

    print(
        "\nAdding validated phishing feedback..."
    )

    feedback = create_feedback_record(
        message_id=source_message_id,
        feedback_type="confirmed_phishing",
        corrected_label="phishing",
        source="admin",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text=source_message,
        sender="security-alert@example.com",
        receiver=None,
    )

    if not update.accepted:
        raise RuntimeError(
            "Validated feedback was not accepted."
        )

    adaptive_memory.add_document(
        update.document
    )

    # ----------------------------------------------------------
    # AFTER LEARNING
    # ----------------------------------------------------------

    print(
        "Evaluating the SAME future message AFTER learning..."
    )

    after_context, after_results = evaluate_query(
        retriever=retriever,
        embedder=embedder,
        message=future_message,
        channel="EMAIL",
    )

    # ----------------------------------------------------------
    # FIND NEWLY LEARNED EVIDENCE
    # ----------------------------------------------------------

    learned_similarity = None

    for result in after_results:

        if result.document_id == source_message_id:
            learned_similarity = result.similarity
            break

    # ----------------------------------------------------------
    # CALCULATE CHANGES
    # ----------------------------------------------------------

    similarity_change = (
        after_context.average_similarity
        - before_context.average_similarity
    )

    phishing_evidence_change = (
        after_context.similar_phishing_count
        - before_context.similar_phishing_count
    )

    legitimate_evidence_change = (
        after_context.similar_legitimate_count
        - before_context.similar_legitimate_count
    )

    # ----------------------------------------------------------
    # PRINT RESULTS
    # ----------------------------------------------------------

    print("\n" + "-" * 70)
    print("ADAPTIVE EVALUATION RESULTS")
    print("-" * 70)

    print(
        f"Before average similarity: "
        f"{before_context.average_similarity:.4f}"
    )

    print(
        f"After average similarity: "
        f"{after_context.average_similarity:.4f}"
    )

    print(
        f"Similarity change: "
        f"{similarity_change:+.4f}"
    )

    print(
        f"Before phishing evidence: "
        f"{before_context.similar_phishing_count}"
    )

    print(
        f"After phishing evidence: "
        f"{after_context.similar_phishing_count}"
    )

    print(
        f"Phishing evidence change: "
        f"{phishing_evidence_change:+d}"
    )

    print(
        f"Before legitimate evidence: "
        f"{before_context.similar_legitimate_count}"
    )

    print(
        f"After legitimate evidence: "
        f"{after_context.similar_legitimate_count}"
    )

    if learned_similarity is None:
        print(
            "\nNewly learned example retrieved: NO"
        )
    else:
        print(
            "\nNewly learned example retrieved: YES"
        )

        print(
            f"Similarity to future message: "
            f"{learned_similarity:.4f}"
        )

    # ----------------------------------------------------------
    # SAVE JSON
    # ----------------------------------------------------------

    results_json = {
        "experiment": (
            "Adaptive semantic threat-memory evaluation"
        ),
        "source_message_id": source_message_id,
        "query_channel": "EMAIL",
        "before_learning": {
            "retrieved_count": (
                before_context.retrieved_count
            ),
            "phishing_evidence": (
                before_context.similar_phishing_count
            ),
            "legitimate_evidence": (
                before_context.similar_legitimate_count
            ),
            "average_similarity": (
                before_context.average_similarity
            ),
        },
        "after_learning": {
            "retrieved_count": (
                after_context.retrieved_count
            ),
            "phishing_evidence": (
                after_context.similar_phishing_count
            ),
            "legitimate_evidence": (
                after_context.similar_legitimate_count
            ),
            "average_similarity": (
                after_context.average_similarity
            ),
        },
        "changes": {
            "average_similarity": similarity_change,
            "phishing_evidence": phishing_evidence_change,
            "legitimate_evidence": legitimate_evidence_change,
        },
        "newly_learned_example": {
            "retrieved": (
                learned_similarity is not None
            ),
            "similarity": learned_similarity,
        },
    }

    json_path = (
        OUTPUT_DIR / "adaptive_results.json"
    )

    with json_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            results_json,
            file,
            indent=2,
        )

    # ----------------------------------------------------------
    # SAVE CSV
    # ----------------------------------------------------------

    csv_path = (
        OUTPUT_DIR
        / "adaptive_retrieval_comparison.csv"
    )

    rows = [
        {
            "stage": "before_learning",
            "retrieved_count": (
                before_context.retrieved_count
            ),
            "phishing_evidence": (
                before_context.similar_phishing_count
            ),
            "legitimate_evidence": (
                before_context.similar_legitimate_count
            ),
            "average_similarity": (
                before_context.average_similarity
            ),
            "learned_example_similarity": "",
        },
        {
            "stage": "after_learning",
            "retrieved_count": (
                after_context.retrieved_count
            ),
            "phishing_evidence": (
                after_context.similar_phishing_count
            ),
            "legitimate_evidence": (
                after_context.similar_legitimate_count
            ),
            "average_similarity": (
                after_context.average_similarity
            ),
            "learned_example_similarity": (
                ""
                if learned_similarity is None
                else learned_similarity
            ),
        },
    ]

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys(),
        )

        writer.writeheader()
        writer.writerows(rows)

    # ----------------------------------------------------------
    # SAVE MARKDOWN REPORT
    # ----------------------------------------------------------

    report_path = (
        OUTPUT_DIR
        / "adaptive_evaluation_report.md"
    )

    learned_text = (
        "Yes"
        if learned_similarity is not None
        else "No"
    )

    learned_similarity_text = (
        "N/A"
        if learned_similarity is None
        else f"{learned_similarity:.4f}"
    )

    report = f"""# Adaptive Semantic Learning Evaluation

## Objective

Evaluate whether validated phishing feedback can expand the
threat-memory knowledge base and allow a semantically different
future message to retrieve the newly learned phishing example.

## Experimental Design

A validated phishing email was added to the adaptive threat
memory. A different email with similar semantic intent was then
evaluated before and after the knowledge update.

The Transformer classifier was not retrained during this
experiment.

## Results

| Metric | Before Learning | After Learning |
|---|---:|---:|
| Retrieved threats | {before_context.retrieved_count} | {after_context.retrieved_count} |
| Phishing evidence | {before_context.similar_phishing_count} | {after_context.similar_phishing_count} |
| Legitimate evidence | {before_context.similar_legitimate_count} | {after_context.similar_legitimate_count} |
| Average similarity | {before_context.average_similarity:.4f} | {after_context.average_similarity:.4f} |

### Changes

- Average similarity change: **{similarity_change:+.4f}**
- Phishing evidence change: **{phishing_evidence_change:+d}**
- Legitimate evidence change: **{legitimate_evidence_change:+d}**
- Newly learned example retrieved: **{learned_text}**
- Similarity to future message: **{learned_similarity_text}**

## Interpretation

The experiment demonstrates that validated feedback can be
converted into a threat-memory document, embedded using the
Hugging Face embedding model, and retrieved for a semantically
different future message.

The result demonstrates adaptive semantic retrieval rather than
Transformer retraining.

The observed similarity change should not be interpreted as a
change in classification accuracy. This experiment evaluates
retrieval behavior.

Because the initial threat memory already contained related
phishing examples, the experiment demonstrates incremental
adaptive retrieval rather than isolated detection improvement.

## Limitations

- This is a controlled semantic-retrieval experiment.
- The future message is manually constructed.
- The baseline memory already contains related phishing examples.
- The experiment does not establish a change in end-to-end
  classification accuracy.
- Transformer weights are unchanged.
"""

    report_path.write_text(
        report,
        encoding="utf-8",
    )

    print("\n" + "-" * 70)
    print("ARTIFACTS SAVED")
    print("-" * 70)

    print(json_path)
    print(csv_path)
    print(report_path)

    print("\n" + "=" * 70)
    print("FORMAL ADAPTIVE EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()