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

from src.config.settings import PHISHING_MODEL_PATH

from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)

from src.fusion.risk_fusion import RiskFusion

from src.pipeline.detection_pipeline import (
    DetectionPipeline,
)

from src.pipeline.real_detector import (
    RealDetectionInput,
    RealPhishingDetector,
)

from src.rag.gemini_adapter import GeminiAdapter
from src.rag.retriever import ThreatRetriever


THREAT_MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory_train_only.pkl"
)


def load_threat_memory():

    with open(
        THREAT_MEMORY_PATH,
        "rb",
    ) as file:

        loaded = pickle.load(file)

    if hasattr(
        loaded,
        "search",
    ):
        return loaded

    if isinstance(
        loaded,
        dict,
    ):

        for key in [
            "vector_store",
            "store",
            "memory",
            "threat_memory",
        ]:

            if (
                key in loaded
                and hasattr(
                    loaded[key],
                    "search",
                )
            ):

                return loaded[key]

    raise TypeError(
        "Could not load a compatible threat memory."
    )


def build_detector(
    embedder,
    store,
):

    retriever = ThreatRetriever(
        vector_store=store,
        similarity_threshold=0.60,
    )

    # Use deterministic local reasoning for this
    # controlled experiment. The adaptive effect being
    # measured comes from the threat-memory update.
    gemini_adapter = GeminiAdapter()

    risk_fusion = RiskFusion(
        suspicious_threshold=40.0,
        phishing_threshold=70.0,
        nlp_weight=0.50,
        identity_weight=0.00,
        behavioral_weight=0.20,
        historical_weight=0.30,
    )

    detection_pipeline = DetectionPipeline(
        risk_fusion=risk_fusion,
        gemini_adapter=gemini_adapter,
    )

    detector = RealPhishingDetector(
        sender_profiles=None,
        relationship_profiles=None,
        threat_retriever=retriever,
        embedder=embedder,
        detection_pipeline=detection_pipeline,
        model_path=PHISHING_MODEL_PATH,
    )

    return detector


def print_result(
    title,
    result,
):

    print()
    print("-" * 70)
    print(title)
    print("-" * 70)

    print(
        f"Transformer phishing probability: "
        f"{result.phishing_probability:.4f}"
    )

    print(
        f"Identity risk: "
        f"{result.identity_risk:.4f}"
    )

    print(
        f"Behavioral risk: "
        f"{result.behavioral_risk:.4f}"
    )

    print(
        f"Historical risk: "
        f"{result.historical_risk:.4f}"
    )

    print(
        f"Retrieved threats: "
        f"{result.retrieved_threat_count}"
    )

    print(
        f"Gemini used: "
        f"{result.gemini_used}"
    )

    print()
    print(
        f"FINAL RISK SCORE: "
        f"{result.risk_score:.2f}/100"
    )

    print(
        f"FINAL CLASSIFICATION: "
        f"{result.classification}"
    )


def main():

    print("=" * 70)
    print("ADAPTIVE RISK PIPELINE TEST")
    print("=" * 70)

    print("\nLoading embedding model...")

    embedder = HuggingFaceEmbedder(
        config=EmbeddingConfig(
            model_name=(
                "sentence-transformers/"
                "all-MiniLM-L6-v2"
            ),
            max_length=256,
        )
    )

    print("Loading training-only threat memory...")

    store = load_threat_memory()

    adaptive_memory = AdaptiveMemory(
        embedder=embedder,
        vector_store=store,
    )

    detector = build_detector(
        embedder=embedder,
        store=store,
    )

    # ==========================================================
    # SOURCE MESSAGE
    # ==========================================================

    learned_message_text = (
        "[CHANNEL] EMAIL "
        "[SUBJECT] Security verification required "
        "[BODY] Your company account requires immediate "
        "security verification. Confirm your password now "
        "to prevent account suspension."
    )

    # ==========================================================
    # FUTURE MESSAGE
    #
    # Different wording from the source message.
    # ==========================================================

    future_message = RealDetectionInput(
        message_id=(
            "adaptive-risk-future-001"
        ),
        channel="EMAIL",
        sender=(
            "security-notice@example.com"
        ),
        receiver=(
            "user@example.com"
        ),
        subject=(
            "Corporate account security notice"
        ),
        body=(
            "Your workplace account is about to be "
            "disabled. Please verify your password "
            "immediately to keep access to your account."
        ),
    )

    # ==========================================================
    # BEFORE ADAPTATION
    # ==========================================================

    print()
    print("=" * 70)
    print("BEFORE ADAPTIVE KNOWLEDGE UPDATE")
    print("=" * 70)

    before_result = detector.detect(
        future_message
    )

    print_result(
        "FUTURE MESSAGE BEFORE LEARNING",
        before_result,
    )

    # ==========================================================
    # VALIDATED FEEDBACK
    # ==========================================================

    print()
    print("=" * 70)
    print("ADDING VALIDATED PHISHING KNOWLEDGE")
    print("=" * 70)

    feedback = create_feedback_record(
        message_id=(
            "adaptive-risk-source-001"
        ),
        feedback_type="confirmed_phishing",
        corrected_label="phishing",
        source="admin",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text=learned_message_text,
        sender="security-alert@example.com",
        receiver=None,
    )

    print(
        f"Knowledge update accepted: "
        f"{update.accepted}"
    )

    print(
        f"Reason: "
        f"{update.reason}"
    )

    if not update.accepted:
        raise RuntimeError(
            "Validated phishing feedback was rejected."
        )

    adaptive_memory.add_document(
        update.document
    )

    print(
        "Validated phishing example added "
        "to adaptive threat memory."
    )

    # ==========================================================
    # AFTER ADAPTATION
    # ==========================================================

    print()
    print("=" * 70)
    print("AFTER ADAPTIVE KNOWLEDGE UPDATE")
    print("=" * 70)

    after_result = detector.detect(
        future_message
    )

    print_result(
        "SAME FUTURE MESSAGE AFTER LEARNING",
        after_result,
    )

    # ==========================================================
    # CHANGE
    # ==========================================================

    risk_change = (
        after_result.risk_score
        - before_result.risk_score
    )

    historical_change = (
        after_result.historical_risk
        - before_result.historical_risk
    )

    print()
    print("=" * 70)
    print("ADAPTIVE RISK CHANGE")
    print("=" * 70)

    print(
        f"Risk score before learning: "
        f"{before_result.risk_score:.2f}"
    )

    print(
        f"Risk score after learning: "
        f"{after_result.risk_score:.2f}"
    )

    print(
        f"Risk score change: "
        f"{risk_change:+.2f}"
    )

    print(
        f"Historical risk before learning: "
        f"{before_result.historical_risk:.4f}"
    )

    print(
        f"Historical risk after learning: "
        f"{after_result.historical_risk:.4f}"
    )

    print(
        f"Historical risk change: "
        f"{historical_change:+.4f}"
    )

    print()
    print("=" * 70)
    print("ADAPTIVE RISK PIPELINE TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()