from __future__ import annotations

import pickle
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


from src.embeddings.embedding_model import (
    HuggingFaceEmbedder,
)

from src.rag.retriever import (
    ThreatRetriever,
)

from src.rag.gemini_adapter import (
    GeminiAdapter,
)

from src.rag.gemini_provider import (
    GeminiProvider,
)

from src.pipeline.detection_pipeline import (
    DetectionPipeline,
)

from src.pipeline.real_detector import (
    RealDetectionInput,
    RealPhishingDetector,
)

from src.fusion.risk_fusion import (
    RiskFusion,
)


THREAT_MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory.pkl"
)


def load_threat_memory():
    print("Loading threat memory...")

    with open(
        THREAT_MEMORY_PATH,
        "rb",
    ) as file:
        vector_store = pickle.load(file)

    print(
        f"Threat memory contains "
        f"{len(vector_store._documents)} documents."
    )

    return vector_store


def inspect_retrieval(
    title: str,
    detector: RealPhishingDetector,
    message: RealDetectionInput,
):
    print("\n" + "=" * 70)
    print(
        f"RAG RETRIEVAL: {title}"
    )
    print("=" * 70)

    context = detector._build_threat_context(
        message
    )

    print(
        f"Retrieved documents: "
        f"{context.retrieved_count}"
    )

    print(
        f"Phishing evidence count: "
        f"{context.similar_phishing_count}"
    )

    print(
        f"Legitimate evidence count: "
        f"{context.similar_legitimate_count}"
    )

    print(
        f"Average similarity: "
        f"{context.average_similarity:.4f}"
    )

    if not context.evidence:
        print(
            "\nNo historical messages "
            "passed the similarity threshold."
        )
        return

    print(
        "\nRetrieved historical evidence:"
    )

    for index, evidence in enumerate(
        context.evidence,
        start=1,
    ):
        print(
            f"\n--- Evidence {index} ---"
        )

        print(
            f"Document ID: "
            f"{evidence.document_id}"
        )

        print(
            f"Channel: "
            f"{evidence.channel}"
        )

        print(
            f"Label: "
            f"{evidence.label}"
        )

        print(
            f"Similarity: "
            f"{evidence.similarity:.4f}"
        )

        print(
            f"Sender: "
            f"{evidence.sender}"
        )

        print(
            f"Receiver: "
            f"{evidence.receiver}"
        )

        print("Text:")

        print(
            evidence.text[:500]
        )


def print_result(
    title: str,
    result,
):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

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
        f"Historical/RAG risk: "
        f"{result.historical_risk:.4f}"
    )

    print(
        f"Final risk score: "
        f"{result.risk_score:.2f}/100"
    )

    print(
        f"Classification: "
        f"{result.classification}"
    )

    print(
        f"Retrieved threats: "
        f"{result.retrieved_threat_count}"
    )

    print(
        f"Gemini used: "
        f"{result.gemini_used}"
    )

    print("\nRisk explanation:")

    for evidence in result.explanation.evidence:
        print(
            f"  - {evidence}"
        )


def main():
    # =========================================================
    # Load Threat Memory
    # =========================================================

    vector_store = load_threat_memory()

    # =========================================================
    # Load Embedding Model
    # =========================================================

    print(
        "\nLoading embedding model..."
    )

    embedder = HuggingFaceEmbedder()

    # =========================================================
    # Create RAG Retriever
    # =========================================================

    retriever = ThreatRetriever(
        vector_store=vector_store,
        similarity_threshold=0.70,
    )

    # =========================================================
    # Load Gemini Provider
    # =========================================================

    print(
        "Loading Gemini provider..."
    )

    gemini_provider = GeminiProvider()

    gemini_adapter = GeminiAdapter(
        provider=gemini_provider
    )

    print(
        "Gemini provider loaded."
    )

    # =========================================================
    # Create Detection Pipeline
    # =========================================================

    detection_pipeline = DetectionPipeline(
        risk_fusion=RiskFusion(),
        gemini_adapter=gemini_adapter,
    )

    # =========================================================
    # Load Real Detector
    # =========================================================

    print(
        "Loading phishing detector..."
    )

    detector = RealPhishingDetector(
        sender_profiles=None,
        relationship_profiles=None,
        threat_retriever=retriever,
        embedder=embedder,
        detection_pipeline=detection_pipeline,
    )

    # =========================================================
    # Test 1: Phishing Email
    # =========================================================

    phishing_email = RealDetectionInput(
        message_id="rag-test-email-001",
        channel="EMAIL",
        sender="security@example.com",
        receiver="student@example.com",
        subject="Urgent account verification required",
        body=(
            "Your account has been suspended. "
            "Verify your account immediately to avoid "
            "permanent suspension. Confirm your credentials "
            "now."
        ),
    )

    inspect_retrieval(
        "PHISHING EMAIL",
        detector,
        phishing_email,
    )

    result = detector.detect(
        phishing_email
    )

    print_result(
        "TEST 1: PHISHING EMAIL",
        result,
    )

    # =========================================================
    # Test 2: Legitimate Email
    # =========================================================

    legitimate_email = RealDetectionInput(
        message_id="rag-test-email-002",
        channel="EMAIL",
        sender="professor@university.edu",
        receiver="student@university.edu",
        subject="Project meeting tomorrow",
        body=(
            "The project review meeting will be held "
            "tomorrow at 10 AM. Please bring your "
            "presentation and progress report."
        ),
    )

    inspect_retrieval(
        "LEGITIMATE EMAIL",
        detector,
        legitimate_email,
    )

    result = detector.detect(
        legitimate_email
    )

    print_result(
        "TEST 2: LEGITIMATE EMAIL",
        result,
    )

    # =========================================================
    # Test 3: Phishing SMS
    # =========================================================

    phishing_sms = RealDetectionInput(
        message_id="rag-test-sms-001",
        channel="SMS",
        body=(
            "Your bank account requires immediate "
            "verification. Confirm your account now "
            "to prevent suspension."
        ),
    )

    inspect_retrieval(
        "PHISHING SMS",
        detector,
        phishing_sms,
    )

    result = detector.detect(
        phishing_sms
    )

    print_result(
        "TEST 3: PHISHING SMS",
        result,
    )

    # =========================================================
    # Test 4: Legitimate SMS
    # =========================================================

    legitimate_sms = RealDetectionInput(
        message_id="rag-test-sms-002",
        channel="SMS",
        body=(
            "Hi, the team meeting has been moved "
            "to 3 PM today. Please let everyone know."
        ),
    )

    inspect_retrieval(
        "LEGITIMATE SMS",
        detector,
        legitimate_sms,
    )

    result = detector.detect(
        legitimate_sms
    )

    print_result(
        "TEST 4: LEGITIMATE SMS",
        result,
    )

    # =========================================================
    # Complete
    # =========================================================

    print("\n" + "=" * 70)
    print(
        "RAG + GEMINI END-TO-END TEST COMPLETED"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()