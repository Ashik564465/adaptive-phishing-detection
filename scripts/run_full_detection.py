from __future__ import annotations

import pickle
import sys
from pathlib import Path


# ---------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


import pandas as pd

from src.config.settings import (
    PHISHING_MODEL_PATH,
)
from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)
from src.fusion.risk_fusion import (
    RiskFusion,
)
from src.pipeline.detection_pipeline import (
    DetectionPipeline,
)
from src.pipeline.real_detector import (
    RealDetectionInput,
    RealPhishingDetector,
)
from src.rag.gemini_adapter import (
    GeminiAdapter,
)
from src.rag.retriever import (
    ThreatRetriever,
)



# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

THREAT_MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory_train_only.pkl"
)


# ---------------------------------------------------------------------
# Load training-only threat memory
# ---------------------------------------------------------------------

def load_threat_memory():

    print(
        "Loading training-only threat memory..."
    )

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
        "Could not load a compatible "
        "threat memory."
    )


# ---------------------------------------------------------------------
# Build detector
# ---------------------------------------------------------------------

def build_detector():

    print()
    print(
        "Loading embedding model..."
    )

    embedder = HuggingFaceEmbedder(
        config=EmbeddingConfig(
            model_name=(
                "sentence-transformers/"
                "all-MiniLM-L6-v2"
            ),
            max_length=256,
        )
    )

    print()
    print(
        "Loading training-only threat memory..."
    )

    store = load_threat_memory()

    print(
        "Creating RAG retriever..."
    )

    retriever = ThreatRetriever(
        vector_store=store,
        similarity_threshold=0.60,
    )

    # ---------------------------------------------------------------
    # Gemini
    # ---------------------------------------------------------------

    print()
    print(
        "Creating Gemini adapter..."
    )

    try:

        from src.rag.gemini_provider import (
            GeminiProvider,
        )

        provider = GeminiProvider()

        gemini_adapter = GeminiAdapter(
            provider=provider
        )

        print(
            "Gemini provider enabled."
        )

    except Exception as error:

        print(
            "Gemini provider unavailable."
        )

        print(
            f"Reason: {error}"
        )

        print(
            "Using local deterministic reasoning fallback."
        )

        gemini_adapter = GeminiAdapter()

    # ---------------------------------------------------------------
    # Risk fusion
    # ---------------------------------------------------------------
# ---------------------------------------------------------------
# Calibrated risk fusion
# ---------------------------------------------------------------

# Frozen from validation calibration.
#
# NLP          = 0.50
# Identity     = 0.00
# Behavioral   = 0.20
# Historical   = 0.30
#
# Decision thresholds remain:
# SAFE        < 40
# SUSPICIOUS  40-69.99
# PHISHING    >= 70

    print()
    print(
        "Creating risk fusion..."
    )

    risk_fusion = RiskFusion(
        suspicious_threshold=40.0,
        phishing_threshold=70.0,
        nlp_weight=0.50,
        identity_weight=0.00,
        behavioral_weight=0.20,
        historical_weight=0.30,
    )

    # ---------------------------------------------------------------
    # Detection pipeline
    # ---------------------------------------------------------------

    detection_pipeline = DetectionPipeline(
        risk_fusion=risk_fusion,
        gemini_adapter=gemini_adapter,
    )

    # ---------------------------------------------------------------
    # Current dataset metadata
    # ---------------------------------------------------------------

    # The current unified dataset does not contain
    # receiver metadata, so relationship profiles
    # are intentionally unavailable.
    #
    # Sender profiles are also not passed here because
    # the current detector expects the profile structure
    # used by build_behavioral_features().
    #
    # For this demonstration, unavailable behavioral
    # evidence remains zero rather than being fabricated.

    sender_profiles = None
    relationship_profiles = None

    # ---------------------------------------------------------------
    # Real detector
    # ---------------------------------------------------------------

    print()
    print(
        "Creating RealPhishingDetector..."
    )

    detector = RealPhishingDetector(
        sender_profiles=sender_profiles,
        relationship_profiles=relationship_profiles,
        threat_retriever=retriever,
        embedder=embedder,
        detection_pipeline=detection_pipeline,
        model_path=PHISHING_MODEL_PATH,
    )

    print(
        "RealPhishingDetector ready."
    )

    return detector


# ---------------------------------------------------------------------
# Run one test case
# ---------------------------------------------------------------------

def run_case(
    detector,
    case_name,
    message,
):

    print()
    print(
        "=" * 70
    )

    print(
        case_name
    )

    print(
        "=" * 70
    )

    print(
        f"Channel: {message.channel}"
    )

    print(
        f"Message ID: {message.message_id}"
    )

    if message.sender:

        print(
            f"Sender: {message.sender}"
        )

    if message.subject:

        print(
            f"Subject: {message.subject}"
        )

    print()
    print(
        "Message:"
    )

    print(
        message.body
    )

    print()

    try:

        result = detector.detect(
            message
        )

    except Exception as error:

        print()
        print(
            "Detection failed."
        )

        print(
            f"Error: {error}"
        )

        return None

    print(
        "Detection completed."
    )

    print()
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

    print()
    print(
        "Explanation:"
    )

    if result.explanation.evidence:

        for evidence in (
            result.explanation.evidence
        ):

            print(
                f"  - {evidence}"
            )

    else:

        print(
            "  - No additional evidence."
        )

    return result


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():

    print()
    print(
        "=" * 70
    )

    print(
        "FULL END-TO-END PHISHING DETECTION TEST"
    )

    print(
        "=" * 70
    )

    detector = build_detector()

    # ---------------------------------------------------------------
    # Case 1: Phishing Email
    # ---------------------------------------------------------------

    phishing_email = RealDetectionInput(
        message_id=(
            "demo-phishing-email-001"
        ),
        channel="EMAIL",
        sender=(
            "security-alert@example.com"
        ),
        receiver=(
            "user@example.com"
        ),
        subject=(
            "Urgent account verification required"
        ),
        body=(
            "Your account has been suspended. "
            "You must verify your account immediately "
            "to avoid permanent closure. "
            "Please confirm your account credentials "
            "as soon as possible."
        ),
    )

    run_case(
        detector,
        "CASE 1: PHISHING EMAIL",
        phishing_email,
    )

    # ---------------------------------------------------------------
    # Case 2: Legitimate Email
    # ---------------------------------------------------------------

    legitimate_email = RealDetectionInput(
        message_id=(
            "demo-legitimate-email-001"
        ),
        channel="EMAIL",
        sender=(
            "team@example.com"
        ),
        receiver=(
            "user@example.com"
        ),
        subject=(
            "Tomorrow's team meeting"
        ),
        body=(
            "Hello everyone, "
            "this is a reminder that our team meeting "
            "is scheduled for tomorrow at 10 AM. "
            "Please bring your project updates."
        ),
    )

    run_case(
        detector,
        "CASE 2: LEGITIMATE EMAIL",
        legitimate_email,
    )

    # ---------------------------------------------------------------
    # Case 3: Phishing SMS
    # ---------------------------------------------------------------

    phishing_sms = RealDetectionInput(
        message_id=(
            "demo-phishing-sms-001"
        ),
        channel="SMS",
        sender="+10000000001",
        body=(
            "URGENT: Your bank account will be blocked "
            "today. Verify your account immediately "
            "to avoid suspension."
        ),
    )

    run_case(
        detector,
        "CASE 3: PHISHING SMS",
        phishing_sms,
    )

    # ---------------------------------------------------------------
    # Case 4: Legitimate SMS
    # ---------------------------------------------------------------

    legitimate_sms = RealDetectionInput(
        message_id=(
            "demo-legitimate-sms-001"
        ),
        channel="SMS",
        sender="+10000000002",
        body=(
            "Hi, just confirming that we will meet "
            "at the library tomorrow afternoon. "
            "See you then."
        ),
    )

    run_case(
        detector,
        "CASE 4: LEGITIMATE SMS",
        legitimate_sms,
    )

    print()
    print(
        "=" * 70
    )

    print(
        "END-TO-END TEST COMPLETE"
    )

    print(
        "=" * 70
    )


if __name__ == "__main__":
    main()