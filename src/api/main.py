from __future__ import annotations

import pickle
import importlib
import os
import sys
from pathlib import Path

import numpy as np

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from src.adaptive.feedback import create_feedback_record
from src.adaptive.knowledge_updater import (
    update_knowledge_from_feedback,
)
from src.adaptive.persistent_memory import (
    PersistentAdaptiveMemory,
)
from src.adaptive.storage import (
    S3AdaptiveMemoryStorage,
)
from src.config.settings import PHISHING_MODEL_PATH
from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)
from src.fusion.risk_fusion import RiskFusion
from src.pipeline.detection_pipeline import DetectionPipeline
from src.pipeline.real_detector import (
    RealDetectionInput,
    RealPhishingDetector,
)
from src.rag.gemini_adapter import GeminiAdapter
from src.rag.retriever import (
    ThreatRetriever,
    VectorSearchResult,
)


app = FastAPI(
    title="Adaptive Phishing Detection API",
    description=(
        "Multi-layer adaptive phishing detection for "
        "email and SMS messages."
    ),
    version="1.0.0",
)


# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------

THREAT_MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory_train_only.pkl"
)

ADAPTIVE_MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "adaptive_threat_memory.pkl"
)


# ------------------------------------------------------------------
# Request models
# ------------------------------------------------------------------

class DetectionRequest(BaseModel):

    message_id: str = Field(
        min_length=1
    )

    channel: str

    body: str = Field(
        min_length=1
    )

    subject: str = ""

    sender: str | None = None

    receiver: str | None = None

    timestamp: str | None = None

    raw_email: str | None = None


class FeedbackRequest(BaseModel):

    message_id: str = Field(
        min_length=1
    )

    feedback_type: str

    corrected_label: str | None = None

    source: str = "user"

    channel: str

    body: str = Field(
        min_length=1
    )

    subject: str = ""

    sender: str | None = None

    receiver: str | None = None


# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------

_embedder = None
_frozen_store = None
_adaptive_memory = None
_combined_store = None
_detector = None


# ------------------------------------------------------------------
# Combined threat-memory store
# ------------------------------------------------------------------

class CombinedThreatMemoryStore:
    """
    Search both frozen training memory and persistent
    adaptive threat memory.

    Frozen memory:
        threat_memory_train_only.pkl

    Adaptive memory:
        adaptive_threat_memory.pkl
    """

    def __init__(
        self,
        frozen_store,
        adaptive_memory,
    ):
        self.frozen_store = frozen_store
        self.adaptive_memory = adaptive_memory

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
    ):
        """
        Search both memory stores and return the highest
        similarity results combined.
        """

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1."
            )

        frozen_results = self.frozen_store.search(
            query_embedding=query_embedding,
            top_k=top_k,
        )

        adaptive_results = self.adaptive_memory.search(
            query_embedding=query_embedding,
            top_k=top_k,
        )

        combined = list(frozen_results)

        for result in adaptive_results:
            combined.append(
                result
            )

        combined.sort(
            key=lambda result: result.similarity,
            reverse=True,
        )

        return combined[:top_k]


# ------------------------------------------------------------------
# Threat-memory loader
# ------------------------------------------------------------------

def load_threat_memory():

    if not THREAT_MEMORY_PATH.exists():

        raise FileNotFoundError(
            "Training-only threat memory not found: "
            f"{THREAT_MEMORY_PATH}"
        )

    with THREAT_MEMORY_PATH.open(
        "rb"
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


# ------------------------------------------------------------------
# Initialize detector
# ------------------------------------------------------------------

def initialize_system():

    global _embedder
    global _frozen_store
    global _adaptive_memory
    global _combined_store
    global _detector

    print(
        "Loading embedding model..."
    )

    _embedder = HuggingFaceEmbedder(
        config=EmbeddingConfig(
            model_name=(
                "sentence-transformers/"
                "all-MiniLM-L6-v2"
            ),
            max_length=256,
        )
    )

    # --------------------------------------------------------------
    # Frozen training-only threat memory
    # --------------------------------------------------------------

    print(
        "Loading training-only threat memory..."
    )

    _frozen_store = load_threat_memory()

    # --------------------------------------------------------------
    # Persistent adaptive memory
    # --------------------------------------------------------------

    print(
        "Loading persistent adaptive threat memory..."
    )

    _adaptive_memory = build_adaptive_memory(
        embedder=_embedder,
    )

    print(
        "Adaptive memory documents:",
        _adaptive_memory.count(),
    )

    # --------------------------------------------------------------
    # Combined retrieval
    # --------------------------------------------------------------

    _combined_store = CombinedThreatMemoryStore(
        frozen_store=_frozen_store,
        adaptive_memory=_adaptive_memory,
    )

    retriever = ThreatRetriever(
        vector_store=_combined_store,
        similarity_threshold=0.60,
    )

    # --------------------------------------------------------------
    # Gemini is optional
    # --------------------------------------------------------------

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

        gemini_adapter = GeminiAdapter()

    # --------------------------------------------------------------
    # Frozen calibrated configuration
    # --------------------------------------------------------------

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

    # --------------------------------------------------------------
    # Real detector
    # --------------------------------------------------------------

    _detector = RealPhishingDetector(
        sender_profiles=None,
        relationship_profiles=None,
        threat_retriever=retriever,
        embedder=_embedder,
        detection_pipeline=detection_pipeline,
        model_path=PHISHING_MODEL_PATH,
    )

    print(
        "Adaptive phishing detector ready."
    )


def build_adaptive_memory(
    embedder: HuggingFaceEmbedder,
) -> PersistentAdaptiveMemory:
    storage_mode = os.getenv(
        "ADAPTIVE_MEMORY_STORAGE",
        "local",
    ).strip().lower()

    if storage_mode == "local":
        return PersistentAdaptiveMemory(
            embedder=embedder,
            path=ADAPTIVE_MEMORY_PATH,
        )

    if storage_mode != "s3":
        raise ValueError(
            "ADAPTIVE_MEMORY_STORAGE must be 'local' or 's3'."
        )

    bucket = os.getenv(
        "ADAPTIVE_MEMORY_S3_BUCKET",
        "",
    )
    key = os.getenv(
        "ADAPTIVE_MEMORY_S3_KEY",
        "adaptive/adaptive_threat_memory.pkl",
    )
    allow_initialize = os.getenv(
        "ADAPTIVE_MEMORY_S3_ALLOW_INITIALIZE",
        "false",
    ).strip().lower() == "true"

    if not bucket.strip():
        raise ValueError(
            "ADAPTIVE_MEMORY_S3_BUCKET is required when "
            "ADAPTIVE_MEMORY_STORAGE=s3."
        )

    boto3 = importlib.import_module("boto3")
    storage = S3AdaptiveMemoryStorage(
        client=boto3.client("s3"),
        bucket=bucket,
        key=key,
        allow_initialize=allow_initialize,
    )
    return PersistentAdaptiveMemory(
        embedder=embedder,
        storage=storage,
    )


@app.on_event("startup")
def startup_event():

    initialize_system()


# ------------------------------------------------------------------
# Health endpoint
# ------------------------------------------------------------------

@app.get("/health")
def health():

    adaptive_count = 0

    if _adaptive_memory is not None:

        adaptive_count = (
            _adaptive_memory.count()
        )

    return {
        "status": "ok",
        "service": "adaptive-phishing-detection",
        "adaptive_memory_documents": adaptive_count,
    }


# ------------------------------------------------------------------
# Detection endpoint
# ------------------------------------------------------------------

@app.post("/detect")
def detect_message(
    request: DetectionRequest,
):

    if _detector is None:

        raise HTTPException(
            status_code=503,
            detail=(
                "Detection system is not initialized."
            ),
        )

    channel = request.channel.upper()

    if channel not in {
        "EMAIL",
        "SMS",
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "channel must be EMAIL or SMS."
            ),
        )

    message = RealDetectionInput(
        message_id=request.message_id,
        channel=channel,
        body=request.body,
        subject=request.subject,
        sender=request.sender,
        receiver=request.receiver,
        timestamp=request.timestamp,
        raw_email=request.raw_email,
    )

    try:

        result = _detector.detect(
            message
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    return {
        "message_id": result.message_id,
        "channel": result.channel,
        "phishing_probability": (
            result.phishing_probability
        ),
        "identity_risk": (
            result.identity_risk
        ),
        "behavioral_risk": (
            result.behavioral_risk
        ),
        "historical_risk": (
            result.historical_risk
        ),
        "risk_score": result.risk_score,
        "classification": result.classification,
        "retrieved_threat_count": (
            result.retrieved_threat_count
        ),
        "gemini_used": result.gemini_used,
        "explanation": (
            result.explanation.evidence
        ),
    }


# ------------------------------------------------------------------
# Feedback endpoint
# ------------------------------------------------------------------

@app.post("/feedback")
def submit_feedback(
    request: FeedbackRequest,
):

    if _adaptive_memory is None:

        raise HTTPException(
            status_code=503,
            detail=(
                "Adaptive memory is not initialized."
            ),
        )

    channel = request.channel.upper()

    if channel not in {
        "EMAIL",
        "SMS",
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "channel must be EMAIL or SMS."
            ),
        )

    if request.corrected_label not in {
        "phishing",
        "legitimate",
        None,
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "corrected_label must be phishing, "
                "legitimate, or null."
            ),
        )

    try:

        feedback = create_feedback_record(
            message_id=request.message_id,
            feedback_type=request.feedback_type,
            corrected_label=request.corrected_label,
            source=request.source,
        )

        # ----------------------------------------------------------
        # Reconstruct the exact model-format text used by the
        # Transformer and embedding pipeline.
        # ----------------------------------------------------------

        if channel == "EMAIL":

            message_text = (
                "[CHANNEL] EMAIL "
                f"[SUBJECT] {request.subject} "
                f"[BODY] {request.body}"
            )

        else:

            message_text = (
                "[CHANNEL] SMS "
                f"[BODY] {request.body}"
            )

        update = update_knowledge_from_feedback(
            feedback=feedback,
            channel=channel,
            text=message_text,
            sender=request.sender,
            receiver=request.receiver,
        )

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    # --------------------------------------------------------------
    # Feedback without a validated label does not update memory.
    # --------------------------------------------------------------

    if not update.accepted:

        return {
            "accepted": False,
            "message_id": feedback.message_id,
            "feedback_type": feedback.feedback_type,
            "corrected_label": (
                feedback.corrected_label
            ),
            "reason": update.reason,
            "knowledge_updated": False,
        }

    # --------------------------------------------------------------
    # Add validated knowledge to persistent adaptive memory.
    #
    # PersistentAdaptiveMemory.add_document():
    #   1. creates embedding
    #   2. adds document to adaptive vector store
    #   3. saves adaptive_threat_memory.pkl
    #
    # CombinedThreatMemoryStore automatically makes this new
    # document available to future detection requests.
    # --------------------------------------------------------------

    try:

        _adaptive_memory.add_document(
            update.document
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to persist adaptive knowledge: "
                f"{error}"
            ),
        )

    return {
        "accepted": True,
        "message_id": feedback.message_id,
        "feedback_type": feedback.feedback_type,
        "corrected_label": (
            feedback.corrected_label
        ),
        "reason": update.reason,
        "knowledge_updated": True,
        "adaptive_memory_documents": (
            _adaptive_memory.count()
        ),
    }