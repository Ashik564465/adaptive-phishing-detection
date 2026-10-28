from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
)

from src.config.settings import PHISHING_MODEL_PATH

from src.layer1_identity.email_authentication import (
    parse_eml_text,
)
from src.layer1_identity.email_identity_features import (
    build_identity_features,
)
from src.layer1_identity.identity_scorer import (
    score_email_identity,
)

from src.layer3_behavior.behavioral_features import (
    build_behavioral_features,
)
from src.layer3_behavior.behavioral_scorer import (
    calculate_behavioral_risk,
)

from src.embeddings.embedding_model import (
    HuggingFaceEmbedder,
)

from src.rag.retriever import (
    ThreatRetriever,
)
from src.rag.context_builder import (
    build_threat_context,
)

from src.pipeline.detection_pipeline import (
    DetectionPipeline,
    DetectionResult,
)
from src.fusion.risk_fusion import (
    RiskFusion,
)


@dataclass(frozen=True)
class RealDetectionInput:
    message_id: str
    channel: str
    body: str

    subject: str = ""

    sender: str | None = None
    receiver: str | None = None
    timestamp: str | None = None

    raw_email: str | None = None


class RealPhishingDetector:
    """
    End-to-end phishing detection orchestrator.

    Layer 1:
        Email identity/authentication evidence.

    Layer 2:
        Trained DistilBERT phishing classifier.

    Layer 3:
        Sender and relationship behavioral intelligence.

    RAG:
        Historical semantic threat retrieval.

    Risk Fusion:
        Combines the independent evidence sources.

    Gemini is intentionally optional and can be attached
    through DetectionPipeline.
    """

    def __init__(
        self,
        sender_profiles: pd.DataFrame,
        relationship_profiles: pd.DataFrame,
        threat_retriever: ThreatRetriever | None = None,
        embedder: HuggingFaceEmbedder | None = None,
        detection_pipeline: DetectionPipeline | None = None,
        model_path: str | Path = PHISHING_MODEL_PATH,
    ):
        self.sender_profiles = sender_profiles
        self.relationship_profiles = relationship_profiles

        self.threat_retriever = threat_retriever
        self.embedder = embedder

        self.detection_pipeline = (
            detection_pipeline
            or DetectionPipeline(
                risk_fusion=RiskFusion()
            )
        )

        self.model_path = str(model_path)

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_path
        )

        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_path
        )

        self.device = torch.device(
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        self.model.to(self.device)
        self.model.eval()

    # =========================================================
    # Layer 2: Transformer
    # =========================================================

    @staticmethod
    def _build_model_input(
        message: RealDetectionInput,
    ) -> str:
        """
        Build the exact input format used during
        Transformer training.
        """

        channel = message.channel.upper()

        if channel == "EMAIL":
            return (
                "[CHANNEL] EMAIL "
                f"[SUBJECT] {message.subject} "
                f"[BODY] {message.body}"
            )

        if channel == "SMS":
            return (
                "[CHANNEL] SMS "
                f"[BODY] {message.body}"
            )

        raise ValueError(
            "channel must be EMAIL or SMS."
        )

    def _predict_phishing_probability(
        self,
        message: RealDetectionInput,
    ) -> float:
        """
        Predict phishing probability using the trained
        DistilBERT classifier.
        """

        text = self._build_model_input(
            message
        )

        encoded = self.tokenizer(
            text,
            truncation=True,
            max_length=256,
            return_tensors="pt",
        )

        encoded = {
            key: value.to(self.device)
            for key, value in encoded.items()
        }

        with torch.no_grad():
            outputs = self.model(
                **encoded
            )

            probabilities = torch.softmax(
                outputs.logits,
                dim=-1,
            )

        # Label mapping:
        # 0 = legitimate
        # 1 = phishing

        probability = float(
            probabilities[0, 1].item()
        )

        return max(
            0.0,
            min(
                1.0,
                probability,
            ),
        )

    # =========================================================
    # Layer 1: Identity
    # =========================================================

    def _identity_risk(
        self,
        message: RealDetectionInput,
    ) -> float:
        """
        Calculate email identity/authentication risk.

        If raw email headers are unavailable, no identity
        evidence is fabricated and the risk remains 0.
        """

        if message.channel.upper() != "EMAIL":
            return 0.0

        if not message.raw_email:
            return 0.0

        authentication = parse_eml_text(
            message.raw_email
        )

        features = build_identity_features(
            authentication
        )

        result = score_email_identity(
            features
        )

        # Layer 1 produces 0-100.
        # Risk fusion expects 0-1.

        return max(
            0.0,
            min(
                1.0,
                result.risk_score / 100.0,
            ),
        )

    # =========================================================
    # Layer 3: Behavioral Intelligence
    # =========================================================

    def _behavioral_risk(
        self,
        message: RealDetectionInput,
    ) -> float:
        """
        Calculate behavioral risk when historical profiles
        are available.

        If behavioral history is unavailable, return 0.0
        rather than fabricating evidence or failing detection.
        """

        if (
            self.sender_profiles is None
            or self.relationship_profiles is None
        ):
            return 0.0

        features = build_behavioral_features(
            sender_profiles=self.sender_profiles,
            relationship_profiles=self.relationship_profiles,
            sender=message.sender,
            receiver=message.receiver,
        )

        result = calculate_behavioral_risk(
            features=features,
        )

        return result.risk_score

    # =========================================================
    # RAG: Historical Threat Memory
    # =========================================================

    def _build_threat_context(
        self,
        message: RealDetectionInput,
    ):
        """
        Generate an embedding for the current message,
        retrieve semantically similar historical messages,
        and build the RAG threat context.

        The embedding model is separate from the primary
        phishing classifier.
        """

        channel = message.channel.upper()

        # RAG is optional.
        # If the embedding model or retriever is unavailable,
        # return an empty historical context rather than
        # fabricating evidence.

        if (
            self.embedder is None
            or self.threat_retriever is None
        ):
            return build_threat_context(
                query_channel=channel,
                retrieved_threats=[],
            )

        model_text = self._build_model_input(
            message
        )

        # The embedding model returns:
        # (1, 384) for a single message.
        #
        # VectorStore.search() expects:
        # (384,)
        #
        # Therefore unwrap the first dimension.

        embedding = self.embedder.encode(
            model_text,
            batch_size=1,
        )

        if embedding.ndim == 2:
            embedding = embedding[0]

        retrieved = self.threat_retriever.retrieve(
            query_embedding=embedding,
            top_k=1,
        )

        return build_threat_context(
            query_channel=channel,
            retrieved_threats=retrieved,
        )

    # =========================================================
    # Full Detection
    # =========================================================

    def detect(
        self,
        message: RealDetectionInput,
    ) -> DetectionResult:
        """
        Run the complete phishing detection pipeline.
        """

        channel = message.channel.upper()

        if channel not in {
            "EMAIL",
            "SMS",
        }:
            raise ValueError(
                "channel must be EMAIL or SMS."
            )

        # -----------------------------
        # Layer 2: Transformer
        # -----------------------------

        phishing_probability = (
            self._predict_phishing_probability(
                message
            )
        )

        # -----------------------------
        # Layer 1: Identity
        # -----------------------------

        identity_risk = self._identity_risk(
            message
        )

        # -----------------------------
        # Layer 3: Behavioral
        # -----------------------------

        behavioral_risk = self._behavioral_risk(
            message
        )

        # -----------------------------
        # RAG: Historical Threat Memory
        # -----------------------------

        threat_context = (
            self._build_threat_context(
                message
            )
        )

        # -----------------------------
        # Risk Fusion
        # -----------------------------

        return self.detection_pipeline.detect(
            message_id=message.message_id,
            channel=channel,
            phishing_probability=phishing_probability,
            identity_risk=identity_risk,
            behavioral_risk=behavioral_risk,
            threat_context=threat_context,
        )