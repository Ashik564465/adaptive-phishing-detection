from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from src.config.settings import (
    PHISHING_MODEL_PATH,
    RANDOM_SEED,
)

from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)

from src.rag.retriever import (
    ThreatRetriever,
)

from src.rag.context_builder import (
    build_threat_context,
)

from src.layer2_nlp.transformer_classifier import (
    split_dataset,
)

from src.layer3_behavior.sender_profile import (
    build_sender_profiles,
)

from src.layer3_behavior.relationship_graph import (
    build_relationship_profiles,
)

from src.layer3_behavior.behavioral_features import (
    build_behavioral_features,
)

from src.fusion.risk_fusion import (
    RiskFusion,
    RiskFusionInput,
)


# ============================================================
# PATHS
# ============================================================

MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory_train_only.pkl"
)

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

OUTPUT_DIR = (
    PROJECT_ROOT
    / "models"
    / "ablation"
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_LENGTH = 256

BATCH_SIZE = 4

TOP_K = 5

SIMILARITY_THRESHOLD = 0.70


# ============================================================
# TEXT BUILDING
# ============================================================

def build_model_text(row: pd.Series) -> str:
    """
    Build exactly the same model input format used by
    the Layer 2 Transformer.
    """

    channel = str(
        row["channel"]
    ).upper()

    if channel == "EMAIL":
        subject = str(
            row.get("subject", "")
            or ""
        )

        body = str(
            row.get("body", "")
            or ""
        )

        return (
            f"[CHANNEL] EMAIL "
            f"[SUBJECT] {subject} "
            f"[BODY] {body}"
        )

    return (
        f"[CHANNEL] SMS "
        f"[BODY] "
        f"{row.get('body', '') or ''}"
    )


# ============================================================
# DATA LOADING
# ============================================================

def load_dataset() -> pd.DataFrame:
    """
    Load the processed email and SMS datasets and
    create the same unified dataset used by training.
    """

    email = pd.read_parquet(
        EMAIL_PATH
    )

    sms = pd.read_parquet(
        SMS_PATH
    )

    return pd.concat(
        [
            email,
            sms,
        ],
        ignore_index=True,
    )


def load_test_split(
    frame: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Reproduce the same duplicate-aware split used
    during Transformer training.
    """

    train_df, _, test_df = split_dataset(
        frame,
        seed=RANDOM_SEED,
    )

    return (
        train_df,
        test_df,
    )


# ============================================================
# TRANSFORMER
# ============================================================

def load_transformer():
    """
    Load the trained phishing Transformer.
    """

    model_path = Path(
        PHISHING_MODEL_PATH
    )

    tokenizer = (
        AutoTokenizer.from_pretrained(
            model_path
        )
    )

    model = (
        AutoModelForSequenceClassification
        .from_pretrained(
            model_path
        )
    )

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    model.to(device)

    model.eval()

    print(
        f"Transformer device: {device}"
    )

    return (
        tokenizer,
        model,
        device,
    )


def predict_transformer(
    rows: pd.DataFrame,
    tokenizer,
    model,
    device,
) -> np.ndarray:
    """
    Generate phishing probabilities using
    the trained Transformer.
    """

    probabilities = []

    texts = [
        build_model_text(row)
        for _, row in rows.iterrows()
    ]

    for start in range(
        0,
        len(texts),
        BATCH_SIZE,
    ):
        batch = texts[
            start:start + BATCH_SIZE
        ]

        encoded = tokenizer(
            batch,
            padding=True,
            truncation=True,
            max_length=MAX_LENGTH,
            return_tensors="pt",
        )

        encoded = {
            key: value.to(device)
            for key, value in encoded.items()
        }

        with torch.no_grad():

            outputs = model(
                **encoded
            )

            probs = torch.softmax(
                outputs.logits,
                dim=-1,
            )[:, 1]

        probabilities.extend(
            probs.detach()
            .cpu()
            .numpy()
            .tolist()
        )

        del encoded
        del outputs
        del probs

        if device.type == "cuda":
            torch.cuda.empty_cache()

    return np.asarray(
        probabilities,
        dtype=np.float32,
    )


# ============================================================
# HISTORICAL RISK
# ============================================================

def calculate_historical_risk(
    context,
) -> float:
    """
    Calculate historical phishing risk.

    Legitimate-only retrieved evidence contributes
    zero phishing risk.

    Mixed evidence is weighted by:

        phishing evidence ratio × similarity
    """

    if context.retrieved_count == 0:
        return 0.0

    total = (
        context.similar_phishing_count
        + context.similar_legitimate_count
    )

    if total == 0:
        return 0.0

    if context.similar_phishing_count == 0:
        return 0.0

    phishing_ratio = (
        context.similar_phishing_count
        / total
    )

    similarity = max(
        0.0,
        min(
            1.0,
            context.average_similarity,
        ),
    )

    return float(
        phishing_ratio
        * similarity
    )


# ============================================================
# BEHAVIORAL RISK
# ============================================================

def calculate_behavioral_risk(
    features,
) -> float:
    """
    Convert behavioral evidence into a bounded
    engineering risk signal.

    This is not a calibrated probability.
    """

    signals = []

    if features.sender_known:
        signals.append(
            features.sender_phishing_rate
        )

    if features.relationship_known:
        signals.append(
            features.relationship_phishing_rate
        )

    if features.relationship_novelty:
        signals.append(
            0.5
        )

    if not signals:
        return 0.0

    return float(
        max(
            0.0,
            min(
                1.0,
                sum(signals)
                / len(signals),
            ),
        )
    )


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    actual: np.ndarray,
    probabilities: np.ndarray,
) -> dict:
    """
    Calculate classification metrics.
    """

    predicted = (
        probabilities >= 0.5
    ).astype(int)

    tn, fp, fn, tp = (
        confusion_matrix(
            actual,
            predicted,
            labels=[0, 1],
        ).ravel()
    )

    return {
        "samples": int(
            len(actual)
        ),

        "accuracy": float(
            accuracy_score(
                actual,
                predicted,
            )
        ),

        "precision": float(
            precision_score(
                actual,
                predicted,
                zero_division=0,
            )
        ),

        "recall": float(
            recall_score(
                actual,
                predicted,
                zero_division=0,
            )
        ),

        "f1": float(
            f1_score(
                actual,
                predicted,
                zero_division=0,
            )
        ),

        "roc_auc": float(
            roc_auc_score(
                actual,
                probabilities,
            )
        ),

        "true_negative": int(
            tn
        ),

        "false_positive": int(
            fp
        ),

        "false_negative": int(
            fn
        ),

        "true_positive": int(
            tp
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    print(
        "Loading dataset..."
    )

    frame = load_dataset()

    print(
        f"Total rows: {len(frame)}"
    )

    train_df, test_df = (
        load_test_split(frame)
    )

    print(
        f"Training rows: "
        f"{len(train_df)}"
    )

    print(
        f"Test rows: "
        f"{len(test_df)}"
    )

    # --------------------------------------------------------
    # Load training-only threat memory
    # --------------------------------------------------------

    print()

    print(
        "Loading training-only "
        "threat memory..."
    )

    with open(
        MEMORY_PATH,
        "rb",
    ) as file:

        memory_payload = pickle.load(
            file
        )

    vector_store = (
        memory_payload["store"]
    )

    print(
        "Threat memory documents: "
        f"{len(memory_payload['documents'])}"
    )

    retriever = ThreatRetriever(
        vector_store=vector_store,
        similarity_threshold=(
            SIMILARITY_THRESHOLD
        ),
    )

    # --------------------------------------------------------
    # Load embedding model
    # --------------------------------------------------------

    print()

    print(
        "Loading embedding model..."
    )

    embedder = HuggingFaceEmbedder(
        EmbeddingConfig(
            max_length=MAX_LENGTH
        )
    )

    # --------------------------------------------------------
    # Load Transformer
    # --------------------------------------------------------

    print(
        "Loading Transformer..."
    )

    (
        tokenizer,
        model,
        device,
    ) = load_transformer()

    # --------------------------------------------------------
    # Transformer predictions
    # --------------------------------------------------------

    print()

    print(
        "Generating Transformer predictions..."
    )

    transformer_probabilities = (
        predict_transformer(
            test_df,
            tokenizer,
            model,
            device,
        )
    )

    actual = (
        test_df["label"]
        .map(
            {
                "legitimate": 0,
                "phishing": 1,
            }
        )
        .astype(int)
        .to_numpy()
    )

    print(
        "Transformer predictions complete."
    )

    # --------------------------------------------------------
    # Behavioral profiles
    #
    # IMPORTANT:
    # Build all behavioral profiles from TRAIN ONLY.
    # --------------------------------------------------------

    print()

    print(
        "Building behavioral profiles "
        "from TRAIN ONLY..."
    )

    sender_profiles = (
        build_sender_profiles(
            train_df[
                [
                    "sender",
                    "label",
                    "timestamp",
                ]
            ]
        )
    )

    print(
        f"Sender profiles: "
        f"{len(sender_profiles)}"
    )

    # --------------------------------------------------------
    # Relationship profiles
    #
    # Do not fabricate receiver metadata.
    # --------------------------------------------------------

    if "receiver" in train_df.columns:

        relationship_profiles = (
            build_relationship_profiles(
                train_df[
                    [
                        "sender",
                        "receiver",
                        "label",
                    ]
                ]
            )
        )

        print(
            "Relationship profiles: "
            f"{len(relationship_profiles)}"
        )

    else:

        relationship_profiles = {}

        print(
            "Receiver metadata unavailable "
            "in unified dataset."
        )

        print(
            "Relationship-based behavioral "
            "features will be treated as "
            "unavailable."
        )

    # --------------------------------------------------------
    # Generate RAG + behavioral signals
    # --------------------------------------------------------

    print()

    print(
        "Generating RAG and behavioral "
        "signals..."
    )

    historical_risks = []

    behavioral_risks = []

    retrieved_counts = []

    total_rows = len(
        test_df
    )

    for index, (_, row) in enumerate(
        test_df.iterrows(),
        start=1,
    ):

        # ----------------------------------------------------
        # Embedding
        # ----------------------------------------------------

        text = build_model_text(
            row
        )

        embedding = embedder.encode(
            text,
            batch_size=1,
        )

        # ----------------------------------------------------
        # RAG retrieval
        # ----------------------------------------------------

        retrieved = (
            retriever.retrieve(
                query_embedding=embedding,
                top_k=TOP_K,
            )
        )

        context = (
            build_threat_context(
                query_channel=str(
                    row["channel"]
                ),
                retrieved_threats=retrieved,
            )
        )

        historical_risk = (
            calculate_historical_risk(
                context
            )
        )

        # ----------------------------------------------------
        # Safely extract sender
        # ----------------------------------------------------

        sender_value = None

        if "sender" in row.index:

            if pd.notna(
                row["sender"]
            ):

                sender_value = (
                    str(
                        row["sender"]
                    ).strip()
                    or None
                )

        # ----------------------------------------------------
        # Safely extract receiver
        # ----------------------------------------------------

        receiver_value = None

        if "receiver" in row.index:

            if pd.notna(
                row["receiver"]
            ):

                receiver_value = (
                    str(
                        row["receiver"]
                    ).strip()
                    or None
                )

        # ----------------------------------------------------
        # Behavioral features
        # ----------------------------------------------------

        behavioral_features = (
            build_behavioral_features(
                sender_profiles=(
                    sender_profiles
                ),

                relationship_profiles=(
                    relationship_profiles
                ),

                sender=sender_value,

                receiver=receiver_value,
            )
        )

        behavioral_risk = (
            calculate_behavioral_risk(
                behavioral_features
            )
        )

        historical_risks.append(
            historical_risk
        )

        behavioral_risks.append(
            behavioral_risk
        )

        retrieved_counts.append(
            context.retrieved_count
        )

        if index % 500 == 0:

            print(
                f"Processed "
                f"{index}/"
                f"{total_rows}"
            )

    historical_risks = np.asarray(
        historical_risks,
        dtype=np.float32,
    )

    behavioral_risks = np.asarray(
        behavioral_risks,
        dtype=np.float32,
    )

    retrieved_counts = np.asarray(
        retrieved_counts,
        dtype=np.int32,
    )

    # --------------------------------------------------------
    # Risk fusion
    # --------------------------------------------------------

    fusion = RiskFusion()

    experiment_probabilities = {}

    # ========================================================
    # A: Transformer only
    # ========================================================

    experiment_probabilities[
        "A_Transformer"
    ] = transformer_probabilities

    # ========================================================
    # B: Transformer + RAG
    # ========================================================

    rag_probabilities = []

    for nlp, historical in zip(
        transformer_probabilities,
        historical_risks,
    ):

        result = fusion.fuse(
            RiskFusionInput(
                nlp_phishing_probability=(
                    float(nlp)
                ),

                identity_risk=0.0,

                behavioral_risk=0.0,

                historical_risk=(
                    float(historical)
                ),
            )
        )

        rag_probabilities.append(
            result.risk_score / 100.0
        )

    experiment_probabilities[
        "B_Transformer_RAG"
    ] = np.asarray(
        rag_probabilities,
        dtype=np.float32,
    )

    # ========================================================
    # C: Gemini
    #
    # Reserved for controlled Gemini evaluation.
    # ========================================================

    # Gemini is intentionally not called thousands
    # of times in this deterministic full-test run.

    # ========================================================
    # D: Transformer + RAG + Behavioral
    # ========================================================

    full_probabilities = []

    for (
        nlp,
        historical,
        behavioral,
    ) in zip(
        transformer_probabilities,
        historical_risks,
        behavioral_risks,
    ):

        result = fusion.fuse(
            RiskFusionInput(
                nlp_phishing_probability=(
                    float(nlp)
                ),

                identity_risk=0.0,

                behavioral_risk=(
                    float(behavioral)
                ),

                historical_risk=(
                    float(historical)
                ),
            )
        )

        full_probabilities.append(
            result.risk_score / 100.0
        )

    experiment_probabilities[
        "D_Transformer_RAG_Behavioral"
    ] = np.asarray(
        full_probabilities,
        dtype=np.float32,
    )

    # --------------------------------------------------------
    # Overall metrics
    # --------------------------------------------------------

    results = []

    for (
        name,
        probabilities,
    ) in experiment_probabilities.items():

        metrics = calculate_metrics(
            actual,
            probabilities,
        )

        metrics[
            "experiment"
        ] = name

        results.append(
            metrics
        )

    results_df = pd.DataFrame(
        results
    )

    # --------------------------------------------------------
    # Per-channel metrics
    # --------------------------------------------------------

    channel_results = []

    for channel in [
        "EMAIL",
        "SMS",
    ]:

        mask = (
            test_df["channel"]
            .to_numpy()
            == channel
        )

        channel_actual = (
            actual[mask]
        )

        for (
            name,
            probabilities,
        ) in experiment_probabilities.items():

            channel_probabilities = (
                probabilities[mask]
            )

            metrics = calculate_metrics(
                channel_actual,
                channel_probabilities,
            )

            metrics[
                "experiment"
            ] = name

            metrics[
                "channel"
            ] = channel

            channel_results.append(
                metrics
            )

    channel_df = pd.DataFrame(
        channel_results
    )

    # --------------------------------------------------------
    # Save result files
    # --------------------------------------------------------

    results_path = (
        OUTPUT_DIR
        / "ablation_results.csv"
    )

    channel_path = (
        OUTPUT_DIR
        / "ablation_channel_results.csv"
    )

    predictions_path = (
        OUTPUT_DIR
        / "ablation_predictions.csv"
    )

    report_path = (
        OUTPUT_DIR
        / "ablation_report.md"
    )

    metrics_path = (
        OUTPUT_DIR
        / "ablation_metrics.json"
    )

    # --------------------------------------------------------
    # Overall results
    # --------------------------------------------------------

    results_df.to_csv(
        results_path,
        index=False,
    )

    # --------------------------------------------------------
    # Channel results
    # --------------------------------------------------------

    channel_df.to_csv(
        channel_path,
        index=False,
    )

    # --------------------------------------------------------
    # Prediction artifact
    # --------------------------------------------------------

    prediction_frame = test_df[
        [
            "message_id",
            "channel",
            "label",
        ]
    ].copy()

    prediction_frame[
        "actual_label"
    ] = actual

    prediction_frame[
        "transformer_probability"
    ] = transformer_probabilities

    prediction_frame[
        "historical_risk"
    ] = historical_risks

    prediction_frame[
        "behavioral_risk"
    ] = behavioral_risks

    prediction_frame[
        "retrieved_threat_count"
    ] = retrieved_counts

    prediction_frame.to_csv(
        predictions_path,
        index=False,
    )

    # --------------------------------------------------------
    # Markdown report
    # --------------------------------------------------------

    report_lines = [
        "# Ablation Evaluation Report",
        "",
        "## Evaluation boundary",
        "",
        (
            "The test set contains 8,452 held-out "
            "messages. Threat-memory retrieval "
            "uses only the training split."
        ),
        "",
        "## Experiments",
        "",
        (
            "| Experiment | Transformer | "
            "RAG | Gemini | Behavioral |"
        ),
        (
            "|---|---:|---:|---:|---:|"
        ),
        (
            "| A | Yes | No | No | No |"
        ),
        (
            "| B | Yes | Yes | No | No |"
        ),
        (
            "| C | Yes | Yes | Yes | No |"
        ),
        (
            "| D | Yes | Yes | No | Yes |"
        ),
        "",
        (
            "Gemini is evaluated separately in "
            "a controlled run."
        ),
        "",
        "## Overall Results",
        "",
    ]

    report_lines.append(
        results_df.to_string(
            index=False
        )
    )

    report_lines.extend(
        [
            "",
            "## Channel Results",
            "",
            channel_df.to_string(
                index=False
            ),
            "",
            "## Notes",
            "",
            (
                "Risk-fusion weights are initial "
                "engineering defaults and are not "
                "presented as statistically optimal "
                "weights."
            ),
            "",
            (
                "These results measure performance "
                "on the held-out dataset and should "
                "not be interpreted as guaranteed "
                "future real-world performance."
            ),
            "",
            (
                "URLs are not used as detection "
                "features."
            ),
            "",
            (
                "Relationship-based behavioral "
                "features are unavailable when "
                "receiver metadata is absent."
            ),
        ]
    )

    report_path.write_text(
        "\n".join(
            report_lines
        ),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # JSON metrics
    # --------------------------------------------------------

    metrics_payload = {
        "overall": results,
        "by_channel": channel_results,
        "test_rows": int(
            len(test_df)
        ),
        "training_memory_rows": int(
            len(
                memory_payload[
                    "documents"
                ]
            )
        ),
        "similarity_threshold": (
            SIMILARITY_THRESHOLD
        ),
        "top_k": TOP_K,
    }

    metrics_path.write_text(
        json.dumps(
            metrics_payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # Console output
    # --------------------------------------------------------

    print()

    print(
        "=" * 70
    )

    print(
        "ABLATION RESULTS"
    )

    print(
        "=" * 70
    )

    print(
        results_df[
            [
                "experiment",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "roc_auc",
            ]
        ].to_string(
            index=False
        )
    )

    print()

    print(
        "Artifacts saved to:"
    )

    print(
        OUTPUT_DIR
    )


if __name__ == "__main__":
    main()