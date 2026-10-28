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

# ---------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------

from src.config.settings import (
    MAX_SEQUENCE_LENGTH,
    PHISHING_MODEL_PATH,
    RANDOM_SEED,
)
from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)
from src.layer2_nlp.transformer_classifier import (
    build_input_text,
    split_dataset,
)
from src.layer3_behavior.sender_profile import (
    build_sender_profiles,
)
from src.rag.retriever import ThreatRetriever


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

PROCESSED_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "unified_messages.parquet"
)

THREAT_MEMORY_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "threat_memory_train_only.pkl"
)

CALIBRATION_PATH = (
    PROJECT_ROOT
    / "models"
    / "fusion_calibration"
    / "best_fusion_config.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "models"
    / "final_evaluation"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ---------------------------------------------------------------------
# Frozen configuration
# ---------------------------------------------------------------------

def load_frozen_configuration():

    print()
    print(
        "Loading frozen validation configuration..."
    )

    with open(
        CALIBRATION_PATH,
        "r",
        encoding="utf-8",
    ) as file:

        configuration = json.load(file)

    best = configuration[
        "best_configuration"
    ]

    required_keys = [
        "nlp_weight",
        "identity_weight",
        "behavioral_weight",
        "historical_weight",
        "rag_similarity_threshold",
        "rag_top_k",
        "decision_threshold",
    ]

    for key in required_keys:

        if key not in best:

            raise RuntimeError(
                f"Missing frozen configuration key: {key}"
            )

    print()
    print(
        "Frozen configuration:"
    )

    print(
        f"  NLP weight: "
        f"{best['nlp_weight']}"
    )

    print(
        f"  Identity weight: "
        f"{best['identity_weight']}"
    )

    print(
        f"  Behavioral weight: "
        f"{best['behavioral_weight']}"
    )

    print(
        f"  Historical weight: "
        f"{best['historical_weight']}"
    )

    print(
        f"  RAG similarity threshold: "
        f"{best['rag_similarity_threshold']}"
    )

    print(
        f"  RAG top-k: "
        f"{best['rag_top_k']}"
    )

    print(
        f"  Decision threshold: "
        f"{best['decision_threshold']}"
    )

    return best


# ---------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------

def load_dataset():

    print()
    print(
        "Loading processed dataset..."
    )

    frame = pd.read_parquet(
        PROCESSED_DATA_PATH
    )

    print(
        f"Total rows: {len(frame)}"
    )

    return frame


def create_official_split(frame):

    print()
    print(
        "Creating the official duplicate-aware "
        "Layer 2 split..."
    )

    train_df, validation_df, test_df = (
        split_dataset(
            frame,
            seed=RANDOM_SEED,
        )
    )

    print(
        f"Training rows:   {len(train_df)}"
    )

    print(
        f"Validation rows: {len(validation_df)}"
    )

    print(
        f"Test rows:       {len(test_df)}"
    )

    expected = (
        39313,
        8404,
        8452,
    )

    actual = (
        len(train_df),
        len(validation_df),
        len(test_df),
    )

    if actual != expected:

        raise RuntimeError(
            "Official split mismatch.\n"
            f"Expected: {expected}\n"
            f"Actual:   {actual}"
        )

    print(
        "Official Layer 2 split verified."
    )

    return (
        train_df.reset_index(drop=True),
        validation_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


# ---------------------------------------------------------------------
# Threat memory
# ---------------------------------------------------------------------

def load_threat_memory():

    print()
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

        store = loaded

    elif isinstance(
        loaded,
        dict,
    ):

        store = None

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

                store = loaded[key]
                break

        if store is None:

            raise TypeError(
                "Threat memory dictionary does not "
                "contain a compatible vector store."
            )

    else:

        raise TypeError(
            "Unsupported threat memory format."
        )

    print(
        "Training-only threat memory loaded."
    )

    return store


# ---------------------------------------------------------------------
# Transformer
# ---------------------------------------------------------------------

def load_transformer():

    print()
    print(
        "Loading trained Transformer..."
    )

    tokenizer = (
        AutoTokenizer.from_pretrained(
            str(PHISHING_MODEL_PATH)
        )
    )

    model = (
        AutoModelForSequenceClassification
        .from_pretrained(
            str(PHISHING_MODEL_PATH)
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


def generate_transformer_predictions(
    frame,
    tokenizer,
    model,
    device,
):

    print()
    print(
        "Generating Transformer predictions "
        "for untouched test set..."
    )

    texts = [
        build_input_text(row)
        for _, row in frame.iterrows()
    ]

    probabilities = []

    batch_size = 4

    for start in range(
        0,
        len(texts),
        batch_size,
    ):

        batch_texts = texts[
            start:start + batch_size
        ]

        encoded = tokenizer(
            batch_texts,
            padding=True,
            truncation=True,
            max_length=MAX_SEQUENCE_LENGTH,
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

            batch_probabilities = (
                torch.softmax(
                    outputs.logits,
                    dim=1,
                )[:, 1]
                .detach()
                .cpu()
                .numpy()
            )

        probabilities.extend(
            batch_probabilities.tolist()
        )

        del encoded
        del outputs

        if device.type == "cuda":

            torch.cuda.empty_cache()

        completed = min(
            start + batch_size,
            len(texts),
        )

        if (
            completed % 500 == 0
            or completed == len(texts)
        ):

            print(
                f"Transformer predictions "
                f"{completed}/{len(texts)}"
            )

    return np.asarray(
        probabilities,
        dtype=np.float64,
    )


# ---------------------------------------------------------------------
# Behavioral intelligence
# ---------------------------------------------------------------------

def build_behavioral_scores(
    train_df,
    test_df,
):

    print()
    print(
        "Building behavioral profiles from TRAIN ONLY..."
    )

    if "sender" not in train_df.columns:

        print(
            "Sender metadata unavailable."
        )

        return np.zeros(
            len(test_df),
            dtype=np.float64,
        )

    profile_columns = [
        column
        for column in [
            "sender",
            "label",
            "timestamp",
        ]
        if column in train_df.columns
    ]

    sender_profiles = build_sender_profiles(
        train_df[
            profile_columns
        ]
    )

    print(
        f"Sender profiles: "
        f"{len(sender_profiles)}"
    )

    if "receiver" not in train_df.columns:

        print(
            "Receiver metadata unavailable."
        )

        print(
            "Relationship-based behavioral "
            "features are unavailable."
        )

    behavioral_scores = np.zeros(
        len(test_df),
        dtype=np.float64,
    )

    for index, row in test_df.iterrows():

        if "sender" not in test_df.columns:

            continue

        sender = row["sender"]

        if (
            sender is None
            or pd.isna(sender)
            or not str(sender).strip()
        ):

            continue

        sender = str(
            sender
        )

        profile = sender_profiles.get(
            sender
        )

        if profile is None:

            continue

        message_count = int(
            profile.message_count
        )

        phishing_rate = float(
            profile.phishing_rate
        )

        if message_count >= 2:

            behavioral_scores[index] = (
                phishing_rate
            )

        if (
            index + 1
        ) % 1000 == 0:

            print(
                f"Behavioral signals "
                f"{index + 1}/{len(test_df)}"
            )

    return behavioral_scores


# ---------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------

def generate_test_embeddings(
    test_df,
    embedder,
):

    print()
    print(
        "Generating test embeddings..."
    )

    texts = [
        build_input_text(row)
        for _, row in test_df.iterrows()
    ]

    embedding_batches = []

    batch_size = 4

    for start in range(
        0,
        len(texts),
        batch_size,
    ):

        batch_texts = texts[
            start:start + batch_size
        ]

        batch_embeddings = (
            embedder.encode(
                batch_texts,
                batch_size=batch_size,
            )
        )

        embedding_batches.append(
            batch_embeddings
        )

        completed = min(
            start + batch_size,
            len(texts),
        )

        if (
            completed % 500 == 0
            or completed == len(texts)
        ):

            print(
                f"Embeddings "
                f"{completed}/{len(texts)}"
            )

    return np.vstack(
        embedding_batches
    )


# ---------------------------------------------------------------------
# RAG historical risk
# ---------------------------------------------------------------------

def calculate_historical_risk(
    retrieved_results,
):

    if not retrieved_results:

        return 0.0

    phishing_count = sum(
        1
        for result in retrieved_results
        if result.label == "phishing"
    )

    legitimate_count = sum(
        1
        for result in retrieved_results
        if result.label == "legitimate"
    )

    total = (
        phishing_count
        + legitimate_count
    )

    if total == 0:

        return 0.0

    # Legitimate-only retrieved evidence
    # cannot create phishing risk.

    if phishing_count == 0:

        return 0.0

    phishing_ratio = (
        phishing_count / total
    )

    average_similarity = (
        sum(
            result.similarity
            for result in retrieved_results
        )
        / len(retrieved_results)
    )

    historical_risk = (
        phishing_ratio
        * average_similarity
    )

    return float(
        np.clip(
            historical_risk,
            0.0,
            1.0,
        )
    )


def generate_historical_scores(
    test_embeddings,
    store,
    similarity_threshold,
    top_k,
):

    print()
    print(
        "Generating frozen RAG historical signals..."
    )

    retriever = ThreatRetriever(
        vector_store=store,
        similarity_threshold=(
            similarity_threshold
        ),
    )

    historical_scores = np.zeros(
        len(test_embeddings),
        dtype=np.float64,
    )

    retrieved_counts = np.zeros(
        len(test_embeddings),
        dtype=np.int32,
    )

    for index, embedding in enumerate(
        test_embeddings
    ):

        retrieved = retriever.retrieve(
            query_embedding=embedding,
            top_k=top_k,
        )

        historical_scores[index] = (
            calculate_historical_risk(
                retrieved
            )
        )

        retrieved_counts[index] = (
            len(retrieved)
        )

        if (
            index + 1
        ) % 500 == 0:

            print(
                f"RAG signals "
                f"{index + 1}/"
                f"{len(test_embeddings)}"
            )

    print(
        "RAG historical signals complete."
    )

    return (
        historical_scores,
        retrieved_counts,
    )


# ---------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------

def calculate_metrics(
    y_true,
    scores,
    decision_threshold,
):

    predictions = (
        scores >= decision_threshold
    ).astype(int)

    matrix = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    )

    return {
        "samples": int(
            len(y_true)
        ),
        "accuracy": float(
            accuracy_score(
                y_true,
                predictions,
            )
        ),
        "precision": float(
            precision_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                y_true,
                scores,
            )
        ),
        "confusion_matrix": (
            matrix.tolist()
        ),
        "decision_threshold": float(
            decision_threshold
        ),
    }


def calculate_channel_metrics(
    test_df,
    scores,
    decision_threshold,
):

    results = {}

    for channel in [
        "EMAIL",
        "SMS",
    ]:

        mask = (
            test_df["channel"]
            .astype(str)
            .str.upper()
            == channel
        )

        if mask.sum() == 0:

            continue

        channel_frame = test_df.loc[
            mask
        ]

        channel_scores = scores[
            mask.to_numpy()
        ]

        y_true = (
            channel_frame["label"]
            .map(
                {
                    "legitimate": 0,
                    "phishing": 1,
                }
            )
            .astype(int)
            .to_numpy()
        )

        results[channel] = (
            calculate_metrics(
                y_true=y_true,
                scores=channel_scores,
                decision_threshold=(
                    decision_threshold
                ),
            )
        )

    return results


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():

    print()
    print(
        "=" * 70
    )

    print(
        "FINAL UNTOUCHED TEST EVALUATION"
    )

    print(
        "=" * 70
    )

    # ---------------------------------------------------------------
    # Load frozen configuration
    # ---------------------------------------------------------------

    config = (
        load_frozen_configuration()
    )

    # ---------------------------------------------------------------
    # Load dataset
    # ---------------------------------------------------------------

    frame = load_dataset()

    (
        train_df,
        validation_df,
        test_df,
    ) = create_official_split(
        frame
    )

    del validation_df

    # ---------------------------------------------------------------
    # Confirm test size
    # ---------------------------------------------------------------

    if len(test_df) != 8452:

        raise RuntimeError(
            "Unexpected test-set size."
        )

    print()
    print(
        "Test set contains exactly "
        f"{len(test_df)} rows."
    )

    # ---------------------------------------------------------------
    # Load threat memory
    # ---------------------------------------------------------------

    store = load_threat_memory()

    # ---------------------------------------------------------------
    # Load Transformer
    # ---------------------------------------------------------------

    (
        tokenizer,
        model,
        device,
    ) = load_transformer()

    # ---------------------------------------------------------------
    # Transformer baseline
    # ---------------------------------------------------------------

    transformer_scores = (
        generate_transformer_predictions(
            test_df,
            tokenizer,
            model,
            device,
        )
    )

    # ---------------------------------------------------------------
    # Behavioral signal
    # ---------------------------------------------------------------

    behavioral_scores = (
        build_behavioral_scores(
            train_df,
            test_df,
        )
    )

    # ---------------------------------------------------------------
    # Identity signal
    # ---------------------------------------------------------------

    identity_scores = np.zeros(
        len(test_df),
        dtype=np.float64,
    )

    print()
    print(
        "Identity risk = 0.0 for this evaluation."
    )

    print(
        "Reason: current processed dataset "
        "does not contain SPF/DKIM/DMARC metadata."
    )

    # ---------------------------------------------------------------
    # Embedding model
    # ---------------------------------------------------------------

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

    # ---------------------------------------------------------------
    # Test embeddings
    # ---------------------------------------------------------------

    test_embeddings = (
        generate_test_embeddings(
            test_df,
            embedder,
        )
    )

    # ---------------------------------------------------------------
    # Frozen RAG
    # ---------------------------------------------------------------

    (
        historical_scores,
        retrieved_counts,
    ) = generate_historical_scores(
        test_embeddings=test_embeddings,
        store=store,
        similarity_threshold=(
            float(
                config[
                    "rag_similarity_threshold"
                ]
            )
        ),
        top_k=int(
            config[
                "rag_top_k"
            ]
        ),
    )

    # ---------------------------------------------------------------
    # Ground truth
    # ---------------------------------------------------------------

    y_true = (
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

    # ---------------------------------------------------------------
    # Transformer-only baseline
    # ---------------------------------------------------------------

    baseline_threshold = 0.50

    baseline_metrics = (
        calculate_metrics(
            y_true=y_true,
            scores=transformer_scores,
            decision_threshold=(
                baseline_threshold
            ),
        )
    )

    baseline_channel_metrics = (
        calculate_channel_metrics(
            test_df=test_df,
            scores=transformer_scores,
            decision_threshold=(
                baseline_threshold
            ),
        )
    )

    # ---------------------------------------------------------------
    # Frozen calibrated fusion
    # ---------------------------------------------------------------

    fused_scores = (
        transformer_scores
        * float(
            config["nlp_weight"]
        )
        + identity_scores
        * float(
            config["identity_weight"]
        )
        + behavioral_scores
        * float(
            config["behavioral_weight"]
        )
        + historical_scores
        * float(
            config["historical_weight"]
        )
    )

    fused_scores = np.clip(
        fused_scores,
        0.0,
        1.0,
    )

    decision_threshold = float(
        config[
            "decision_threshold"
        ]
    )

    fusion_metrics = (
        calculate_metrics(
            y_true=y_true,
            scores=fused_scores,
            decision_threshold=(
                decision_threshold
            ),
        )
    )

    fusion_channel_metrics = (
        calculate_channel_metrics(
            test_df=test_df,
            scores=fused_scores,
            decision_threshold=(
                decision_threshold
            ),
        )
    )

    # ---------------------------------------------------------------
    # Prediction labels
    # ---------------------------------------------------------------

    baseline_predictions = (
        transformer_scores
        >= baseline_threshold
    ).astype(int)

    fusion_predictions = (
        fused_scores
        >= decision_threshold
    ).astype(int)

    # ---------------------------------------------------------------
    # Prediction artifact
    # ---------------------------------------------------------------

    prediction_frame = pd.DataFrame(
        {
            "message_id": (
                test_df["message_id"]
                .astype(str)
                .to_numpy()
            ),
            "channel": (
                test_df["channel"]
                .astype(str)
                .to_numpy()
            ),
            "actual_label": (
                test_df["label"]
                .astype(str)
                .to_numpy()
            ),
            "transformer_probability": (
                transformer_scores
            ),
            "transformer_prediction": (
                baseline_predictions
            ),
            "behavioral_risk": (
                behavioral_scores
            ),
            "historical_risk": (
                historical_scores
            ),
            "retrieved_threat_count": (
                retrieved_counts
            ),
            "fusion_score": (
                fused_scores
            ),
            "fusion_prediction": (
                fusion_predictions
            ),
        }
    )

    prediction_path = (
        OUTPUT_DIR
        / "final_test_predictions.csv"
    )

    prediction_frame.to_csv(
        prediction_path,
        index=False,
    )

    # ---------------------------------------------------------------
    # Confusion matrices
    # ---------------------------------------------------------------

    confusion_output = {
        "transformer_only": (
            baseline_metrics[
                "confusion_matrix"
            ]
        ),
        "calibrated_fusion": (
            fusion_metrics[
                "confusion_matrix"
            ]
        ),
        "labels": [
            "legitimate",
            "phishing",
        ],
    }

    confusion_path = (
        OUTPUT_DIR
        / "final_confusion_matrix.json"
    )

    with open(
        confusion_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            confusion_output,
            file,
            indent=2,
        )

    # ---------------------------------------------------------------
    # Final metrics JSON
    # ---------------------------------------------------------------

    final_results = {
        "evaluation_type": (
            "Final held-out test evaluation"
        ),
        "test_set_rows": int(
            len(test_df)
        ),
        "test_set_used_for_calibration": False,
        "gemini_used": False,
        "identity_metadata_available": False,
        "receiver_metadata_available": False,
        "frozen_configuration": config,
        "transformer_only": {
            "overall": baseline_metrics,
            "channel": baseline_channel_metrics,
        },
        "calibrated_fusion": {
            "overall": fusion_metrics,
            "channel": fusion_channel_metrics,
        },
    }

    metrics_path = (
        OUTPUT_DIR
        / "final_test_metrics.json"
    )

    with open(
        metrics_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            final_results,
            file,
            indent=2,
        )

    # ---------------------------------------------------------------
    # Final report
    # ---------------------------------------------------------------

    report_path = (
        OUTPUT_DIR
        / "final_evaluation_report.md"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as file:

        file.write(
            "# Final Held-Out Test Evaluation\n\n"
        )

        file.write(
            "## Evaluation protocol\n\n"
        )

        file.write(
            f"- Total dataset rows: {len(frame)}\n"
        )

        file.write(
            f"- Training rows: {len(train_df)}\n"
        )

        file.write(
            f"- Test rows: {len(test_df)}\n"
        )

        file.write(
            "- Test data was not used during calibration.\n"
        )

        file.write(
            "- Threat memory was constructed from training data only.\n"
        )

        file.write(
            "- Fusion parameters were selected using validation data only.\n"
        )

        file.write(
            "- Gemini was not used in the bulk test evaluation.\n"
        )

        file.write(
            "\n"
        )

        file.write(
            "## Frozen fusion configuration\n\n"
        )

        file.write(
            f"- NLP weight: {config['nlp_weight']}\n"
        )

        file.write(
            f"- Identity weight: {config['identity_weight']}\n"
        )

        file.write(
            f"- Behavioral weight: {config['behavioral_weight']}\n"
        )

        file.write(
            f"- Historical weight: {config['historical_weight']}\n"
        )

        file.write(
            f"- RAG similarity threshold: "
            f"{config['rag_similarity_threshold']}\n"
        )

        file.write(
            f"- RAG top-k: {config['rag_top_k']}\n"
        )

        file.write(
            f"- Decision threshold: "
            f"{config['decision_threshold']}\n"
        )

        file.write(
            "\n"
        )

        file.write(
            "## Overall results\n\n"
        )

        file.write(
            "| Metric | Transformer only | Calibrated fusion |\n"
        )

        file.write(
            "|---|---:|---:|\n"
        )

        file.write(
            f"| Accuracy | "
            f"{baseline_metrics['accuracy']:.6f} | "
            f"{fusion_metrics['accuracy']:.6f} |\n"
        )

        file.write(
            f"| Precision | "
            f"{baseline_metrics['precision']:.6f} | "
            f"{fusion_metrics['precision']:.6f} |\n"
        )

        file.write(
            f"| Recall | "
            f"{baseline_metrics['recall']:.6f} | "
            f"{fusion_metrics['recall']:.6f} |\n"
        )

        file.write(
            f"| F1 | "
            f"{baseline_metrics['f1']:.6f} | "
            f"{fusion_metrics['f1']:.6f} |\n"
        )

        file.write(
            f"| ROC-AUC | "
            f"{baseline_metrics['roc_auc']:.6f} | "
            f"{fusion_metrics['roc_auc']:.6f} |\n"
        )

        file.write(
            "\n"
        )

        file.write(
            "## Transformer-only confusion matrix\n\n"
        )

        file.write(
            "Rows = actual, columns = predicted.\n\n"
        )

        file.write(
            "```text\n"
        )

        file.write(
            str(
                baseline_metrics[
                    "confusion_matrix"
                ]
            )
        )

        file.write(
            "\n```\n\n"
        )

        file.write(
            "## Calibrated fusion confusion matrix\n\n"
        )

        file.write(
            "Rows = actual, columns = predicted.\n\n"
        )

        file.write(
            "```text\n"
        )

        file.write(
            str(
                fusion_metrics[
                    "confusion_matrix"
                ]
            )
        )

        file.write(
            "\n```\n\n"
        )

        file.write(
            "## Email results\n\n"
        )

        if "EMAIL" in fusion_channel_metrics:

            email = fusion_channel_metrics[
                "EMAIL"
            ]

            file.write(
                f"- Samples: {email['samples']}\n"
            )

            file.write(
                f"- Accuracy: {email['accuracy']:.6f}\n"
            )

            file.write(
                f"- Precision: {email['precision']:.6f}\n"
            )

            file.write(
                f"- Recall: {email['recall']:.6f}\n"
            )

            file.write(
                f"- F1: {email['f1']:.6f}\n"
            )

            file.write(
                f"- ROC-AUC: {email['roc_auc']:.6f}\n"
            )

        else:

            file.write(
                "No EMAIL samples were present.\n"
            )

        file.write(
            "\n"
        )

        file.write(
            "## SMS results\n\n"
        )

        if "SMS" in fusion_channel_metrics:

            sms = fusion_channel_metrics[
                "SMS"
            ]

            file.write(
                f"- Samples: {sms['samples']}\n"
            )

            file.write(
                f"- Accuracy: {sms['accuracy']:.6f}\n"
            )

            file.write(
                f"- Precision: {sms['precision']:.6f}\n"
            )

            file.write(
                f"- Recall: {sms['recall']:.6f}\n"
            )

            file.write(
                f"- F1: {sms['f1']:.6f}\n"
            )

            file.write(
                f"- ROC-AUC: {sms['roc_auc']:.6f}\n"
            )

        else:

            file.write(
                "No SMS samples were present.\n"
            )

        file.write(
            "\n"
        )

        file.write(
            "## Dataset limitations\n\n"
        )

        file.write(
            "- SPF/DKIM/DMARC authentication metadata is not "
            "present in the current dataset.\n"
        )

        file.write(
            "- Receiver metadata is not available, so "
            "sender-recipient relationship behavior is not "
            "evaluated here.\n"
        )

        file.write(
            "- Sender-history behavior is evaluated only when "
            "sender metadata is available.\n"
        )

        file.write(
            "- These results measure performance on this "
            "held-out dataset and should not be interpreted "
            "as guaranteed future-world performance.\n"
        )

        file.write(
            "- URLs are not used as detection features.\n"
        )

    # ---------------------------------------------------------------
    # Console output
    # ---------------------------------------------------------------

    print()
    print(
        "=" * 70
    )

    print(
        "FINAL TEST RESULTS"
    )

    print(
        "=" * 70
    )

    print()
    print(
        "TRANSFORMER ONLY"
    )

    print(
        f"Accuracy : "
        f"{baseline_metrics['accuracy']:.6f}"
    )

    print(
        f"Precision: "
        f"{baseline_metrics['precision']:.6f}"
    )

    print(
        f"Recall   : "
        f"{baseline_metrics['recall']:.6f}"
    )

    print(
        f"F1       : "
        f"{baseline_metrics['f1']:.6f}"
    )

    print(
        f"ROC-AUC  : "
        f"{baseline_metrics['roc_auc']:.6f}"
    )

    print()
    print(
        "CALIBRATED TRANSFORMER + RAG + BEHAVIOR"
    )

    print(
        f"Accuracy : "
        f"{fusion_metrics['accuracy']:.6f}"
    )

    print(
        f"Precision: "
        f"{fusion_metrics['precision']:.6f}"
    )

    print(
        f"Recall   : "
        f"{fusion_metrics['recall']:.6f}"
    )

    print(
        f"F1       : "
        f"{fusion_metrics['f1']:.6f}"
    )

    print(
        f"ROC-AUC  : "
        f"{fusion_metrics['roc_auc']:.6f}"
    )

    print()
    print(
        "Artifacts saved to:"
    )

    print(
        OUTPUT_DIR
    )

    print()
    print(
        "Final test evaluation complete."
    )


if __name__ == "__main__":
    main()