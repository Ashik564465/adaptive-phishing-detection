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
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import AutoModelForSequenceClassification, AutoTokenizer

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

OUTPUT_DIR = (
    PROJECT_ROOT
    / "models"
    / "fusion_calibration"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ---------------------------------------------------------------------
# Calibration search space
# ---------------------------------------------------------------------

WEIGHT_CONFIGS = {
    "balanced": {
        "nlp": 0.50,
        "identity": 0.00,
        "behavioral": 0.20,
        "historical": 0.30,
    },
    "nlp_heavy": {
        "nlp": 0.70,
        "identity": 0.00,
        "behavioral": 0.10,
        "historical": 0.20,
    },
    "nlp_rag": {
        "nlp": 0.70,
        "identity": 0.00,
        "behavioral": 0.00,
        "historical": 0.30,
    },
    "nlp_behavior_rag": {
        "nlp": 0.65,
        "identity": 0.00,
        "behavioral": 0.15,
        "historical": 0.20,
    },
    "transformer_first": {
        "nlp": 0.80,
        "identity": 0.00,
        "behavioral": 0.10,
        "historical": 0.10,
    },
}

RAG_THRESHOLDS = [
    0.60,
    0.65,
    0.70,
    0.75,
    0.80,
    0.85,
]

RAG_TOP_K_VALUES = [
    1,
    3,
    5,
    10,
]

DECISION_THRESHOLDS = [
    0.30,
    0.35,
    0.40,
    0.45,
    0.50,
    0.55,
    0.60,
    0.65,
    0.70,
    0.75,
    0.80,
]


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------


def get_store_count(store) -> int | None:
    """
    Safely determine how many documents/vectors are stored.

    This supports the current InMemoryVectorStore implementation
    without assuming a particular internal attribute name.
    """

    possible_attributes = [
        "documents",
        "_documents",
        "items",
        "_items",
        "vectors",
        "_vectors",
        "embeddings",
        "_embeddings",
    ]

    for attribute_name in possible_attributes:

        if not hasattr(store, attribute_name):
            continue

        value = getattr(
            store,
            attribute_name,
        )

        try:
            return len(value)
        except TypeError:
            continue

    return None


def load_threat_memory():

    print()
    print("Loading training-only threat memory...")

    with open(
        THREAT_MEMORY_PATH,
        "rb",
    ) as file:

        loaded = pickle.load(file)

    # Direct vector store
    if hasattr(
        loaded,
        "search",
    ):
        store = loaded

    # Dictionary wrapper
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

            if key in loaded and hasattr(
                loaded[key],
                "search",
            ):

                store = loaded[key]
                break

        if store is None:

            raise TypeError(
                "Threat memory dictionary does not contain "
                "a compatible vector store."
            )

    else:

        raise TypeError(
            "Unsupported threat memory format."
        )

    count = get_store_count(store)

    if count is not None:

        print(
            f"Threat memory documents: {count}"
        )

    else:

        print(
            "Threat memory loaded."
        )

    return store


def load_processed_data():

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


def verify_official_split(frame):

    print()
    print(
        "Creating the official duplicate-aware "
        "Layer 2 split..."
    )

    train_df, validation_df, test_df = split_dataset(
        frame,
        seed=RANDOM_SEED,
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
            "Official Layer 2 split mismatch.\n"
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


def load_transformer():

    print()
    print(
        "Loading trained Transformer..."
    )

    tokenizer = AutoTokenizer.from_pretrained(
        str(PHISHING_MODEL_PATH)
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        str(PHISHING_MODEL_PATH)
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
        "Generating validation Transformer predictions..."
    )

    predictions = []

    batch_size = 4

    texts = [
        build_input_text(row)
        for _, row in frame.iterrows()
    ]

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

            probabilities = torch.softmax(
                outputs.logits,
                dim=1,
            )

            phishing_probabilities = (
                probabilities[:, 1]
                .detach()
                .cpu()
                .numpy()
            )

        predictions.extend(
            phishing_probabilities.tolist()
        )

        del encoded
        del outputs
        del probabilities

        if device.type == "cuda":
            torch.cuda.empty_cache()

    predictions = np.asarray(
        predictions,
        dtype=np.float64,
    )

    print(
        "Transformer predictions complete."
    )

    return predictions


def generate_behavioral_signals(
    train_df,
    validation_df,
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
            len(validation_df),
            dtype=np.float64,
        )

    sender_profiles = build_sender_profiles(
        train_df[
            [
                column
                for column in [
                    "sender",
                    "label",
                    "timestamp",
                ]
                if column in train_df.columns
            ]
        ]
    )

    print(
        f"Sender profiles: {len(sender_profiles)}"
    )

    if "receiver" not in train_df.columns:

        print(
            "Receiver metadata unavailable in "
            "processed dataset."
        )

        print(
            "Relationship-based behavioral features "
            "will be treated as unavailable."
        )

    behavioral_scores = np.zeros(
        len(validation_df),
        dtype=np.float64,
    )

    for index, row in validation_df.iterrows():

        sender = (
            row["sender"]
            if "sender" in validation_df.columns
            else None
        )

        if not sender:

            continue

        profile = sender_profiles.get(
            sender
        )

        if profile is None:

            continue

        # Sender-level behavioral signal.
        #
        # This uses historical phishing rate only.
        # No fabricated relationship metadata is used.

        phishing_rate = float(
            profile.phishing_rate
        )

        message_count = int(
            profile.message_count
        )

        if message_count >= 2:

            behavioral_scores[index] = phishing_rate

        if (
            index + 1
        ) % 1000 == 0:

            print(
                f"Behavioral {index + 1}/"
                f"{len(validation_df)}"
            )

    return behavioral_scores


def generate_embeddings(
    frame,
    embedder,
):

    print()
    print(
        "Generating validation embeddings..."
    )

    texts = [
        build_input_text(row)
        for _, row in frame.iterrows()
    ]

    embeddings = []

    batch_size = 4

    for start in range(
        0,
        len(texts),
        batch_size,
    ):

        batch = texts[
            start:start + batch_size
        ]

        batch_embeddings = embedder.encode(
            batch,
            batch_size=batch_size,
        )

        embeddings.append(
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
                f"Embedded {completed}/"
                f"{len(texts)}"
            )

    result = np.vstack(
        embeddings
    )

    print(
        "Validation embeddings complete."
    )

    return result


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


def generate_rag_signals(
    validation_embeddings,
    validation_df,
    store,
):

    print()
    print(
        "Generating RAG signals..."
    )

    results = {}

    for threshold in RAG_THRESHOLDS:

        retriever = ThreatRetriever(
            vector_store=store,
            similarity_threshold=threshold,
        )

        for top_k in RAG_TOP_K_VALUES:

            configuration_key = (
                f"threshold={threshold:.2f};"
                f"top_k={top_k}"
            )

            historical_scores = np.zeros(
                len(validation_df),
                dtype=np.float64,
            )

            for index, embedding in enumerate(
                validation_embeddings
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

            results[
                configuration_key
            ] = historical_scores

            print(
                "RAG configuration "
                f"{len(results)}/"
                f"{len(RAG_THRESHOLDS) * len(RAG_TOP_K_VALUES)} "
                f"completed: "
                f"threshold={threshold:.2f}, "
                f"top_k={top_k}"
            )

    return results


def calculate_fused_score(
    nlp,
    identity,
    behavioral,
    historical,
    weights,
):

    score = (
        nlp
        * weights["nlp"]
        + identity
        * weights["identity"]
        + behavioral
        * weights["behavioral"]
        + historical
        * weights["historical"]
    )

    return np.clip(
        score,
        0.0,
        1.0,
    )


def evaluate_configuration(
    y_true,
    scores,
    decision_threshold,
):

    predictions = (
        scores >= decision_threshold
    ).astype(int)

    return {
        "accuracy": accuracy_score(
            y_true,
            predictions,
        ),
        "precision": precision_score(
            y_true,
            predictions,
            zero_division=0,
        ),
        "recall": recall_score(
            y_true,
            predictions,
            zero_division=0,
        ),
        "f1": f1_score(
            y_true,
            predictions,
            zero_division=0,
        ),
        "roc_auc": roc_auc_score(
            y_true,
            scores,
        ),
    }


# ---------------------------------------------------------------------
# Main calibration process
# ---------------------------------------------------------------------


def main():

    np.random.seed(
        RANDOM_SEED
    )

    # ---------------------------------------------------------------
    # Load data
    # ---------------------------------------------------------------

    frame = load_processed_data()

    (
        train_df,
        validation_df,
        test_df,
    ) = verify_official_split(
        frame
    )

    del test_df

    # ---------------------------------------------------------------
    # Threat memory
    # ---------------------------------------------------------------

    store = load_threat_memory()

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
    # Transformer
    # ---------------------------------------------------------------

    (
        tokenizer,
        model,
        device,
    ) = load_transformer()

    # ---------------------------------------------------------------
    # Transformer validation predictions
    # ---------------------------------------------------------------

    nlp_scores = generate_transformer_predictions(
        validation_df,
        tokenizer,
        model,
        device,
    )

    # ---------------------------------------------------------------
    # Behavioral signals
    # ---------------------------------------------------------------

    behavioral_scores = (
        generate_behavioral_signals(
            train_df,
            validation_df,
        )
    )

    # ---------------------------------------------------------------
    # Identity unavailable for current processed dataset
    # ---------------------------------------------------------------

    identity_scores = np.zeros(
        len(validation_df),
        dtype=np.float64,
    )

    print()
    print(
        "Identity authentication metadata is "
        "unavailable in the current processed dataset."
    )

    print(
        "Identity risk will therefore be treated "
        "as unavailable rather than fabricated."
    )

    # ---------------------------------------------------------------
    # Validation embeddings
    # ---------------------------------------------------------------

    validation_embeddings = (
        generate_embeddings(
            validation_df,
            embedder,
        )
    )

    # ---------------------------------------------------------------
    # RAG signals
    # ---------------------------------------------------------------

    rag_signals = generate_rag_signals(
        validation_embeddings,
        validation_df,
        store,
    )

    # ---------------------------------------------------------------
    # Ground truth
    # ---------------------------------------------------------------

    y_true = (
        validation_df["label"]
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
    # Search configurations
    # ---------------------------------------------------------------

    print()
    print(
        "Searching fusion configurations..."
    )

    calibration_rows = []

    total_configurations = (
        len(WEIGHT_CONFIGS)
        * len(rag_signals)
        * len(DECISION_THRESHOLDS)
    )

    configuration_number = 0

    for weight_name, weights in (
        WEIGHT_CONFIGS.items()
    ):

        for rag_name, historical_scores in (
            rag_signals.items()
        ):

            fused_scores = calculate_fused_score(
                nlp=nlp_scores,
                identity=identity_scores,
                behavioral=behavioral_scores,
                historical=historical_scores,
                weights=weights,
            )

            for decision_threshold in (
                DECISION_THRESHOLDS
            ):

                configuration_number += 1

                metrics = evaluate_configuration(
                    y_true=y_true,
                    scores=fused_scores,
                    decision_threshold=(
                        decision_threshold
                    ),
                )

                threshold_parts = (
                    rag_name.split(";")
                )

                rag_threshold = float(
                    threshold_parts[0]
                    .split("=")[1]
                )

                top_k = int(
                    threshold_parts[1]
                    .split("=")[1]
                )

                calibration_rows.append(
                    {
                        "weight_config": (
                            weight_name
                        ),
                        "nlp_weight": (
                            weights["nlp"]
                        ),
                        "identity_weight": (
                            weights["identity"]
                        ),
                        "behavioral_weight": (
                            weights["behavioral"]
                        ),
                        "historical_weight": (
                            weights["historical"]
                        ),
                        "rag_similarity_threshold": (
                            rag_threshold
                        ),
                        "rag_top_k": (
                            top_k
                        ),
                        "decision_threshold": (
                            decision_threshold
                        ),
                        "accuracy": (
                            metrics["accuracy"]
                        ),
                        "precision": (
                            metrics["precision"]
                        ),
                        "recall": (
                            metrics["recall"]
                        ),
                        "f1": (
                            metrics["f1"]
                        ),
                        "roc_auc": (
                            metrics["roc_auc"]
                        ),
                    }
                )

                if (
                    configuration_number % 100
                    == 0
                    or configuration_number
                    == total_configurations
                ):

                    print(
                        f"Calibration "
                        f"{configuration_number}/"
                        f"{total_configurations}"
                    )

    results_df = pd.DataFrame(
        calibration_rows
    )

    # ---------------------------------------------------------------
    # Sort by validation F1
    # ---------------------------------------------------------------

    results_df = results_df.sort_values(
        by=[
            "f1",
            "roc_auc",
            "precision",
        ],
        ascending=False,
    ).reset_index(
        drop=True
    )

    best = results_df.iloc[0].to_dict()

    # ---------------------------------------------------------------
    # Save all validation results
    # ---------------------------------------------------------------

    all_results_path = (
        OUTPUT_DIR
        / "validation_calibration_results.csv"
    )

    results_df.to_csv(
        all_results_path,
        index=False,
    )

    # ---------------------------------------------------------------
    # Save top configurations
    # ---------------------------------------------------------------

    top_results_path = (
        OUTPUT_DIR
        / "top_validation_configs.csv"
    )

    results_df.head(20).to_csv(
        top_results_path,
        index=False,
    )

    # ---------------------------------------------------------------
    # Save best configuration
    # ---------------------------------------------------------------

    best_config_path = (
        OUTPUT_DIR
        / "best_fusion_config.json"
    )

    with open(
        best_config_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            {
                "selection_basis": (
                    "Validation F1, followed by "
                    "validation ROC-AUC and precision."
                ),
                "dataset": {
                    "training_rows": len(train_df),
                    "validation_rows": len(validation_df),
                },
                "best_configuration": best,
                "test_set_used": False,
                "identity_metadata_available": False,
                "receiver_metadata_available": (
                    "receiver"
                    in train_df.columns
                ),
            },
            file,
            indent=2,
        )

    # ---------------------------------------------------------------
    # Human-readable report
    # ---------------------------------------------------------------

    report_path = (
        OUTPUT_DIR
        / "fusion_calibration_report.md"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as file:

        file.write(
            "# Fusion Calibration Report\n\n"
        )

        file.write(
            "## Dataset split\n\n"
        )

        file.write(
            f"- Training rows: {len(train_df)}\n"
        )

        file.write(
            f"- Validation rows: "
            f"{len(validation_df)}\n"
        )

        file.write(
            "- Test rows were not used during calibration.\n\n"
        )

        file.write(
            "## Calibration method\n\n"
        )

        file.write(
            "Fusion weights, RAG similarity threshold, "
            "RAG top-k, and decision threshold were "
            "searched using the validation set only.\n\n"
        )

        file.write(
            "The Transformer phishing probability "
            "remains the primary NLP signal.\n\n"
        )

        file.write(
            "Current identity authentication metadata "
            "is unavailable, so identity weight was "
            "set to zero during this calibration experiment.\n\n"
        )

        file.write(
            "Receiver metadata is unavailable in the "
            "current processed dataset, so relationship "
            "behavioral features were not used.\n\n"
        )

        file.write(
            "## Best validation configuration\n\n"
        )

        for key, value in best.items():

            file.write(
                f"- **{key}**: {value}\n"
            )

        file.write(
            "\n## Top 10 validation configurations\n\n"
        )

        top_ten = results_df.head(
            10
        )

        file.write(
            top_ten.to_string(
                index=False
            )
        )

        file.write(
            "\n"
        )

    # ---------------------------------------------------------------
    # Final console output
    # ---------------------------------------------------------------

    print()
    print(
        "=" * 70
    )

    print(
        "FUSION CALIBRATION COMPLETE"
    )

    print(
        "=" * 70
    )

    print()
    print(
        "Best validation configuration:"
    )

    for key, value in best.items():

        print(
            f"  {key}: {value}"
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
        "Important:"
    )

    print(
        "The test set was not used for calibration."
    )

    print(
        "The selected configuration must be "
        "evaluated once on the untouched test set."
    )


if __name__ == "__main__":
    main()