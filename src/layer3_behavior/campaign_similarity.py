from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class SimilarityResult:
    available: bool
    max_similarity: float
    similar_message_count: int
    threshold: float


def cosine_similarity(
    first: np.ndarray,
    second: np.ndarray,
) -> float:
    """
    Calculate cosine similarity between two vectors.
    """

    first = np.asarray(first, dtype=float)
    second = np.asarray(second, dtype=float)

    if first.ndim != 1 or second.ndim != 1:
        raise ValueError(
            "Both vectors must be one-dimensional."
        )

    if first.shape != second.shape:
        raise ValueError(
            "Vectors must have the same dimensions."
        )

    first_norm = np.linalg.norm(first)
    second_norm = np.linalg.norm(second)

    if first_norm == 0 or second_norm == 0:
        return 0.0

    return float(
        np.dot(first, second)
        / (first_norm * second_norm)
    )


def compare_embedding_to_history(
    current_embedding: np.ndarray | None,
    historical_embeddings: np.ndarray | None,
    threshold: float = 0.85,
) -> SimilarityResult:
    """
    Compare a current message embedding against
    historical message embeddings.

    Similarity above the threshold is treated as
    potentially similar historical content.

    This function does not claim campaign attribution.
    """

    if current_embedding is None:
        return SimilarityResult(
            available=False,
            max_similarity=0.0,
            similar_message_count=0,
            threshold=threshold,
        )

    if historical_embeddings is None:
        return SimilarityResult(
            available=False,
            max_similarity=0.0,
            similar_message_count=0,
            threshold=threshold,
        )

    current = np.asarray(
        current_embedding,
        dtype=float,
    )

    history = np.asarray(
        historical_embeddings,
        dtype=float,
    )

    if current.ndim != 1:
        raise ValueError(
            "current_embedding must be one-dimensional."
        )

    if history.ndim != 2:
        raise ValueError(
            "historical_embeddings must be two-dimensional."
        )

    if history.shape[0] == 0:
        return SimilarityResult(
            available=False,
            max_similarity=0.0,
            similar_message_count=0,
            threshold=threshold,
        )

    if history.shape[1] != current.shape[0]:
        raise ValueError(
            "Embedding dimensions do not match."
        )

    similarities = np.array(
        [
            cosine_similarity(current, vector)
            for vector in history
        ]
    )

    similar_count = int(
        np.sum(similarities >= threshold)
    )

    return SimilarityResult(
        available=True,
        max_similarity=float(
            np.max(similarities)
        ),
        similar_message_count=similar_count,
        threshold=threshold,
    )