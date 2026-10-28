import numpy as np

from src.embeddings.embedding_model import (
    EmbeddingConfig,
    HuggingFaceEmbedder,
)


def test_embedding_model_returns_vector():

    embedder = HuggingFaceEmbedder(
        EmbeddingConfig(
            max_length=128
        )
    )

    result = embedder.encode(
        "Your account requires verification."
    )

    assert isinstance(result, np.ndarray)
    assert result.ndim == 1
    assert result.shape[0] > 0


def test_embedding_is_normalized():

    embedder = HuggingFaceEmbedder(
        EmbeddingConfig(
            max_length=128
        )
    )

    result = embedder.encode(
        "Your account requires verification."
    )

    norm = np.linalg.norm(result)

    assert np.isclose(
        norm,
        1.0,
        atol=1e-5,
    )


def test_multiple_messages_return_matrix():

    embedder = HuggingFaceEmbedder(
        EmbeddingConfig(
            max_length=128
        )
    )

    result = embedder.encode(
        [
            "Your account requires verification.",
            "The meeting is scheduled for tomorrow.",
        ]
    )

    assert isinstance(result, np.ndarray)
    assert result.ndim == 2
    assert result.shape[0] == 2
    assert result.shape[1] > 0