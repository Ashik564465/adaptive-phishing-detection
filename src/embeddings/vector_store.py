from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from src.embeddings.document_chunker import (
    ThreatMemoryDocument,
)


@dataclass(frozen=True)
class VectorSearchResult:
    document: ThreatMemoryDocument
    similarity: float


class InMemoryVectorStore:
    """
    Lightweight vector store for semantic threat memory.

    Vectors are kept in memory and searched using cosine
    similarity.

    This is intentionally simple so the retrieval interface
    can later be replaced by a persistent vector database.
    """

    def __init__(self) -> None:
        self._vectors: list[np.ndarray] = []
        self._documents: list[ThreatMemoryDocument] = []

    @staticmethod
    def _normalize(vector: np.ndarray) -> np.ndarray:
        vector = np.asarray(
            vector,
            dtype=np.float32,
        )

        if vector.ndim != 1:
            raise ValueError(
                "Vector must be one-dimensional."
            )

        norm = np.linalg.norm(vector)

        if norm == 0:
            raise ValueError(
                "Zero vector cannot be stored."
            )

        return vector / norm

    def add(
        self,
        document: ThreatMemoryDocument,
        embedding: np.ndarray,
    ) -> None:
        """
        Add one document and its embedding.
        """

        vector = self._normalize(embedding)

        if self._vectors:
            expected_dimension = self._vectors[0].shape[0]

            if vector.shape[0] != expected_dimension:
                raise ValueError(
                    "Embedding dimension does not match "
                    "existing vectors."
                )

        self._vectors.append(vector)
        self._documents.append(document)

    def __len__(self) -> int:
        return len(self._documents)

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
    ) -> list[VectorSearchResult]:
        """
        Return the most similar historical documents.
        """

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1."
            )

        if not self._vectors:
            return []

        query = self._normalize(query_embedding)

        matrix = np.vstack(self._vectors)

        similarities = matrix @ query

        top_k = min(
            top_k,
            len(self._documents),
        )

        indices = np.argsort(
            -similarities
        )[:top_k]

        return [
            VectorSearchResult(
                document=self._documents[index],
                similarity=float(
                    similarities[index]
                ),
            )
            for index in indices
        ]