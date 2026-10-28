from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from src.embeddings.vector_store import (
    InMemoryVectorStore,
    VectorSearchResult,
)


@dataclass(frozen=True)
class RetrievedThreat:
    document_id: str
    channel: str
    label: str
    text: str
    similarity: float
    sender: str | None
    receiver: str | None


class ThreatRetriever:
    """
    Retrieves historically similar messages from semantic threat memory.

    The retriever does not perform phishing classification.
    It only retrieves relevant historical knowledge.
    """

    def __init__(
        self,
        vector_store: InMemoryVectorStore,
        similarity_threshold: float = 0.75,
    ):
        if not 0.0 <= similarity_threshold <= 1.0:
            raise ValueError(
                "similarity_threshold must be between 0 and 1."
            )

        self.vector_store = vector_store
        self.similarity_threshold = similarity_threshold

    def retrieve(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
    ) -> list[RetrievedThreat]:
        results: list[VectorSearchResult] = self.vector_store.search(
            query_embedding=query_embedding,
            top_k=top_k,
        )

        retrieved: list[RetrievedThreat] = []

        for result in results:
            if result.similarity < self.similarity_threshold:
                continue

            document = result.document

            retrieved.append(
                RetrievedThreat(
                    document_id=document.document_id,
                    channel=document.channel,
                    label=document.label,
                    text=document.text,
                    similarity=result.similarity,
                    sender=document.sender,
                    receiver=document.receiver,
                )
            )

        return retrieved