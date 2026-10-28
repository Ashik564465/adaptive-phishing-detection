from __future__ import annotations

import numpy as np

from src.embeddings.document_chunker import ThreatMemoryDocument
from src.embeddings.embedding_model import HuggingFaceEmbedder
from src.embeddings.vector_store import (
    InMemoryVectorStore,
    VectorSearchResult,
)


class AdaptiveMemory:
    """
    Adaptive threat-memory manager.

    Validated threat-memory documents are converted into embeddings
    and stored for future semantic retrieval.

    This component does not retrain the Transformer classifier.
    """

    def __init__(
        self,
        embedder: HuggingFaceEmbedder,
        vector_store: InMemoryVectorStore,
    ):
        self.embedder = embedder
        self.vector_store = vector_store

    def add_document(
        self,
        document: ThreatMemoryDocument,
    ) -> None:
        embedding = self.embedder.encode(document.text)

        if embedding.ndim != 1:
            raise ValueError(
                "Document embedding must be one-dimensional."
            )

        self.vector_store.add(
            document=document,
            embedding=embedding,
        )

    def search(
        self,
        query_text: str,
        top_k: int = 5,
    ) -> list[VectorSearchResult]:
        if not query_text.strip():
            raise ValueError(
                "query_text cannot be empty."
            )

        query_embedding = self.embedder.encode(query_text)

        return self.vector_store.search(
            query_embedding=query_embedding,
            top_k=top_k,
        )