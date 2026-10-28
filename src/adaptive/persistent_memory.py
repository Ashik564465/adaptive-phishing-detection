from __future__ import annotations

import io
import pickle
from pathlib import Path

import numpy as np

from src.adaptive.storage import (
    AdaptiveMemoryStorage,
    LocalFileStorage,
)
from src.embeddings.document_chunker import (
    ThreatMemoryDocument,
)
from src.embeddings.embedding_model import (
    HuggingFaceEmbedder,
)
from src.embeddings.vector_store import (
    InMemoryVectorStore,
)


class PersistentAdaptiveMemory:
    """
    Persistent adaptive threat memory.

    The frozen training-only threat memory is kept separate.
    Only validated feedback is stored in this adaptive memory.
    """

    def __init__(
        self,
        embedder: HuggingFaceEmbedder,
        path: str | Path | None = None,
        storage: AdaptiveMemoryStorage | None = None,
    ):
        self.embedder = embedder
        if storage is None:
            if path is None:
                raise ValueError(
                    "A local path or adaptive-memory storage is required."
                )
            storage = LocalFileStorage(path)

        self.storage = storage
        self.path = Path(path) if path is not None else None
        self._version: str | None = None

        self.store = InMemoryVectorStore()
        self.documents: list[ThreatMemoryDocument] = []

        self._load()

    def _load(self) -> None:
        """
        Load previously validated adaptive knowledge.
        """

        snapshot = self.storage.load()
        if snapshot is None:
            return

        try:
            payload = pickle.load(io.BytesIO(snapshot.data))
        except (pickle.PickleError, EOFError, TypeError) as error:
            raise ValueError(
                "Adaptive memory contains an invalid serialized payload."
            ) from error

        if not isinstance(payload, dict):
            raise ValueError(
                "Adaptive memory payload must be a dictionary."
            )

        documents = payload.get(
            "documents",
            [],
        )

        embeddings = payload.get(
            "embeddings",
            [],
        )

        if len(documents) != len(embeddings):
            raise ValueError(
                "Adaptive memory document/embedding "
                "count mismatch."
            )

        for document, embedding in zip(
            documents,
            embeddings,
        ):
            self.store.add(
                document=document,
                embedding=np.asarray(
                    embedding,
                    dtype=np.float32,
                ),
            )

        self.documents = list(documents)
        self._version = snapshot.version

    def add_document(
        self,
        document: ThreatMemoryDocument,
    ) -> None:
        """
        Embed and persist one validated threat-memory document.
        """

        embedding = np.asarray(
            self.embedder.encode(document.text),
            dtype=np.float32,
        )

        next_store = InMemoryVectorStore()
        for existing_document, existing_embedding in zip(
            self.documents,
            self.store._vectors,
        ):
            next_store.add(
                document=existing_document,
                embedding=existing_embedding,
            )
        next_store.add(
            document=document,
            embedding=embedding,
        )

        payload = self._payload(
            documents=[
                *self.documents,
                document,
            ],
            vectors=next_store._vectors,
        )
        new_version = self.storage.save(
            self._serialize(payload),
            expected_version=self._version,
        )

        self.store = next_store
        self.documents.append(document)
        self._version = new_version

    def save(self) -> None:
        """
        Persist adaptive documents and embeddings.
        """

        payload = self._payload(
            documents=self.documents,
            vectors=self.store._vectors,
        )
        self._version = self.storage.save(
            self._serialize(payload),
            expected_version=self._version,
        )

    @staticmethod
    def _payload(
        documents: list[ThreatMemoryDocument],
        vectors: list[np.ndarray],
    ) -> dict:
        return {
            "documents": list(documents),
            "embeddings": [
                np.asarray(vector, dtype=np.float32)
                for vector in vectors
            ],
        }

    @staticmethod
    def _serialize(payload: dict) -> bytes:
        output = io.BytesIO()
        pickle.dump(payload, output)
        return output.getvalue()

    def count(self) -> int:
        """
        Return number of adaptive documents.
        """

        return len(self.documents)

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
    ):
        """
        Search adaptive threat memory.
        """

        return self.store.search(
            query_embedding=query_embedding,
            top_k=top_k,
        )