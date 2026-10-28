from __future__ import annotations

import numpy as np

from src.adaptive.persistent_memory import (
    PersistentAdaptiveMemory,
)
from src.embeddings.document_chunker import (
    build_memory_document,
)


class FakeEmbedder:
    def encode(
        self,
        text: str,
    ) -> np.ndarray:
        return np.array(
            [1.0, 0.0, 0.0],
            dtype=np.float32,
        )


def test_persistent_memory_save_and_reload(
    tmp_path,
):
    path = (
        tmp_path
        / "adaptive_threat_memory.pkl"
    )

    embedder = FakeEmbedder()

    memory = PersistentAdaptiveMemory(
        embedder=embedder,
        path=path,
    )

    document = build_memory_document(
        message_id="adaptive-test-001",
        channel="EMAIL",
        label="phishing",
        text="Your account requires verification.",
    )

    memory.add_document(document)

    assert memory.count() == 1
    assert path.exists()

    reloaded = PersistentAdaptiveMemory(
        embedder=embedder,
        path=path,
    )

    assert reloaded.count() == 1

    results = reloaded.search(
        np.array(
            [1.0, 0.0, 0.0],
            dtype=np.float32,
        ),
        top_k=1,
    )

    assert len(results) == 1

    assert (
        results[0].document.document_id
        == "adaptive-test-001"
    )

    assert (
        results[0].document.label
        == "phishing"
    )