import numpy as np

from src.adaptive.adaptive_memory import AdaptiveMemory
from src.embeddings.document_chunker import (
    build_memory_document,
)
from src.embeddings.vector_store import (
    InMemoryVectorStore,
)


class FakeEmbedder:
    def encode(self, text):
        text = text.lower()

        if "verify" in text or "account" in text:
            return np.array(
                [1.0, 0.0, 0.0],
                dtype=np.float32,
            )

        return np.array(
            [0.0, 1.0, 0.0],
            dtype=np.float32,
        )


def test_add_document_to_adaptive_memory():
    memory = AdaptiveMemory(
        embedder=FakeEmbedder(),
        vector_store=InMemoryVectorStore(),
    )

    document = build_memory_document(
        message_id="msg-001",
        channel="EMAIL",
        label="phishing",
        text="Verify your account immediately.",
    )

    memory.add_document(document)

    results = memory.search(
        "Please verify my account.",
        top_k=1,
    )

    assert len(results) == 1
    assert results[0].document.document_id == "msg-001"


def test_search_returns_relevant_memory():
    memory = AdaptiveMemory(
        embedder=FakeEmbedder(),
        vector_store=InMemoryVectorStore(),
    )

    phishing = build_memory_document(
        message_id="msg-phishing",
        channel="EMAIL",
        label="phishing",
        text="Your account requires verification.",
    )

    legitimate = build_memory_document(
        message_id="msg-legitimate",
        channel="EMAIL",
        label="legitimate",
        text="Team meeting tomorrow.",
    )

    memory.add_document(phishing)
    memory.add_document(legitimate)

    results = memory.search(
        "Verify account",
        top_k=1,
    )

    assert len(results) == 1
    assert results[0].document.document_id == "msg-phishing"


def test_empty_query_is_rejected():
    memory = AdaptiveMemory(
        embedder=FakeEmbedder(),
        vector_store=InMemoryVectorStore(),
    )

    try:
        memory.search("")
    except ValueError:
        return

    raise AssertionError(
        "Empty query should raise ValueError."
    )


def test_multiple_documents_can_be_stored():
    memory = AdaptiveMemory(
        embedder=FakeEmbedder(),
        vector_store=InMemoryVectorStore(),
    )

    first = build_memory_document(
        message_id="msg-001",
        channel="SMS",
        label="phishing",
        text="Verify your account.",
    )

    second = build_memory_document(
        message_id="msg-002",
        channel="SMS",
        label="legitimate",
        text="Meeting tomorrow.",
    )

    memory.add_document(first)
    memory.add_document(second)

    results = memory.search(
        "account verification",
        top_k=2,
    )

    assert len(results) == 2