import numpy as np

from src.embeddings.document_chunker import (
    build_memory_document,
)

from src.embeddings.vector_store import (
    InMemoryVectorStore,
)


def test_vector_store_adds_document():

    store = InMemoryVectorStore()

    document = build_memory_document(
        message_id="msg-001",
        channel="EMAIL",
        label="phishing",
        text="Your account requires verification.",
    )

    embedding = np.array(
        [1.0, 0.0, 0.0],
        dtype=np.float32,
    )

    store.add(
        document,
        embedding,
    )

    assert len(store) == 1


def test_vector_store_returns_most_similar_document():

    store = InMemoryVectorStore()

    phishing_document = build_memory_document(
        message_id="msg-phishing",
        channel="EMAIL",
        label="phishing",
        text="Your account requires verification.",
    )

    legitimate_document = build_memory_document(
        message_id="msg-legitimate",
        channel="EMAIL",
        label="legitimate",
        text="Meeting scheduled for tomorrow.",
    )

    store.add(
        phishing_document,
        np.array(
            [1.0, 0.0, 0.0],
            dtype=np.float32,
        ),
    )

    store.add(
        legitimate_document,
        np.array(
            [0.0, 1.0, 0.0],
            dtype=np.float32,
        ),
    )

    results = store.search(
        np.array(
            [0.95, 0.05, 0.0],
            dtype=np.float32,
        ),
        top_k=1,
    )

    assert len(results) == 1
    assert results[0].document.document_id == (
        "msg-phishing"
    )
    assert results[0].similarity > 0.9


def test_vector_store_returns_empty_when_empty():

    store = InMemoryVectorStore()

    results = store.search(
        np.array(
            [1.0, 0.0, 0.0],
            dtype=np.float32,
        )
    )

    assert results == []


def test_vector_store_rejects_dimension_mismatch():

    store = InMemoryVectorStore()

    document = build_memory_document(
        message_id="msg-001",
        channel="SMS",
        label="phishing",
        text="Verify your account.",
    )

    store.add(
        document,
        np.array(
            [1.0, 0.0, 0.0],
            dtype=np.float32,
        ),
    )

    try:
        store.add(
            document,
            np.array(
                [1.0, 0.0],
                dtype=np.float32,
            ),
        )
    except ValueError:
        return

    raise AssertionError(
        "Dimension mismatch should raise ValueError"
    )