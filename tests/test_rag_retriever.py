import numpy as np

from src.embeddings.document_chunker import build_memory_document
from src.embeddings.vector_store import InMemoryVectorStore
from src.rag.retriever import ThreatRetriever


def test_retriever_returns_similar_threat():
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
        np.array([1.0, 0.0, 0.0], dtype=np.float32),
    )

    store.add(
        legitimate_document,
        np.array([0.0, 1.0, 0.0], dtype=np.float32),
    )

    retriever = ThreatRetriever(
        store,
        similarity_threshold=0.75,
    )

    results = retriever.retrieve(
        np.array([0.95, 0.05, 0.0], dtype=np.float32),
        top_k=2,
    )

    assert len(results) == 1
    assert results[0].document_id == "msg-phishing"
    assert results[0].label == "phishing"
    assert results[0].similarity > 0.75


def test_retriever_filters_low_similarity_results():
    store = InMemoryVectorStore()

    document = build_memory_document(
        message_id="msg-001",
        channel="SMS",
        label="phishing",
        text="Verify your account immediately.",
    )

    store.add(
        document,
        np.array([1.0, 0.0, 0.0], dtype=np.float32),
    )

    retriever = ThreatRetriever(
        store,
        similarity_threshold=0.95,
    )

    results = retriever.retrieve(
        np.array([0.7, 0.7, 0.0], dtype=np.float32),
        top_k=5,
    )

    assert results == []


def test_retriever_handles_empty_store():
    store = InMemoryVectorStore()

    retriever = ThreatRetriever(store)

    results = retriever.retrieve(
        np.array([1.0, 0.0, 0.0], dtype=np.float32)
    )

    assert results == []


def test_retriever_rejects_invalid_threshold():
    store = InMemoryVectorStore()

    try:
        ThreatRetriever(
            store,
            similarity_threshold=1.5,
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid similarity threshold should raise ValueError"
    )