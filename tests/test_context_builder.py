from src.rag.context_builder import build_threat_context
from src.rag.retriever import RetrievedThreat


def test_context_builder_counts_phishing_and_legitimate():
    threats = [
        RetrievedThreat(
            document_id="msg-1",
            channel="EMAIL",
            label="phishing",
            text="Verify your account.",
            similarity=0.95,
            sender=None,
            receiver=None,
        ),
        RetrievedThreat(
            document_id="msg-2",
            channel="EMAIL",
            label="phishing",
            text="Your account is suspended.",
            similarity=0.90,
            sender=None,
            receiver=None,
        ),
        RetrievedThreat(
            document_id="msg-3",
            channel="EMAIL",
            label="legitimate",
            text="Meeting tomorrow.",
            similarity=0.80,
            sender=None,
            receiver=None,
        ),
    ]

    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=threats,
    )

    assert context.query_channel == "EMAIL"
    assert context.retrieved_count == 3
    assert context.similar_phishing_count == 2
    assert context.similar_legitimate_count == 1


def test_context_builder_calculates_average_similarity():
    threats = [
        RetrievedThreat(
            document_id="msg-1",
            channel="SMS",
            label="phishing",
            text="Verify now.",
            similarity=0.90,
            sender=None,
            receiver=None,
        ),
        RetrievedThreat(
            document_id="msg-2",
            channel="SMS",
            label="phishing",
            text="Account blocked.",
            similarity=0.80,
            sender=None,
            receiver=None,
        ),
    ]

    context = build_threat_context(
        query_channel="SMS",
        retrieved_threats=threats,
    )

    assert abs(context.average_similarity - 0.85) < 1e-6


def test_context_builder_handles_empty_results():
    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=[],
    )

    assert context.retrieved_count == 0
    assert context.similar_phishing_count == 0
    assert context.similar_legitimate_count == 0
    assert context.average_similarity == 0.0
    assert context.evidence == []


def test_context_builder_rejects_invalid_channel():
    try:
        build_threat_context(
            query_channel="UNKNOWN",
            retrieved_threats=[],
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid channel should raise ValueError"
    )