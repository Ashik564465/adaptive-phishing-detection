from src.embeddings.document_chunker import (
    ThreatMemoryDocument,
    build_memory_document,
)


def test_memory_document_is_created():

    document = build_memory_document(
        message_id="msg-001",
        channel="email",
        label="phishing",
        text="Your account requires verification.",
        sender="attacker@example.com",
        receiver="victim@example.com",
    )

    assert isinstance(
        document,
        ThreatMemoryDocument,
    )

    assert document.document_id == "msg-001"
    assert document.channel == "EMAIL"
    assert document.label == "phishing"
    assert document.sender == "attacker@example.com"


def test_sms_document_without_metadata():

    document = build_memory_document(
        message_id="sms-001",
        channel="sms",
        label="legitimate",
        text="Your appointment is tomorrow.",
    )

    assert document.channel == "SMS"
    assert document.label == "legitimate"
    assert document.sender is None
    assert document.receiver is None


def test_invalid_channel_is_rejected():

    try:
        build_memory_document(
            message_id="msg-001",
            channel="URL",
            label="phishing",
            text="Test",
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid channel should raise ValueError"
    )


def test_invalid_label_is_rejected():

    try:
        build_memory_document(
            message_id="msg-001",
            channel="EMAIL",
            label="unknown",
            text="Test",
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid label should raise ValueError"
    )