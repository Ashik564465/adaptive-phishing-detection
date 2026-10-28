from src.adaptive.feedback import create_feedback_record
from src.adaptive.knowledge_updater import (
    update_knowledge_from_feedback,
)


def test_phishing_feedback_creates_memory_document():
    feedback = create_feedback_record(
        message_id="msg-001",
        feedback_type="confirmed_phishing",
        source="user",
        corrected_label="phishing",
        timestamp="2026-09-20T10:00:00",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text="Your account requires verification.",
    )

    assert update.accepted is True
    assert update.document is not None
    assert update.document.document_id == "msg-001"
    assert update.document.label == "phishing"
    assert update.document.channel == "EMAIL"


def test_legitimate_feedback_creates_memory_document():
    feedback = create_feedback_record(
        message_id="msg-002",
        feedback_type="confirmed_legitimate",
        source="admin",
        corrected_label="legitimate",
        timestamp="2026-09-20T10:00:00",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="SMS",
        text="Meeting starts at 10 AM.",
    )

    assert update.accepted is True
    assert update.document is not None
    assert update.document.label == "legitimate"
    assert update.document.channel == "SMS"


def test_unknown_feedback_is_not_added():
    feedback = create_feedback_record(
        message_id="msg-003",
        feedback_type="unknown",
        source="user",
        timestamp="2026-09-20T10:00:00",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text="Unknown message.",
    )

    assert update.accepted is False
    assert update.document is None


def test_incorrect_prediction_with_correction_is_added():
    feedback = create_feedback_record(
        message_id="msg-004",
        feedback_type="incorrect_prediction",
        source="admin",
        corrected_label="phishing",
        timestamp="2026-09-20T10:00:00",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text="Urgent account verification required.",
    )

    assert update.accepted is True
    assert update.document is not None
    assert update.document.label == "phishing"


def test_sender_and_receiver_are_preserved():
    feedback = create_feedback_record(
        message_id="msg-005",
        feedback_type="confirmed_phishing",
        source="admin",
        corrected_label="phishing",
        timestamp="2026-09-20T10:00:00",
    )

    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text="Verify your account.",
        sender="attacker@example.com",
        receiver="user@example.com",
    )

    assert update.document is not None
    assert update.document.sender == "attacker@example.com"
    assert update.document.receiver == "user@example.com"