from src.adaptive.feedback import create_feedback_record


def test_create_phishing_feedback():
    record = create_feedback_record(
        message_id="msg-001",
        feedback_type="confirmed_phishing",
        source="user",
        corrected_label="phishing",
        timestamp="2026-09-20T10:00:00",
    )

    assert record.message_id == "msg-001"
    assert record.feedback_type == "confirmed_phishing"
    assert record.corrected_label == "phishing"
    assert record.source == "user"


def test_create_legitimate_feedback():
    record = create_feedback_record(
        message_id="msg-002",
        feedback_type="confirmed_legitimate",
        source="admin",
        corrected_label="legitimate",
        timestamp="2026-09-20T10:00:00",
    )

    assert record.corrected_label == "legitimate"


def test_feedback_without_correction():
    record = create_feedback_record(
        message_id="msg-003",
        feedback_type="unknown",
        source="user",
        timestamp="2026-09-20T10:00:00",
    )

    assert record.corrected_label is None


def test_invalid_feedback_type():
    try:
        create_feedback_record(
            message_id="msg-004",
            feedback_type="random_value",
            source="user",
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid feedback type should raise ValueError."
    )


def test_invalid_label():
    try:
        create_feedback_record(
            message_id="msg-005",
            feedback_type="confirmed_phishing",
            source="user",
            corrected_label="spam",
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid corrected label should raise ValueError."
    )


def test_empty_message_id():
    try:
        create_feedback_record(
            message_id="",
            feedback_type="unknown",
            source="user",
        )
    except ValueError:
        return

    raise AssertionError(
        "Empty message ID should raise ValueError."
    )