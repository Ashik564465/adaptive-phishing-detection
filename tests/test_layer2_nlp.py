import pandas as pd
import pytest

from src.layer2_nlp.intent_classifier import INTENT_CATEGORIES, unannotated_intent
from src.layer2_nlp.transformer_classifier import (
    LABEL_TO_ID,
    build_input_text,
    inference_output,
    prepare_dataset,
    split_dataset,
)


def sample_frame():
    return pd.DataFrame(
        {
            "message_id": ["e1", "s1", "e2", "s2"],
            "channel": ["EMAIL", "SMS", "EMAIL", "SMS"],
            "subject": ["Notice", None, "Notice", None],
            "body": ["Your account is safe", "Your prize is ready", "Your account is safe", "Please verify payment"],
            "label": ["legitimate", "phishing", "legitimate", "phishing"],
        }
    )


def test_label_mapping_and_text_construction():
    assert LABEL_TO_ID == {"legitimate": 0, "phishing": 1}
    assert build_input_text(sample_frame().iloc[0]).startswith("[CHANNEL] EMAIL [SUBJECT]")
    assert build_input_text(sample_frame().iloc[1]) == "[CHANNEL] SMS [BODY] Your prize is ready"


def test_url_exclusion_and_missing_fields():
    frame = sample_frame()
    frame["urls"] = [1, 0, 1, 0]
    prepared = prepare_dataset(frame)
    assert "urls" not in prepared["text"].iloc[0]
    assert "sender" not in prepared["text"].iloc[0]
    assert "None" not in prepared["text"].iloc[1]


def test_duplicate_group_split_has_no_overlap():
    train, validation, test = split_dataset(sample_frame(), seed=42)
    groups = [set(part.text.str.casefold()) for part in (train, validation, test)]
    assert groups[0].isdisjoint(groups[1])
    assert groups[0].isdisjoint(groups[2])
    assert groups[1].isdisjoint(groups[2])


def test_inference_schema_and_probability_range():
    result = inference_output("m1", "email", [0.25, 0.75])
    assert result["channel"] == "EMAIL"
    assert result["predicted_label"] == 1
    assert result["nlp_risk"] == 75.0
    with pytest.raises(ValueError):
        inference_output("m1", "SMS", [1.2, -0.2])


def test_intent_categories_are_not_ground_truth():
    annotation = unannotated_intent()
    assert set(INTENT_CATEGORIES) >= {"NORMAL_COMMUNICATION", "CREDENTIAL_REQUEST", "OTHER"}
    assert annotation.label is None
    assert annotation.is_ground_truth is False