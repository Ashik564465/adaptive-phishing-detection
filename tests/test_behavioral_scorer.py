from src.layer3_behavior.behavioral_features import BehavioralFeatures
from src.layer3_behavior.behavioral_scorer import calculate_behavioral_risk


def test_unknown_sender_has_behavioral_risk():
    features = BehavioralFeatures(
        sender_known=False,
        sender_message_count=0,
        sender_phishing_rate=0.0,
        relationship_known=False,
        relationship_interaction_count=0,
        relationship_phishing_rate=0.0,
        relationship_novelty=False,
    )

    result = calculate_behavioral_risk(features)

    assert result.risk_score > 0
    assert result.risk_score <= 1


def test_known_safe_relationship_has_low_risk():
    features = BehavioralFeatures(
        sender_known=True,
        sender_message_count=20,
        sender_phishing_rate=0.0,
        relationship_known=True,
        relationship_interaction_count=10,
        relationship_phishing_rate=0.0,
        relationship_novelty=False,
    )

    result = calculate_behavioral_risk(features)

    assert result.risk_score == 0.0


def test_new_relationship_increases_risk():
    features = BehavioralFeatures(
        sender_known=True,
        sender_message_count=20,
        sender_phishing_rate=0.0,
        relationship_known=False,
        relationship_interaction_count=0,
        relationship_phishing_rate=0.0,
        relationship_novelty=True,
    )

    result = calculate_behavioral_risk(features)

    assert result.risk_score > 0