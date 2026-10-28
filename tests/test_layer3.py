import pandas as pd
import numpy as np

from src.layer3_behavior.sender_profile import (
    build_sender_profiles,
    get_sender_profile,
)
from src.layer3_behavior.behavioral_features import (
    build_behavioral_features,
)
from src.layer3_behavior.anomaly_detector import (
    detect_temporal_anomaly,
)
from src.layer3_behavior.campaign_similarity import (
    cosine_similarity,
    compare_embedding_to_history,
)
def test_cosine_similarity_identical_vectors():

    first = np.array([1.0, 0.0, 0.0])
    second = np.array([1.0, 0.0, 0.0])

    result = cosine_similarity(
        first,
        second,
    )

    assert result == 1.0


def test_campaign_similarity_detects_similar_messages():

    current = np.array([1.0, 0.0, 0.0])

    history = np.array(
        [
            [1.0, 0.0, 0.0],
            [0.99, 0.1, 0.0],
            [0.0, 1.0, 0.0],
        ]
    )

    result = compare_embedding_to_history(
        current,
        history,
        threshold=0.85,
    )

    assert result.available is True
    assert result.max_similarity >= 0.99
    assert result.similar_message_count == 2


def test_campaign_similarity_without_embeddings_is_unavailable():

    result = compare_embedding_to_history(
        None,
        None,
    )

    assert result.available is False
    assert result.similar_message_count == 0
def test_temporal_anomaly_detects_unusual_hour():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "timestamp": "2026-01-01 09:00:00",
            },
            {
                "sender": "alice@example.com",
                "timestamp": "2026-01-02 10:00:00",
            },
            {
                "sender": "alice@example.com",
                "timestamp": "2026-01-03 10:30:00",
            },
        ]
    )

    result = detect_temporal_anomaly(
        events,
        "alice@example.com",
        "2026-01-04 03:15:00",
    )

    assert result.available is True
    assert result.anomaly == 1
    assert result.current_hour == 3
    assert result.historical_message_count == 3


def test_temporal_anomaly_accepts_typical_hour():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "timestamp": "2026-01-01 09:00:00",
            },
            {
                "sender": "alice@example.com",
                "timestamp": "2026-01-02 10:00:00",
            },
        ]
    )

    result = detect_temporal_anomaly(
        events,
        "alice@example.com",
        "2026-01-03 10:30:00",
    )

    assert result.available is True
    assert result.anomaly == 0


def test_temporal_anomaly_without_metadata_is_unavailable():

    events = pd.DataFrame(
        [
            {
                "sender": None,
                "timestamp": None,
            }
        ]
    )

    result = detect_temporal_anomaly(
        events,
        None,
        None,
    )

    assert result.available is False
    assert result.anomaly == 0

def test_sender_profiles_are_built():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-01 10:00:00",
            },
            {
                "sender": "alice@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-02 10:00:00",
            },
            {
                "sender": "alice@example.com",
                "label": "phishing",
                "timestamp": "2026-01-03 10:00:00",
            },
            {
                "sender": "attacker@example.com",
                "label": "phishing",
                "timestamp": "2026-01-04 10:00:00",
            },
        ]
    )

    profiles = build_sender_profiles(events)

    alice = get_sender_profile(
        profiles,
        "alice@example.com",
    )

    assert alice is not None
    assert alice.message_count == 3
    assert alice.legitimate_count == 2
    assert alice.phishing_count == 1
    assert alice.phishing_rate == 1 / 3


def test_unknown_sender_returns_none():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-01 10:00:00",
            }
        ]
    )

    profiles = build_sender_profiles(events)

    result = get_sender_profile(
        profiles,
        "unknown@example.com",
    )

    assert result is None


def test_missing_sender_is_not_fabricated():

    events = pd.DataFrame(
        [
            {
                "sender": None,
                "label": "phishing",
                "timestamp": "2026-01-01 10:00:00",
            }
        ]
    )

    profiles = build_sender_profiles(events)

    assert profiles.empty
from src.layer3_behavior.relationship_graph import (
    build_relationship_profiles,
    get_relationship_profile,
)


def test_relationship_profiles_are_built():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
            },
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
            },
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "phishing",
            },
            {
                "sender": "attacker@example.com",
                "receiver": "bob@example.com",
                "label": "phishing",
            },
        ]
    )

    profiles = build_relationship_profiles(events)

    relationship = get_relationship_profile(
        profiles,
        "alice@example.com",
        "bob@example.com",
    )

    assert relationship is not None
    assert relationship.interaction_count == 3
    assert relationship.legitimate_count == 2
    assert relationship.phishing_count == 1
    assert relationship.phishing_rate == 1 / 3


def test_new_relationship_returns_none():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
            }
        ]
    )

    profiles = build_relationship_profiles(events)

    relationship = get_relationship_profile(
        profiles,
        "new@example.com",
        "bob@example.com",
    )

    assert relationship is None


def test_missing_relationship_endpoints_are_not_fabricated():

    events = pd.DataFrame(
        [
            {
                "sender": None,
                "receiver": "bob@example.com",
                "label": "phishing",
            },
            {
                "sender": "attacker@example.com",
                "receiver": None,
                "label": "phishing",
            },
        ]
    )

    profiles = build_relationship_profiles(events)

    assert profiles.empty
def test_behavioral_features_detect_known_relationship():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-01 10:00:00",
            },
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-02 10:00:00",
            },
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "phishing",
                "timestamp": "2026-01-03 10:00:00",
            },
        ]
    )

    sender_profiles = build_sender_profiles(events)

    relationship_profiles = build_relationship_profiles(
        events
    )

    features = build_behavioral_features(
        sender_profiles,
        relationship_profiles,
        "alice@example.com",
        "bob@example.com",
    )

    assert features.sender_known == 1
    assert features.sender_message_count == 3
    assert features.sender_phishing_rate == 1 / 3

    assert features.relationship_known == 1
    assert features.relationship_interaction_count == 3
    assert features.relationship_phishing_rate == 1 / 3

    assert features.relationship_novelty == 0


def test_behavioral_features_detect_new_relationship():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-01 10:00:00",
            }
        ]
    )

    sender_profiles = build_sender_profiles(events)

    relationship_profiles = build_relationship_profiles(
        events
    )

    features = build_behavioral_features(
        sender_profiles,
        relationship_profiles,
        "alice@example.com",
        "charlie@example.com",
    )

    assert features.sender_known == 1
    assert features.relationship_known == 0
    assert features.relationship_novelty == 1


def test_behavioral_features_unknown_sender():

    events = pd.DataFrame(
        [
            {
                "sender": "alice@example.com",
                "receiver": "bob@example.com",
                "label": "legitimate",
                "timestamp": "2026-01-01 10:00:00",
            }
        ]
    )

    sender_profiles = build_sender_profiles(events)

    relationship_profiles = build_relationship_profiles(
        events
    )

    features = build_behavioral_features(
        sender_profiles,
        relationship_profiles,
        "unknown@example.com",
        "bob@example.com",
    )

    assert features.sender_known == 0
    assert features.sender_message_count is None
    assert features.sender_phishing_rate is None

    assert features.relationship_known == 0
    assert features.relationship_novelty == 0