from __future__ import annotations

from dataclasses import dataclass

from src.rag.retriever import RetrievedThreat


@dataclass(frozen=True)
class ThreatContext:
    query_channel: str
    retrieved_count: int
    similar_phishing_count: int
    similar_legitimate_count: int
    average_similarity: float
    evidence: list[RetrievedThreat]


def build_threat_context(
    query_channel: str,
    retrieved_threats: list[RetrievedThreat],
) -> ThreatContext:
    """
    Build structured historical threat context.

    This component summarizes retrieved evidence only.
    It does not classify the current message.
    """

    query_channel = query_channel.upper()

    if query_channel not in {"EMAIL", "SMS"}:
        raise ValueError("query_channel must be EMAIL or SMS.")

    phishing_count = sum(
        1
        for threat in retrieved_threats
        if threat.label == "phishing"
    )

    legitimate_count = sum(
        1
        for threat in retrieved_threats
        if threat.label == "legitimate"
    )

    if retrieved_threats:
        average_similarity = sum(
            threat.similarity
            for threat in retrieved_threats
        ) / len(retrieved_threats)
    else:
        average_similarity = 0.0

    return ThreatContext(
        query_channel=query_channel,
        retrieved_count=len(retrieved_threats),
        similar_phishing_count=phishing_count,
        similar_legitimate_count=legitimate_count,
        average_similarity=average_similarity,
        evidence=list(retrieved_threats),
    )