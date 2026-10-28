from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticEvidence:
	urgency: float | None = None
	coercion_or_threat: float | None = None
	impersonation: float | None = None
	requested_action: str | None = None
	credential_intent: float | None = None
	financial_intent: float | None = None
	source: str = "unavailable"
	is_ground_truth: bool = False


def empty_semantic_evidence() -> SemanticEvidence:
	"""Return explicit placeholders until validated auxiliary annotations exist."""
	return SemanticEvidence()


def validate_semantic_evidence(evidence: SemanticEvidence) -> SemanticEvidence:
	for name in (
		"urgency",
		"coercion_or_threat",
		"impersonation",
		"credential_intent",
		"financial_intent",
	):
		value = getattr(evidence, name)
		if value is not None and not 0 <= value <= 1:
			raise ValueError(f"{name} must be in [0, 1] when provided.")
	return evidence
