from __future__ import annotations

from dataclasses import dataclass


INTENT_CATEGORIES = (
	"NORMAL_COMMUNICATION",
	"ACCOUNT_VERIFICATION",
	"CREDENTIAL_REQUEST",
	"PAYMENT_REQUEST",
	"FINANCIAL_FRAUD",
	"IMPERSONATION",
	"THREAT_OR_URGENCY",
	"DELIVERY_SCAM",
	"GOVERNMENT_IMPERSONATION",
	"TECH_SUPPORT_SCAM",
	"REWARD_SCAM",
	"OTHER",
)


@dataclass(frozen=True)
class IntentAnnotation:
	label: str | None
	source: str
	is_ground_truth: bool = False


def validate_intent_annotation(annotation: IntentAnnotation) -> IntentAnnotation:
	if annotation.label is not None and annotation.label not in INTENT_CATEGORIES:
		raise ValueError(f"Unsupported intent category: {annotation.label}")
	if annotation.source == "human_verified" and annotation.label is None:
		raise ValueError("Human-verified intent annotations require a label.")
	return annotation


def unannotated_intent() -> IntentAnnotation:
	return IntentAnnotation(label=None, source="unavailable", is_ground_truth=False)
