from collections.abc import Mapping


SMS_LABEL_MAPPING = {
	"ham": "legitimate",
	"spam": "phishing",
}


def require_email_label_mapping(mapping: Mapping | None) -> dict[str, str]:
	if mapping is None or set(mapping) != {"0", "1"}:
		raise ValueError(
			"EMAIL_LABEL_MAPPING must explicitly map both '0' and '1' "
			"before email processing can write outputs."
		)
	values = {str(key): str(value) for key, value in mapping.items()}
	if not all(values.values()):
		raise ValueError("EMAIL_LABEL_MAPPING values must be non-empty labels.")
	if set(values.values()) != {"legitimate", "phishing"}:
		raise ValueError(
			"EMAIL_LABEL_MAPPING must map the two source labels to "
			"'legitimate' and 'phishing'."
		)
	return values


def normalize_email_label(value: object, mapping: Mapping | None) -> str:
	labels = require_email_label_mapping(mapping)
	key = str(value).strip()
	if key not in labels:
		raise ValueError(f"Unmapped email label: {value!r}")
	return labels[key]


def normalize_sms_label(value: object) -> str:
	key = str(value).strip().lower()
	if key not in SMS_LABEL_MAPPING:
		raise ValueError(f"Unsupported SMS label: {value!r}")
	return SMS_LABEL_MAPPING[key]
