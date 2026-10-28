# Proposed Unified Schema

This schema is a target contract for a unified email/SMS event table. It does not alter the current datasets. Fields unavailable today remain nullable until collected from trusted sources.

## Design principles

- Preserve raw evidence and provenance separately from derived model features.
- Use stable pseudonymous identifiers rather than exposing personal addresses or phone numbers in behavioral tables.
- Keep authentication fields explicitly nullable with an `unavailable_reason`; never infer SPF, DKIM, or DMARC.
- Keep URL-related content out of the detection layers. The current email `urls` count is retained only as an excluded audit/provenance field, not as a model feature.
- Keep labels, annotations, feedback, and adaptive knowledge provenance explicit.
- Store timestamps with timezone information when known.

## Unified message table

| Field | Type | Required now | Description |
|---|---|---:|---|
| `message_id` | string | Future | Stable source ID or generated privacy-safe ID |
| `channel` | enum: `email`, `sms` | Yes | Communication channel |
| `source_dataset` | string | Yes | Dataset/provenance identifier |
| `source_row_id` | string/integer | Future | Original row or record identifier |
| `sender_id` | string, nullable | Email partial | Stable pseudonymous sender identity |
| `recipient_id` | string, nullable | Email partial | Stable pseudonymous recipient identity |
| `sender_raw` | string, nullable | Email partial | Restricted raw sender value, if policy permits |
| `recipient_raw` | string, nullable | Email partial | Restricted raw recipient value, if policy permits |
| `sender_id_type` | enum, nullable | Future | Email address, phone/Sender ID, or other |
| `recipient_id_type` | enum, nullable | Future | Email address, phone/device, or other |
| `timestamp_utc` | datetime, nullable | Email candidate | Normalized event time in UTC |
| `timestamp_original` | string, nullable | Email candidate | Original timestamp before normalization |
| `timestamp_timezone` | string, nullable | Future | Original timezone or `unknown` |
| `subject` | string, nullable | Email | Email subject; null for SMS |
| `body_text` | string, nullable | Yes | Normalized message text used by Layer 2 |
| `body_raw_reference` | string, nullable | Future | Controlled reference to raw content |
| `language` | string, nullable | Future | Detected or annotated language |
| `label` | string, nullable | Yes for supervised records | Original or unified target label |
| `label_definition` | string, nullable | Future | Meaning of the label, e.g. phishing/legitimate or spam/ham |
| `label_source` | string, nullable | Future | Dataset, analyst, user feedback, or adjudication |
| `label_confidence` | float, nullable | Future | Confidence or adjudicated certainty |
| `is_duplicate_grouped` | boolean, nullable | Future | Whether duplicate/similar grouping was applied |
| `duplicate_group_id` | string, nullable | Future | Group key used to prevent split leakage |
| `raw_urls_count_excluded` | integer, nullable | Email only | Audit-only source value; excluded from detection |

## Layer 1 identity and authenticity fields

These fields belong to the message record or a linked authentication record. `unknown` means the source was checked but did not provide a usable value; `null` means not collected/not applicable. Both must be distinguished from a positive or negative authentication result.

| Field | Type | Description |
|---|---|---|
| `email_from_address` | string, nullable | Parsed From address |
| `email_from_display_name` | string, nullable | Parsed From display name |
| `email_reply_to` | string, nullable | Reply-To address |
| `email_return_path` | string, nullable | Return-Path address |
| `from_reply_to_consistent` | boolean, nullable | Consistency result, not an inferred authentication result |
| `return_path_consistent` | boolean, nullable | Return-Path consistency when available |
| `display_name_consistent` | boolean, nullable | Display-name consistency result |
| `spf_result` | enum, nullable | `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`, `unknown` |
| `dkim_result` | enum, nullable | DKIM verification result with provenance |
| `dmarc_result` | enum, nullable | DMARC verification result with provenance |
| `authentication_checked_at` | datetime, nullable | Time authentication was observed/verified |
| `authentication_source` | string, nullable | Raw `.eml`, gateway header, or trusted provider |
| `authentication_unavailable_reason` | string, nullable | Why an auth value is unavailable |
| `sms_sender_id` | string, nullable | Sender ID for SMS |
| `sms_sender_known` | boolean, nullable | Whether sender is known to the recipient/project |
| `sms_sender_history_id` | string, nullable | Link to sender history profile |

## Layer 3 behavioral event and profile fields

These can be represented in a derived message table or separate profile/edge tables. They require historical events; they must not be fabricated from one isolated message.

| Field | Type | Description |
|---|---|---|
| `sender_message_count_prior` | integer, nullable | Sender history before this event |
| `sender_reputation_prior` | float, nullable | Project-derived reputation before this event |
| `sender_recipient_interaction_count_prior` | integer, nullable | Prior pair interaction count |
| `relationship_first_seen_at` | datetime, nullable | First observed sender-recipient relationship |
| `relationship_novelty_score` | float, nullable | Novelty based on prior relationship history |
| `message_frequency_score` | float, nullable | Frequency anomaly from historical event windows |
| `time_of_day_anomaly_score` | float, nullable | Deviation from sender's historical time pattern |
| `channel_anomaly_score` | float, nullable | Deviation from normal channel usage |
| `cross_channel_event_count_prior` | integer, nullable | Prior related activity across email and SMS |
| `campaign_group_id` | string, nullable | Similar-message/campaign cluster ID |
| `campaign_similarity_score` | float, nullable | Similarity to known campaign messages |
| `behavior_profile_as_of` | datetime, nullable | Profile cutoff time preventing future-event leakage |

A graph-like representation can use an edge table with `sender_id`, `recipient_id`, `channel`, `first_seen_at`, `last_seen_at`, `interaction_count`, and `relationship_features`. A graph database is not required.

## Layer 2 model outputs

These are derived outputs, not raw input fields. The Transformer remains the primary phishing/legitimate or spam/ham detector.

| Field | Type | Description |
|---|---|---|
| `nlp_model_name` | string | Hugging Face model identifier/version |
| `nlp_model_version` | string | Locally trained/fine-tuned version |
| `classification_label` | string | Primary model class |
| `classification_score` | float | Primary model confidence/score |
| `intent_label` | string, nullable | Intent class; requires annotation/task definition |
| `intent_score` | float, nullable | Intent confidence |
| `semantic_embedding_ref` | string, nullable | Reference to stored embedding |
| `urgency_score` | float, nullable | Urgency signal |
| `coercion_threat_score` | float, nullable | Coercion/threat signal |
| `impersonation_score` | float, nullable | Impersonation signal |
| `requested_action` | string/nullable | Requested action category |
| `requested_action_score` | float, nullable | Requested-action confidence |
| `nlp_features_as_of` | datetime | Inference time |

## Adaptive/RAG fields

| Field | Type | Description |
|---|---|---|
| `feedback_id` | string, nullable | Linked user/admin feedback record |
| `feedback_label` | string, nullable | Validated feedback label |
| `feedback_validated` | boolean, nullable | Validation result before knowledge extraction |
| `threat_pattern_id` | string, nullable | Extracted validated pattern |
| `embedding_document_id` | string, nullable | Document stored in vector store |
| `retrieved_pattern_ids` | array/string, nullable | Similar historical pattern references |
| `rag_context_version` | string, nullable | Context builder version |
| `gemini_reasoning_ref` | string, nullable | Structured Gemini response reference |
| `adaptive_context_score` | float, nullable | Additional contextual signal, never sole classifier |
| `adaptive_knowledge_as_of` | datetime, nullable | Knowledge cutoff time |

## Final fusion output fields

| Field | Type | Description |
|---|---|---|
| `identity_score` | float, nullable | Layer 1 score from available evidence only |
| `nlp_score` | float | Layer 2 primary score |
| `behavior_score` | float, nullable | Layer 3 score when metadata is sufficient |
| `adaptive_score` | float, nullable | Optional adaptive contextual contribution |
| `risk_score` | float | Final fused risk score |
| `risk_decision` | enum | `phishing`, `suspicious`, `legitimate`, or project-approved equivalent |
| `decision_reason_codes` | array/string | Structured explanation codes |
| `score_missing_components` | array/string | Components unavailable for this event |
| `fusion_model_version` | string | Fusion version |
| `decision_as_of` | datetime | Decision time |

## Current-to-target mapping

| Current source | Unified target |
|---|---|
| Email `sender` | `sender_raw`; normalized/pseudonymous `sender_id` when implemented |
| Email `receiver` | `recipient_raw`; normalized/pseudonymous `recipient_id` when implemented |
| Email `date` | `timestamp_original`; validated value may populate `timestamp_utc` |
| Email `subject` | `subject` |
| Email `body` | `body_text` after documented normalization |
| Email `label` | `label`, pending semantic confirmation |
| Email `urls` | `raw_urls_count_excluded`, audit-only |
| SMS `label` | `label`, with `label_definition=spam/ham` |
| SMS `text` | `body_text` |

## Validation rules before modeling

1. Confirm the email `0/1` label semantics from provenance; do not infer them from class counts.
2. Parse and validate email dates, including timezone handling and invalid values.
3. Decide how missing subject/body values are represented without fabricating content.
4. Normalize and pseudonymize identities before behavioral aggregation.
5. Build duplicate/similarity groups before creating train/validation/test splits.
6. Keep source labels and unified labels separate until label harmonization is approved.
7. Treat all authentication and behavioral fields as unavailable when their source evidence is absent.
8. Exclude URL counts and URL-derived features from all three detection layers.
9. Version every derived feature, embedding, feedback validation, RAG context, and final fusion decision.
