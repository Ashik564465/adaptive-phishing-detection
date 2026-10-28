# Dataset Audit

## Scope and input discrepancy

This is an inspection-only audit. The source datasets were not modified, converted, or deduplicated.

The requested path `data/raw/email_combined.csv` does not exist in the workspace. The available email source is `data/raw/email_combined.xlsx`, which was audited as the email dataset. The SMS source exists at `data/raw/sms_combined.csv`.

The email workbook contains one populated sheet, `Sheet1`. Values and types below are inferred from the stored cell values; no model training or feature engineering was performed.

## 1. File size

| Dataset | Actual path | File size |
|---|---|---:|
| Email | `data/raw/email_combined.xlsx` | 29,489,527 bytes |
| SMS | `data/raw/sms_combined.csv` | 816,434 bytes |

## 2. Row count

| Dataset | Data rows |
|---|---:|
| Email | 48,295 |
| SMS | 10,430 |

## 3-5. Columns, data types, and missing values

### Email

| Column | Inferred type | Missing | Missing % |
|---|---|---:|---:|
| `sender` | string | 366 | 0.76% |
| `receiver` | string | 2,003 | 4.15% |
| `date` | string/date candidate | 482 | 1.00% |
| `subject` | string | 119 | 0.25% |
| `body` | string | 291 | 0.60% |
| `label` | integer-like | 0 | 0.00% |
| `urls` | integer-like | 0 | 0.00% |

The `date` column is present, but its parseability and timezone semantics must be validated before use as a timestamp. The `urls` column is present as a numeric field, but it must not be used as a URL reputation, URL classification, or URL phishing-detection layer under this project specification.

### SMS

| Column | Inferred type | Missing | Missing % |
|---|---|---:|---:|
| `label` | string | 0 | 0.00% |
| `text` | string | 0 | 0.00% |

## 6. Duplicate rows

Duplicate counts below mean duplicate excess rows: for each repeated complete row, the first occurrence is retained conceptually and subsequent occurrences are counted as duplicates.

| Dataset | Duplicate excess rows | Interpretation |
|---|---:|---|
| Email | 2 | Very low exact-row duplication |
| SMS | 2,550 | Material duplication; repeated message text/label pairs must be handled before train/test splitting |

The SMS file therefore has 7,880 distinct complete `(label, text)` rows if duplicate complete rows are collapsed. Duplicate removal should be a later, documented preprocessing decision; it was not performed for this audit.

## 7. Labels and distribution

### Email

The email label values are `0` and `1`:

| Label | Rows | Share |
|---:|---:|---:|
| `0` | 21,403 | 44.32% |
| `1` | 26,892 | 55.68% |

The semantic meaning of `0` and `1` was not assumed. The project must confirm which value means phishing and which means legitimate from dataset documentation or provenance before training.

### SMS

The SMS label values are `ham` and `spam`:

| Label | Rows | Share |
|---|---:|---:|
| `ham` | 7,072 | 67.77% |
| `spam` | 3,358 | 32.23% |

SMS has a moderate class imbalance toward `ham`. Email is closer to balanced but still requires stratified evaluation and class-aware metrics.

## 8-13. Email field availability

| Requirement | Finding |
|---|---|
| Email sender exists | Yes: `sender`; 366 rows are missing it |
| Email recipient exists | Yes: `receiver`; 2,003 rows are missing it |
| Email timestamp exists | Yes: `date`; 482 rows are missing it; parsing/timezone need validation |
| Email subject exists | Yes: `subject`; 119 rows are missing it |
| Email body exists | Yes: `body`; 291 rows are missing it |
| SPF fields exist | No field matching SPF was found |
| DKIM fields exist | No field matching DKIM was found |
| DMARC fields exist | No field matching DMARC was found |
| From/Reply-To fields exist | No dedicated fields were found |
| Return-Path field exists | No dedicated field was found |
| Display-name field exists | No dedicated field was found |

Authentication values must remain unavailable/null. They must not be inferred from the label, sender string, or any other current column. Real `.eml` files or captured header metadata can be integrated later.

## 14-16. SMS field availability

| Requirement | Finding |
|---|---|
| SMS sender exists | No sender field exists |
| SMS recipient exists | No recipient field exists |
| SMS timestamp exists | No timestamp field exists |
| SMS text exists | Yes: `text`, complete for all 10,430 rows |

Consequently, Sender ID, known/unknown sender, sender history, sender reputation, recipient relationship, time-of-day anomaly, frequency anomaly, channel anomaly, and cross-channel behavior cannot be calculated for the current SMS records.

## 17. Layer 3 metadata availability

The current datasets do not contain the metadata needed for a complete Layer 3 behavioral implementation. Email provides sender, receiver, and a timestamp candidate, so limited email sender/recipient aggregation may be possible after validation. SMS has no sender, recipient, or timestamp and cannot support behavioral profiles.

Missing or separately required metadata includes:

- Stable pseudonymous sender and recipient identifiers for both channels.
- Message/event IDs and an event ingestion timestamp.
- Validated event timestamp, timezone, and ordering information.
- Email authentication results and raw header provenance.
- Email From, Reply-To, Return-Path, and display-name components.
- SMS Sender ID, recipient/device identifier, and known-contact status.
- Historical sender-recipient interaction events across both channels.
- Channel and event-type fields suitable for cross-channel sequencing.
- A trusted label definition, label source, and feedback/audit history.

No graph database is required for the first implementation; the requested relationship graph can be represented with tabular edge records once these fields exist.

## 18. Potential data leakage risks

- The `urls` column may encode information derived from the message or dataset construction. It is excluded from the detection architecture because URL-based detection is prohibited, and it should not be used as a shortcut feature.
- Exact and near-duplicate messages, especially in SMS, can cross a random train/test split and inflate performance. Splitting must occur after duplicate and similarity-group analysis.
- Sender and receiver identifiers can leak labels if a sender appears almost exclusively in one class. Sender-aware and group-aware evaluation should be considered.
- Email source or collection-batch artifacts may correlate with the label. Dataset provenance/source columns should be investigated if discovered later.
- Timestamp or collection-order artifacts can leak the label or create an unrealistic random split. Temporal evaluation is preferable once timestamps are validated.
- Missingness itself may be predictive because fields are incomplete in a class-dependent way. Missing indicators should be monitored and evaluated explicitly.
- Labels may reflect source-specific spam/phishing definitions rather than one unified target. The email `0/1` semantics are currently unverified and must not be guessed.
- User feedback and adaptive knowledge must be kept out of the evaluation set unless the evaluation protocol explicitly models time and feedback availability.

## 19. Potential class imbalance

SMS is moderately imbalanced (`ham` 67.77%, `spam` 32.23%). Email is mildly imbalanced (`label 1` 55.68%, `label 0` 44.32%), with the label meaning still unknown. Accuracy alone is insufficient; use per-class precision, recall, F1, confusion matrices, and PR-AUC where appropriate. Splits should be stratified by the confirmed target label and grouped to control duplicates or sender leakage.

## 20. Architecture that can be implemented directly

### Layer 1: Identity and authenticity

- Email: partial sender/receiver identity features and basic address consistency checks may be explored from the available strings.
- Email: SPF, DKIM, DMARC, From/Reply-To, Return-Path, and display-name authenticity checks cannot be implemented from the current fields.
- SMS: text-only processing is possible, but Sender ID, known/unknown status, sender history, and project-derived sender reputation are unavailable.

### Layer 2: Intent and NLP

This is the most directly implementable layer. Email `subject + body` and SMS `text` can support a Hugging Face Transformer primary classifier, provided the target-label mapping and task definition are confirmed. Transformer-based semantic representations can also support intent, urgency, coercion/threat, impersonation, and requested-action signals. Some of these auxiliary labels are not present and would require annotation, weak supervision with validation, or a separately defined task dataset.

### Layer 3: Behavioral intelligence

Only a limited email sender/receiver profile is potentially available, subject to date parsing and identity normalization. Complete sender history, interaction count, relationship novelty, frequency anomaly, time-of-day anomaly, channel anomaly, cross-channel behavior, and campaign similarity require additional event metadata. SMS behavior is not implementable from this file alone.

### Adaptive component

The architecture can be designed now, but meaningful adaptive retrieval requires validated feedback, threat-pattern documents, and a Hugging Face embedding model/vector store. Gemini can provide structured contextual reasoning after retrieval, but it must remain an additional contextual signal; the Transformer remains the primary NLP detector. No retraining-after-every-message behavior should be introduced.

## 21. Metadata to collect separately

Collect or derive the following through controlled, privacy-conscious data collection:

1. Raw email headers or `.eml` files, preserving SPF/DKIM/DMARC results and authentication provenance.
2. Parsed From, Reply-To, Return-Path, display name, sender address, recipient address, and message ID.
3. SMS Sender ID, recipient/device pseudonym, known-contact status, and message event timestamp.
4. Stable pseudonymous IDs, channel, timezone, event type, and ingestion/source identifiers.
5. Historical communication events for sender profiles and sender-recipient relationship edges.
6. Verified phishing/legitimate and ham/spam label definitions, label source, and annotation/feedback records.
7. Intent and auxiliary NLP annotations for urgency, coercion/threat, impersonation, and requested action.
8. Adaptive feedback records and validated threat-pattern provenance for RAG documents.

Do not fabricate any unavailable authentication, sender, recipient, or timestamp values.

## 22. Is another public dataset necessary?

Not strictly necessary for the first audit or for an initial text-only Layer 2 prototype. The current data is sufficient to begin schema validation, preprocessing design, label-definition work, and a constrained Transformer experiment after the email label semantics are confirmed.

Additional public data is advisable, but not automatically required, for the missing objectives: authenticated email headers, SMS sender/recipient behavior, cross-channel event sequences, intent/auxiliary annotations, and external generalization testing. Any added data must have compatible label definitions, documented provenance, privacy/legal approval, and no URL-based detection dependency.

## Audit conclusion

The immediate implementation boundary is a text-first Transformer Layer 2 plus a schema that preserves nullable identity, authentication, and behavioral fields for future enrichment. A complete three-layer detector cannot be honestly implemented from the current files: email authentication metadata and nearly all SMS/ cross-channel behavioral metadata are absent. The next data step is to confirm label semantics and validate the email workbook's date values and provenance; model training is intentionally outside this first task.
