# Data Pipeline Report

## Execution status

Production output generation completed after the email label semantics were confirmed from the dataset source.

No raw file was modified. No model was trained, no Gemini call was made, no RAG component was built, and no URL feature was used.

## Inputs

| Dataset | Source rows | Source labels |
|---|---:|---|
| Email (`data/raw/email_combined.xlsx`) | 48,295 | `0`: 21,403; `1`: 26,892 |
| SMS (`data/raw/sms_combined.csv`) | 10,430 | `ham`: 7,072; `spam`: 3,358 |

## Canonical output metrics

These are non-destructive metrics calculated from normalized raw values. The corresponding files are not written until email label mapping is confirmed.

| Dataset | Canonical output rows | Normalized exact duplicate excess |
|---|---:|---:|
| Email | 48,289 | 6 |
| SMS | 7,880 | 2,550 |
| Unified | 56,169 | 2,550 SMS + 6 email duplicate excess rows |

Generated output label distributions:

- Email: `legitimate` 21,402; `phishing` 26,887.
- SMS: `legitimate` 5,605; `phishing` 2,275.

The small reduction from source label totals is due to exact duplicate removal.

The email duplicate count is the canonical count after whitespace/Unicode/HTML normalization and timestamp parsing, so it can differ from the earlier raw-cell duplicate count. Near-duplicate analysis found 2,148 candidate groups covering 10,088 candidate rows; these were reported only and not removed, so meaningful message text is preserved.

## Missing values and null handling

### Email

| Field | Missing source rows |
|---|---:|
| `sender` | 366 |
| `receiver` | 2,003 |
| `date` | 482 source blanks; 595 missing/unparseable after normalization |
| `subject` | 119 |
| `body` | 291 |

Excel missing cells remain null. They are never converted to the string `"nan"`, and no sender, recipient, timestamp, authentication value, or other metadata is fabricated.

### SMS

The processed schema sets `sender`, `recipient`, and `timestamp` to null for every SMS row because the source contains none of those fields. `subject` is also null because SMS has no subject column. `body` is normalized from `text`.

## Label handling

- SMS normalization is fixed: `ham` becomes `legitimate`; `spam` becomes `phishing`; `original_label` is preserved.
- Confirmed email mapping: `0` becomes `legitimate`; `1` becomes `phishing`; `original_label` is preserved.
- Email label semantics were confirmed before supervised model development: label 0 represents legitimate/safe messages and label 1 represents phishing/spam messages.

## Timestamp parsing

Email timestamps are parsed with mixed-format handling and normalized to UTC while retaining `timestamp_original` in the email processed frame:

- Valid parsed timestamps in output: 47,697
- Missing or unparseable timestamps in output: 592
- SMS timestamps: unavailable for all rows and remain null

The 595 email failures include the 482 source blanks plus nonblank values whose timezone/date syntax still requires a project-approved parsing policy. The pipeline does not invent a timestamp for them.

## Email behavioral metadata

Metrics below are derived from normalized email identity values without exposing raw addresses in the metadata design:

| Metric | Count |
|---|---:|
| Unique nonblank email senders | 29,960 |
| Unique nonblank email recipients | 6,150 |
| Unique sender-recipient relationships | 33,787 |
| Email behavioral events | 48,289 |
| Email sender profile rows generated | 29,944 |
| Email relationship profile rows generated | 33,746 |

When enabled, the pipeline writes stable SHA-256-based pseudonymous `sender_id` and `recipient_id` values to communication events, sender profiles, and relationship profiles. Raw email addresses are not written to those derived metadata files. SPF, DKIM, and DMARC are not inferred or generated.

The unified dataset contains `EMAIL` (48,289 rows) and `SMS` (7,880 rows). `timestamp_original` is retained as an email-only preservation field alongside the required unified schema so the original timestamp text remains available after UTC normalization.

## SMS behavioral metadata limitations

The pipeline creates only `data/metadata/sms_event_schema.md`. It does not create fake SMS sender profiles, relationship profiles, or behavioral events. Sender ID, recipient ID, timestamps, sender history, communication frequency, temporal behavior, and cross-channel behavior require additional source metadata.

## Output files

The following production files were generated:

- `data/processed/email_processed.parquet`
- `data/processed/sms_processed.parquet`
- `data/processed/unified_messages.parquet`
- `data/metadata/email_communication_events.csv`
- `data/metadata/email_sender_profiles.csv`
- `data/metadata/email_relationship_profiles.csv`

The SMS schema document is also present and does not fabricate unavailable behavioral fields.

## URL exclusion confirmation

The source email `urls` column is not included in the processed schema, feature columns, duplicate logic, behavioral metadata, or label handling. No URL reputation, URL blacklist, URL classification, WHOIS lookup, or URL phishing detector is implemented.

No fabricated sender, recipient, timestamp, SPF, DKIM, DMARC, Reply-To, or Return-Path metadata was introduced. SMS behavioral profiles were not generated because those source fields are unavailable.

## Validation

Focused validation completed successfully:

```text
6 passed
```

The tests cover schema fields, label normalization and fail-closed mapping, null handling, duplicate removal, mixed-format timestamp parsing, URL exclusion, and pseudonymization.