# Project Data Plan

## Decision

**No. The complete three-layer system cannot be implemented using the current datasets alone.**

The current files are sufficient for a constrained text-first Layer 2 prototype and for designing the interfaces for Layers 1 and 3. They are not sufficient for reliable identity/authenticity evidence, complete sender behavior, SMS behavior, or cross-channel behavior.

## What the current datasets can provide

### Can be derived now

- Email message text from `subject` and `body`, with explicit handling for missing values.
- SMS message text from `text`.
- Email sender and receiver string features from `sender` and `receiver`, subject to missing values, normalization, and privacy controls.
- Email date parsing and limited email-only temporal/frequency features, after validating date formats and timezone semantics.
- Dataset labels: email `0/1` and SMS `ham/spam`, after confirming the semantic meaning of the email labels.
- Transformer-based primary NLP classification inputs.
- Text embeddings for semantic representation and later retrieval.
- Limited email-only sender/receiver aggregation; this is not a complete cross-channel behavioral layer.

### Must remain excluded

The email `urls` field is not a permitted detection feature. No URL reputation, blacklist lookup, URL classification, WHOIS scoring, or URL phishing detector will be added.

## Minimum data required for actual implementation

These are the smallest additional data categories required to implement the proposed three-layer architecture honestly. They do not imply downloading public datasets.

### 1. Confirmed label contract

Required before supervised training:

- Authoritative meaning of email labels `0` and `1`.
- Confirmation that email and SMS labels represent the intended project targets.
- Label provenance and any known source-specific labeling rules.

This is a provenance requirement, not a new dataset requirement.

### 2. Email identity and authenticity evidence

Required for the email portion of Layer 1:

- Raw `.eml` files or trusted captured headers.
- SPF result and verification provenance.
- DKIM result and verification provenance.
- DMARC result and verification provenance.
- Parsed From address and display name.
- Reply-To address.
- Return-Path address.
- Message ID or another stable source record identifier.

Unavailable authentication values must be represented as unavailable, not inferred from message text or labels.

### 3. SMS identity evidence

Required for the SMS portion of Layer 1:

- Sender ID or stable pseudonymous sender identifier.
- Stable pseudonymous recipient/device identifier.
- Known/unknown sender status where the project has a valid reference point.
- Source provenance for these fields.

Email authentication fields do not apply to SMS and must not be substituted for SMS identity data.

### 4. Historical communication events

Required for Layer 3 and cross-channel analysis:

- Stable pseudonymous sender and recipient IDs for both channels.
- Event/message ID.
- Event timestamp and timezone.
- Channel (`email` or `sms`).
- Historical sender-recipient events, not just isolated messages.
- A source or event type where needed to distinguish message events from feedback events.

This single event-history contract supports sender profiles, recipient profiles, relationships, frequency, time-of-day behavior, channel behavior, and cross-channel sequencing. A graph database is unnecessary for the first implementation; tabular event and edge records are sufficient.

### 5. Validated feedback for adaptive intelligence

Required for the adaptive component to produce trustworthy project knowledge:

- User/admin feedback tied to a message ID.
- Feedback validation or adjudication status.
- Extracted threat-pattern provenance.
- Feedback timestamp and knowledge cutoff.

The adaptive component may then create embedding documents, store them in a vector store, retrieve similar validated patterns, build RAG context, and send that context to Gemini. Gemini remains contextual support, not the sole classifier, and the Hugging Face Transformer remains the primary NLP model.

## Data useful for research evaluation, but not required to start

These improve evidence quality and generalization studies but are not minimum prerequisites for the first implementation boundary:

- Human annotations for intent classes.
- Human annotations for urgency, coercion/threat, impersonation, and requested action.
- Additional trusted labels for ambiguous or borderline messages.
- Temporal holdout events for realistic future-performance evaluation.
- Sender- or campaign-grouped evaluation partitions.
- Independent authenticated email samples to test Layer 1 generalization.
- Independent SMS samples containing sender and recipient metadata to test Layer 3 generalization.
- Cross-channel event sequences from a separate approved evaluation period.
- External public datasets for robustness testing, only if their label definitions and provenance are compatible.

No additional public dataset is required merely to begin schema validation or a constrained Layer 2 experiment. Public data becomes useful when measuring external generalization or filling a specific approved annotation/metadata gap.

## Minimum implementation phases

### Phase 1: Existing data only

Implement data validation, label confirmation checks, text normalization, duplicate-group analysis, and a Transformer-based Layer 2 pipeline. Produce semantic embeddings and define nullable Layer 1/Layer 3 interfaces. Do not claim complete three-layer detection.

### Phase 2: Required metadata enrichment

Add authenticated email headers, SMS sender/recipient identifiers, stable pseudonymous identities, and timestamped historical events. Build identity features, sender/recipient profiles, relationship edges, frequency and temporal features, and cross-channel behavior.

### Phase 3: Adaptive feedback loop

Add validated feedback, threat-pattern extraction, embedding documents, vector-store retrieval, RAG context construction, and structured Gemini context. Keep feedback and knowledge cutoffs separate from evaluation data.

### Phase 4: Evaluation hardening

Use duplicate-aware, sender-aware, campaign-aware, and temporal evaluation where the available event history supports them. Add research-only annotations or external datasets only to answer a defined evaluation question.

## Layer-by-layer feasibility

| Layer | Current feasibility | Why |
|---|---|---|
| Layer 1: identity/authenticity | PARTIAL | Email sender/receiver strings exist, but authentication headers and SMS sender identity are absent |
| Layer 2: intent + NLP | FEASIBLE WITH LIMITATIONS | Text exists for both channels; primary labels and auxiliary intent annotations need confirmation or collection |
| Layer 3: behavioral intelligence | NOT COMPLETE | Email has limited sender/receiver/date candidates; SMS and cross-channel event history are absent |
| Adaptive component | ARCHITECTURE FEASIBLE, KNOWLEDGE INCOMPLETE | The pipeline can be designed, but reliable retrieval requires validated feedback and threat patterns |

## Final recommendation

Do not collect broad additional datasets yet. First confirm label semantics and acquire the minimum project-owned metadata: authenticated email headers, SMS sender/recipient/timestamp fields, stable pseudonymous IDs, and historical communication events. Add intent and auxiliary annotations only when the project requires those outputs to be trained or evaluated. This is the smallest defensible path to the proposed three-layer architecture.
