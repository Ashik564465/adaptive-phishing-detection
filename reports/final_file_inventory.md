# Final file inventory

This inventory lists project-relevant components only. Cache directories, Python bytecode, temporary files, and environment secrets are omitted.

## Production source

### `src/layer1_identity/`

Email identity and authenticity features and scoring, including authentication evidence, sender identity fields, mismatch signals, and identity-risk explanations.

### `src/layer2_nlp/`

Transformer-based phishing classification and related semantic/NLP scoring components. The Transformer is the primary phishing classifier.

### `src/layer3_behavior/`

Behavioral intelligence components for sender profiles, relationships, temporal anomalies, campaign similarity, and behavioral-risk scoring.

### `src/embeddings/`

Hugging Face embedding model integration, threat-memory document construction, and vector-store operations.

### `src/rag/`

Threat retrieval and context construction, plus optional Gemini provider and adapter integration. Gemini is auxiliary contextual reasoning only.

### `src/adaptive/`

Validated feedback handling, knowledge-update rules, adaptive-memory structures, persistence, and pattern extraction.

### `src/fusion/`

Risk-fusion weights, thresholds, normalized score calculation, classification, and risk explanations.

### `src/pipeline/`

Detection orchestration across the Transformer, identity, behavioral, RAG, Gemini adapter, and risk-fusion components.

### `src/api/`

FastAPI application with `/health`, `/detect`, and `/feedback` endpoints.

## Models

### `models/`

Contains the trained phishing-classifier artifacts and model configuration used by the Transformer pipeline, including the project classifier checkpoint and embedding configuration.

## Processed data and memory

### `data/processed/`

Contains processed email/SMS datasets and threat-memory artifacts, including:

- `email_processed.parquet`
- `sms_processed.parquet`
- `unified_messages.parquet`
- `threat_memory_train_only.pkl`
- `adaptive_threat_memory.pkl`

The frozen training memory and adaptive memory are persisted separately.

## Tests

### `tests/`

Unit and integration coverage for:

- Data preparation and context construction
- Layer 1 identity behavior
- Layer 2 NLP and Transformer behavior
- Layer 3 behavioral scoring
- Embeddings and vector stores
- RAG retrieval
- Gemini provider, adapter, and opt-in live behavior
- Risk fusion and explanations
- Detection pipeline
- Adaptive feedback and persistent memory

The ordinary suite does not require a live Gemini call.

## Scripts

### `scripts/`

Project utilities for:

- Dataset preparation
- Model training and evaluation
- Calibration and ablation evaluation
- Threat-memory and embedding construction
- Single-message and full detection runs
- Adaptive-learning experiments
- Layer 2 leakage auditing
- Saving experimental reports
