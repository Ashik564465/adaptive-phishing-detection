# Layer 2 NLP Report

## 1. Objective
Layer 2 performs semantic phishing detection with one Hugging Face Transformer for email and SMS. It does not implement Layer 1, Layer 3, RAG, Gemini, adaptive feedback, risk fusion, or a web application.

**Layer 2 performs semantic phishing detection using a Hugging Face Transformer. It does not use URL reputation, URL classification, or URL-based features.**

## 2. Dataset summary
The unified processed dataset contains 56,169 rows: 48,289 `EMAIL` and 7,880 `SMS`. Exact normalized duplicates were removed before this stage: 6 email rows and 2,550 SMS rows. The measured run used a stratified 512-row CPU smoke subset because CUDA was unavailable; results are not full-dataset benchmarks.

## 3. Confirmed label mapping
`legitimate` is binary label `0`; `phishing` is binary label `1`. Email source `0` maps to legitimate and source `1` to phishing. SMS `ham` maps to legitimate and `spam` to phishing. `original_label` is traceability only and is not included in input text.

## 4. Preprocessing
Input is read from `data/processed/unified_messages.parquet`. Existing normalization handles Unicode, whitespace, and email HTML. Missing subject/body values remain empty segments. Sender and recipient values are never used as text features.

## 5. Unified text construction
Email: `[CHANNEL] EMAIL [SUBJECT] <subject> [BODY] <body>`.

SMS: `[CHANNEL] SMS [BODY] <body>`.

The source `urls` field is excluded. URLs are not extracted, counted, embedded, classified, or scored.

## 6. Transformer model
The primary model is configurable compact `distilbert-base-uncased`, loaded with Hugging Face Transformers and PyTorch. Its model, tokenizer, and configuration are saved under `models/phishing_classifier/`. CUDA is detected automatically; this run used CPU.

## 7. Hyperparameters

| Parameter | Value |
|---|---:|
| Model | `distilbert-base-uncased` |
| Maximum sequence length | 256 |
| Train/eval batch size | 8 / 16 |
| Learning rate | 2e-5 |
| Epochs | 1 |
| Seed | 42 |
| Smoke limit | 512 rows |

Configuration is in `src/config/settings.py` and `models/phishing_classifier/model_config.json`.

## 8. Dataset splitting
A reproducible 70/15/15 split uses seed 42. Normalized message-content duplicate groups are created before splitting, preventing duplicate copies from crossing splits. The smoke split was train 358, validation 77, test 77. Temporal evaluation was not implemented, though email timestamps remain available for later work.

## 9. Duplicate leakage prevention
Duplicate message groups are assigned to one split. Near-duplicate analysis is not used to delete meaningful text. No sender, timestamp, or label is included in the input grouping text.

## 10. Class distribution

| Channel | Legitimate | Phishing | Phishing % |
|---|---:|---:|---:|
| EMAIL | 21,402 | 26,887 | 55.68% |
| SMS | 5,605 | 2,275 | 28.87% |
| Overall | 27,007 | 29,162 | 51.91% |

No artificial rebalancing or class weighting was applied. The smoke subset was sampled evenly by label for development.

## 11. Training procedure
The tokenizer and pretrained encoder were loaded, tokenized with truncation and fixed padding, trained for one epoch, evaluated each epoch, checkpointed, and saved using the best validation F1. The run used 358 training rows and completed successfully on CPU.

## 12. Overall metrics
Measured on 77 smoke-test rows:

| Accuracy | Precision | Recall | F1 | ROC-AUC |
|---:|---:|---:|---:|---:|
| 0.7922 | 0.7115 | 0.9737 | 0.8222 | 0.9487 |

Confusion matrix, `[legitimate, phishing]`: `[[24, 15], [1, 37]]`.

## 13. Email metrics
Measured on 66 smoke-test email rows: precision `0.8293`, recall `0.9714`, F1 `0.8947`, ROC-AUC `0.9650`. Confusion matrix: `[[24, 7], [1, 34]]`.

## 14. SMS metrics
Measured on 11 smoke-test SMS rows: precision `0.2727`, recall `1.0000`, F1 `0.4286`, ROC-AUC `0.7083`. Confusion matrix: `[[0, 8], [0, 3]]`. This small sample is not a generalizable SMS benchmark.

## 15. Error analysis
`models/phishing_classifier/error_analysis.csv` contains test errors with `message_id`, `channel`, `actual_label`, `predicted_label`, and `phishing_probability`. It contains no email addresses and no raw message text. False positives and false negatives are filterable by the two label columns; no human difficulty annotation is claimed.

## 16. Limitations
Results are from a 512-row smoke subset, one epoch, and CPU-only training. SMS support is only 11 test rows. No temporal evaluation, hyperparameter search, or comparison baseline was run. Layer 2 output is an NLP signal and not final system risk.

## 17. Intent-label limitation
The datasets have no verified human intent labels. `src/layer2_nlp/intent_classifier.py` defines the requested intent categories and an explicit unannotated state; it does not guess labels or treat machine-generated suggestions as ground truth. `semantic_features.py` exposes nullable structured evidence fields and does not use arbitrary keyword-count scoring.

## 18. Model artifacts
Generated under `models/phishing_classifier/`: `model_config.json`, `config.json`, `model.safetensors`, tokenizer files, `evaluation_metrics.json`, `error_analysis.csv`, and checkpoints. `models/intent_classifier/` remains an annotation architecture location only. Inference returns phishing/legitimate probabilities, binary prediction, and `nlp_risk = phishing_probability * 100`; this is not final system risk.

## 19. Confirmation that URLs were not used
No URL extraction, reputation, blacklist lookup, URL classification, domain feature, WHOIS lookup, URL embedding, or URL-based risk score was implemented. No Layer 1, Layer 3, RAG, Gemini, adaptive feedback, risk fusion, or web UI work was performed.
