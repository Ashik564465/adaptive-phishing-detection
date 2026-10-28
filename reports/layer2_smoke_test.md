# Layer 2 Smoke Test

The 512-row CPU run validated the end-to-end Transformer training, checkpointing, evaluation, inference schema, and error-artifact pipeline. It is not the final Layer 2 experiment and must not be compared as a full-data benchmark.

- Model: `distilbert-base-uncased`
- Device: CPU
- Smoke input: 512 stratified rows
- Train/validation/test: 358 / 77 / 77
- Overall test accuracy: 0.7922
- Overall precision: 0.7115
- Overall recall: 0.9737
- Overall F1: 0.8222
- Overall ROC-AUC: 0.9487

Smoke artifacts are preserved under `models/phishing_classifier_smoke/`. The complete experiment uses the full processed dataset and GPU acceleration; its results are recorded separately in `reports/layer2_nlp_report.md` and `models/phishing_classifier/`.
