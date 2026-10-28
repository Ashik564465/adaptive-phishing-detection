from pathlib import Path

OUTPUT_DIR = Path("models/adaptive_evaluation")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

report = """# Adaptive Risk Pipeline Evaluation

## Objective

Evaluate whether validated phishing feedback can influence the
end-to-end phishing risk score through the adaptive threat-memory
layer without changing the primary Transformer classifier.

## Experimental Design

A semantically related future phishing email was evaluated twice.

1. The message was evaluated using the existing training-only
   threat memory.
2. A separately validated phishing example was added to adaptive
   threat memory.
3. The same future message was evaluated again.
4. Transformer probability, historical risk, and final fused risk
   were compared.

The Transformer model was not retrained during the experiment.

## Results

| Metric | Before Learning | After Learning | Change |
|---|---:|---:|---:|
| Transformer phishing probability | 0.9995 | 0.9995 | 0.0000 |
| Identity risk | 0.0000 | 0.0000 | 0.0000 |
| Behavioral risk | 0.0000 | 0.0000 | 0.0000 |
| Historical risk | 0.5591 | 0.6757 | +0.1166 |
| Final risk score | 66.75 | 70.25 | +3.50 |
| Classification | SUSPICIOUS | PHISHING | Changed |

## Main Observation

The primary Transformer probability remained unchanged at 0.9995.

After validated phishing knowledge was added to the adaptive
threat memory, historical risk increased from 0.5591 to 0.6757.

The resulting fused risk score increased from 66.75 to 70.25.

Under the predefined production thresholds:

- SAFE: below 40
- SUSPICIOUS: 40 to below 70
- PHISHING: 70 and above

the same future message changed from SUSPICIOUS to PHISHING.

## Interpretation

The experiment demonstrates that validated threat knowledge can
affect the end-to-end risk assessment through the retrieval and
historical-evidence component without retraining the primary
Transformer.

The adaptive component therefore acts as a knowledge-update layer,
while the Transformer remains the primary semantic phishing
classifier.

## Limitations

This is a controlled proof-of-concept experiment rather than a
large-scale accuracy evaluation.

The future message was manually constructed, the initial threat
memory already contained related phishing examples, and identity
and behavioral metadata were unavailable in this experiment.

Therefore, the observed +3.50 risk-score change should not be
reported as a general accuracy improvement.

The result demonstrates adaptive risk behavior, not statistically
validated improvement across a future test population.
"""

path = OUTPUT_DIR / "adaptive_risk_pipeline_report.md"
path.write_text(report, encoding="utf-8")

print("Saved:")
print(path)