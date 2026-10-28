# Final system validation report

## 1. System validation overview

This report summarizes the verified state of the adaptive phishing detection system for email and SMS messages.

The system combines:

- Transformer-based phishing classification
- Email identity and authentication evidence
- Behavioral intelligence
- Historical threat-memory retrieval
- Optional Gemini contextual reasoning
- Risk fusion into `SAFE`, `SUSPICIOUS`, or `PHISHING`
- Validated adaptive threat-memory updates

The validation described here is experimental and dataset- and environment-specific. It is not a claim of future real-world attack accuracy.

## 2. Transformer classifier validation

Held-out Transformer evaluation:

| Metric | Result |
|---|---:|
| Accuracy | 0.992664 |
| Precision | 0.993859 |
| Recall | 0.992054 |
| F1 | 0.992956 |
| ROC-AUC | 0.999504 |

These are held-out dataset results for the trained Transformer classifier.

## 3. Layer 1 identity validation

Layer 1 provides interpretable email identity and authenticity evidence, including available SPF, DKIM, DMARC, From/Reply-To, From/Return-Path, and display-name consistency signals.

The scorer is deterministic and evidence-based rather than a separately trained machine-learning model. Missing authentication metadata is represented as unavailable evidence rather than fabricated authentication results.

The current datasets do not contain real SPF/DKIM/DMARC headers, so production-style authentication validation is limited to the available synthetic or derived feature inputs.

## 4. Layer 3 behavioral validation

Layer 3 evaluates available sender, recipient, relationship, temporal, historical phishing-rate, and similarity signals.

The behavioral scorer produces a normalized risk value and explanatory reasons. Its behavior is deterministic and bounded to the available metadata.

The SMS dataset currently lacks sender, receiver, and timestamp metadata. Consequently, behavioral analysis for SMS is limited where those fields are unavailable.

## 5. RAG/threat-memory validation

The retrieval layer uses Hugging Face embeddings and an in-memory vector-search interface to retrieve historical threat evidence.

The project keeps:

- Frozen training-only threat memory as baseline historical knowledge.
- Persistent adaptive threat memory as validated post-deployment knowledge.

These stores remain separate. Retrieved evidence is summarized in `ThreatContext` and supplied as auxiliary context; it does not replace the Transformer classifier.

## 6. Gemini integration validation

Gemini is configured as optional contextual reasoning using the existing `gemini-3.6-flash` model.

Verified behavior:

- The API key is environment-based.
- Normal Gemini adapter/provider tests pass.
- Successful provider results are represented by `GeminiReasoningResult` with `gemini_used=True`.
- A successful real Gemini response has not been verified in the current environment.

The formal classifier and ablation evaluations did not use Gemini as a bulk test component.

## 7. Gemini failure-resilience validation

The adapter has a deterministic local fallback for provider/API/network/timeout/parsing failures.

Failure cases covered by tests include:

- No provider
- HTTP 429-style failure
- HTTP 503-style failure
- Timeout
- Network/connection failure
- Provider/parsing `ValueError`
- Empty threat context

Invalid provider return types continue to raise `TypeError`, preserving visibility of programming-contract violations.

The latest live environment did not provide a real Gemini response. The live test correctly skipped when the adapter returned fallback with `gemini_used=false`. Fallback is not reported as successful Gemini reasoning.

## 8. Risk-fusion validation

Risk fusion combines:

- Transformer phishing probability
- Identity risk
- Behavioral risk
- Historical threat-memory risk

The configured production pipeline uses explicit weights and thresholds for the three output classes:

- `SAFE`
- `SUSPICIOUS`
- `PHISHING`

Calibrated Transformer + RAG + behavior evaluation:

| Metric | Result |
|---|---:|
| Accuracy | 0.992901 |
| Precision | 0.994087 |
| Recall | 0.992281 |
| F1 | 0.993183 |
| ROC-AUC | 0.999362 |

The calibrated evaluation used a binary decision threshold of `0.30`. These F1 values do not represent the production three-class `SAFE`/`SUSPICIOUS`/`PHISHING` thresholds.

## 9. Adaptive-learning validation

Controlled adaptive-memory experiment:

| State | Final risk | Classification | Historical risk |
|---|---:|---|---:|
| Before learning | approximately 66.75 | `SUSPICIOUS` | approximately 0.5591 |
| After validated phishing memory | approximately 70.25 | `PHISHING` | approximately 0.6757 |

The Transformer probability remained approximately unchanged.

This demonstrates contextual adaptation through persistent threat memory. It does not prove improved classifier accuracy, future generalization, or improved detection on unseen campaigns.

## 10. Persistence validation

The controlled API memory-count experiment produced:

| Stage | Adaptive-memory documents |
|---|---:|
| Before feedback | 3 |
| After one validated phishing feedback event | 4 |
| After API restart | 4 |

This verifies persistence of validated adaptive knowledge across restart without retraining the Transformer.

## 11. API end-to-end validation

The API was started with the FastAPI application and tested with a synthetic email phishing message while Gemini was unavailable.

Result:

```text
HTTP 200
```

Response values:

| Field | Value |
|---|---:|
| `phishing_probability` | 0.9997517466545105 |
| `identity_risk` | 0.0 |
| `behavioral_risk` | 0.0 |
| `historical_risk` | 0.9477321258667377 |
| `risk_score` | 78.42 |
| `classification` | `PHISHING` |
| `retrieved_threat_count` | 1 |
| `gemini_used` | `false` |

The response also contained the expected `message_id`, `channel`, and explanation fields.

This confirms that `/detect` continues successfully when Gemini is unavailable and that fallback state is exposed explicitly.

## 12. Security validation

Verified security properties:

- `GEMINI_API_KEY` is loaded from environment configuration.
- `.env` is ignored by Git.
- No API key appears in source files.
- No API key appears in reports.
- No API key is printed by the validation tests or reports.
- No URL-based detection features were introduced.
- URLs remain excluded from detection features and are not used as reputation or classification signals.
- Frozen training threat memory remains separate from persistent adaptive memory.

## 13. Test-suite summary

Normal suite:

```text
100 passed, 1 skipped
```

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Opt-in Gemini suite:

```text
13 passed, 1 skipped, 87 deselected
```

The skipped live test indicates Gemini was unavailable. It does not indicate successful Gemini reasoning.

## 14. Known limitations

- Current datasets do not contain real SPF/DKIM/DMARC headers.
- The current SMS dataset lacks sender/receiver/timestamp metadata.
- Live Gemini model response is currently unavailable in the test environment.
- Behavioral analysis is therefore limited by available metadata.
- Final classifier results are dataset-based and should not be generalized to unseen future campaigns.
- URL features are intentionally excluded.
- The formal ablation/evaluation did not use Gemini as a bulk test component.
- The calibrated combined evaluation used a binary threshold of `0.30`, not the production three-class thresholds.
- Adaptive-memory behavior demonstrates contextual change, not improved classifier accuracy.

## 15. Final conclusion

The verified system provides a functioning layered phishing-detection pipeline with Transformer-first classification, deterministic identity and behavioral evidence, separate frozen and adaptive threat memory, optional Gemini reasoning, explicit Gemini fallback state, risk fusion, and persistent validated feedback.

The normal automated suite is green at `100 passed, 1 skipped`. The API remains operational when Gemini is unavailable, returning HTTP 200 with `gemini_used=false`. Adaptive memory updates persist across restart. A real successful Gemini response remains unverified in the current environment and is not claimed here.
