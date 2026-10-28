# Lambda runtime artifact audit

## Scope and constraints

This is a read-only audit of the current Lambda execution path. No files were
deleted, no Dockerfile was changed, no Docker build was run, and no AWS
resource or configuration was created.

The execution path is:

```text
src/lambda_handler.py
  -> src.api.main:app
     -> FastAPI startup_event()
        -> HuggingFaceEmbedder
        -> load_threat_memory()
        -> PersistentAdaptiveMemory
        -> RealPhishingDetector
```

The required HTTP routes remain `/health`, `/detect`, and `/feedback`.

## 1. Classifier runtime loading

`src/config/settings.py` defines:

```text
PHISHING_MODEL_PATH = PROJECT_ROOT / "models" / "phishing_classifier"
```

`src/pipeline/real_detector.py` passes that directory to:

```text
AutoTokenizer.from_pretrained(self.model_path)
AutoModelForSequenceClassification.from_pretrained(self.model_path)
```

The classifier is therefore loaded from the root
`models/phishing_classifier/` directory, not from either checkpoint directory.
The model performs DistilBERT sequence classification using the local
tokenizer and `model.safetensors`.

### Root classifier directory inventory

| File | Size | Classification | Runtime evidence |
|---|---:|---|---|
| `models/phishing_classifier/model.safetensors` | 255.43 MiB | `REQUIRED_AT_RUNTIME` | Loaded by `AutoModelForSequenceClassification.from_pretrained()` |
| `models/phishing_classifier/config.json` | 719 B | `REQUIRED_AT_RUNTIME` | Standard model configuration consumed by `from_pretrained()` |
| `models/phishing_classifier/tokenizer.json` | 0.68 MiB | `REQUIRED_AT_RUNTIME` | Fast tokenizer asset consumed by `AutoTokenizer.from_pretrained()` |
| `models/phishing_classifier/tokenizer_config.json` | 1.25 KiB | `REQUIRED_AT_RUNTIME` | Tokenizer configuration consumed by `AutoTokenizer.from_pretrained()` |
| `models/phishing_classifier/special_tokens_map.json` | 132 B | `REQUIRED_AT_RUNTIME` | Special-token configuration consumed by tokenizer loading |
| `models/phishing_classifier/vocab.txt` | 0.22 MiB | `REQUIRED_AT_RUNTIME` | WordPiece vocabulary asset retained for the local tokenizer |
| `models/phishing_classifier/model_config.json` | 308 B | `OPTIONAL_METADATA` | No code reference; the active loader uses `config.json` |
| `models/phishing_classifier/training_args.bin` | 5.85 KiB | `TRAINING_ONLY` | Training configuration; not read by inference code |
| `models/phishing_classifier/evaluation_metrics.json` | 2.78 KiB | `OPTIONAL_METADATA` | Evaluation report; no runtime reference |
| `models/phishing_classifier/test_predictions.csv` | 0.66 MiB | `OPTIONAL_METADATA` | Evaluation artifact; no runtime reference |
| `models/phishing_classifier/error_analysis.csv` | 0.02 MiB | `OPTIONAL_METADATA` | Evaluation artifact; no runtime reference |

The six root files explicitly copied by `Dockerfile.lambda` are the complete
local classifier/tokenizer set currently used by the inference loader.

### Checkpoint inventory

Both checkpoint directories contain duplicate model/tokenizer artifacts plus
training state. They are not referenced because the configured model path is
the root directory.

For both `checkpoint-45` and `checkpoint-4915`:

| File pattern | Classification | Reason |
|---|---|---|
| `config.json` | `DUPLICATE_OR_UNUSED` | Duplicate of root classifier configuration; checkpoint directories are not loaded |
| `model.safetensors` | `DUPLICATE_OR_UNUSED` | Duplicate model weights; root model is loaded |
| `special_tokens_map.json` | `DUPLICATE_OR_UNUSED` | Duplicate tokenizer asset |
| `tokenizer.json` | `DUPLICATE_OR_UNUSED` | Duplicate tokenizer asset |
| `tokenizer_config.json` | `DUPLICATE_OR_UNUSED` | Duplicate tokenizer configuration |
| `vocab.txt` | `DUPLICATE_OR_UNUSED` | Duplicate vocabulary |
| `optimizer.pt` | `TRAINING_ONLY` | Optimizer state; not used during inference |
| `scheduler.pt` | `TRAINING_ONLY` | Learning-rate scheduler state |
| `rng_state.pth` | `TRAINING_ONLY` | Training random-state snapshot |
| `scaler.pt` (`checkpoint-4915` only) | `TRAINING_ONLY` | Training mixed-precision scaler state |
| `trainer_state.json` | `TRAINING_ONLY` | Trainer progress/state |
| `training_args.bin` | `TRAINING_ONLY` | Training arguments |

The checkpoint directories account for most of the approximately 1,791.53 MiB
recursive classifier-directory audit size. They are not copied by the Lambda
Dockerfile.

## 2. Tokenizer requirements

The classifier tokenizer is loaded from the same root directory by
`AutoTokenizer.from_pretrained()` in `src/pipeline/real_detector.py`.

The current local inference payload includes:

- `tokenizer.json`
- `tokenizer_config.json`
- `special_tokens_map.json`
- `vocab.txt`
- `config.json`, which accompanies the model directory

These are classified as required for the current local Hugging Face loading
behavior. No tokenizer checkpoint directory is used.

## 3. Embedding model requirements

`src/api/main.py` constructs:

```text
EmbeddingConfig(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    max_length=256,
)
```

`src/embeddings/embedding_model.py` then calls:

```text
AutoTokenizer.from_pretrained(self.config.model_name)
AutoModel.from_pretrained(self.config.model_name)
```

This is a model-name lookup, not a local path lookup. The Dockerfile sets:

```text
HF_HOME=/tmp/huggingface
```

Therefore the current implementation intends to download/cache the embedding
model at runtime under `/tmp/huggingface`. The Lambda image does not currently
contain `sentence-transformers/all-MiniLM-L6-v2`, and no local embedding model
files are copied.

`models/embedding_config/` does not exist in the workspace. Although
`EMBEDDING_CONFIG_PATH` is defined in `src/config/settings.py`, the audited
execution path does not read it.

The embedding model is consequently:

- Not a current image payload artifact.
- Required for successful runtime initialization.
- Expected to be obtained from Hugging Face at runtime under the current
  implementation.
- Not changed or redesigned by this audit.

## 4. RAG and frozen threat-memory requirements

`src/api/main.py` defines:

```text
THREAT_MEMORY_PATH =
    PROJECT_ROOT / "data" / "processed" / "threat_memory_train_only.pkl"
```

`load_threat_memory()` opens that file with `pickle.load()` and requires the
loaded object, or one of its recognized dictionary values, to provide a
`search()` method. The result is combined with adaptive memory by
`CombinedThreatMemoryStore`, then queried through `ThreatRetriever`.

### Processed-data inventory

| File | Size | Classification | Runtime evidence |
|---|---:|---|---|
| `data/processed/threat_memory_train_only.pkl` | 4.99 MiB | `REQUIRED_AT_RUNTIME` | Directly opened by `load_threat_memory()` |
| `data/processed/adaptive_threat_memory.pkl` | 0.01 MiB | `REQUIRED_AT_RUNTIME` for current behavior | Directly opened by `PersistentAdaptiveMemory` if present; created on feedback |
| `data/processed/threat_memory.pkl` | 4.98 MiB | `DUPLICATE_OR_UNUSED` | No reference in the audited Lambda path |
| `data/processed/email_processed.parquet` | 37.82 MiB | `TRAINING_ONLY` | No runtime reference |
| `data/processed/sms_processed.parquet` | 0.58 MiB | `TRAINING_ONLY` | No runtime reference |
| `data/processed/unified_messages.parquet` | 38.34 MiB | `TRAINING_ONLY` | No runtime reference |

The frozen pickle may contain serialized project objects, so the copied `src`
package remains necessary for deserialization and method behavior. No Parquet
dataset is loaded by Lambda startup or request handling.

## 5. Adaptive-memory requirements

`src/api/main.py` constructs `PersistentAdaptiveMemory` with:

```text
data/processed/adaptive_threat_memory.pkl
```

`src/adaptive/persistent_memory.py`:

- Reads `documents` and `embeddings` from the pickle at startup.
- Reconstructs its in-memory vector store.
- Uses the embedding model to embed validated feedback.
- Writes the updated pickle on accepted feedback.

The current artifact is therefore required to preserve the existing local
adaptive-memory count and behavior. The implementation is still local-file
based; this audit does not claim that Lambda local storage is permanent.

## 6. Current Lambda image payload

`Dockerfile.lambda` currently copies:

```text
requirements.lambda.txt
src/
models/phishing_classifier/config.json
models/phishing_classifier/model.safetensors
models/phishing_classifier/special_tokens_map.json
models/phishing_classifier/tokenizer.json
models/phishing_classifier/tokenizer_config.json
models/phishing_classifier/vocab.txt
data/processed/threat_memory_train_only.pkl
data/processed/adaptive_threat_memory.pkl
```

Approximate non-package payload sizes:

| Payload group | Size |
|---|---:|
| Explicitly copied classifier and tokenizer artifacts | 256.34 MiB |
| `src/` source tree | 0.26 MiB |
| Frozen and adaptive memory files | 5.00 MiB |
| Total listed application/artifact payload | 261.33 MiB |

The total image will be larger because the Lambda base image and Python
packages, especially CPU Torch, are installed separately.

The Dockerfile does not copy:

- `models/phishing_classifier/checkpoints/`
- Root classifier evaluation/metadata files
- Any processed Parquet dataset
- `data/processed/threat_memory.pkl`
- `models/embedding_config/` (absent and not used)
- Streamlit source or dependency
- Uvicorn dependency
- A local embedding-model cache

## 7. Minimal required Lambda payload

For the current execution path, the minimal payload is:

```text
src/                                      # imported application and pickle classes
models/phishing_classifier/config.json
models/phishing_classifier/model.safetensors
models/phishing_classifier/special_tokens_map.json
models/phishing_classifier/tokenizer.json
models/phishing_classifier/tokenizer_config.json
models/phishing_classifier/vocab.txt
data/processed/threat_memory_train_only.pkl
data/processed/adaptive_threat_memory.pkl
```

Plus the Python packages in `requirements.lambda.txt` and the CPU Torch wheel.

The current `Dockerfile.lambda` already implements this minimal application
artifact payload. No further exclusion is recommended without a focused
runtime test of the Hugging Face loader against the exact resulting directory.

## 8. Files safe to exclude from the Lambda image

The following files/directories can be excluded without changing current
inference behavior because the audited Lambda path does not load them:

- `models/phishing_classifier/checkpoints/`
- `models/phishing_classifier/model_config.json`
- `models/phishing_classifier/training_args.bin`
- `models/phishing_classifier/evaluation_metrics.json`
- `models/phishing_classifier/test_predictions.csv`
- `models/phishing_classifier/error_analysis.csv`
- `data/processed/threat_memory.pkl`
- `data/processed/email_processed.parquet`
- `data/processed/sms_processed.parquet`
- `data/processed/unified_messages.parquet`
- `models/embedding_config/` if created without changing code, because the
  current code does not read it
- `ui/` and Streamlit-only assets, provided they are not copied by the Lambda
  Dockerfile

These exclusions do not change inference behavior because they are not
referenced by the Lambda startup, classifier, RAG retrieval, feedback, or
adaptive-memory code paths. The existing Dockerfile already excludes them.
No files were removed by this audit.

## 9. Runtime references by subsystem

| Subsystem | Code reference | Required files |
|---|---|---|
| Lambda adapter | `src/lambda_handler.py` | `src/lambda_handler.py`, `src/api/` and imported `src/` modules |
| FastAPI startup | `src/api/main.py:startup_event` | Imported `src/` modules, frozen memory, adaptive memory, embedding model at runtime |
| Classifier | `src/pipeline/real_detector.py` | Root classifier config, weights, tokenizer files |
| Embeddings | `src/embeddings/embedding_model.py` | Hugging Face model downloaded at runtime to `HF_HOME` |
| Frozen RAG memory | `src/api/main.py:load_threat_memory` | `threat_memory_train_only.pkl` |
| Adaptive memory | `src/adaptive/persistent_memory.py` | `adaptive_threat_memory.pkl` and writable local path |
| Risk fusion | `src/fusion/risk_fusion.py` | Python source only; no separate model artifact found |
| Gemini adapter | `src/rag/gemini_adapter.py` and provider modules | Python source and optional runtime credentials; no model artifact copied |

## 10. Conclusion

The existing Lambda Dockerfile already excludes the large training checkpoints,
optimizer/scheduler state, trainer state, logs/evaluation artifacts, duplicate
weights, datasets, and unused memory copy. Its explicit copied artifact set is
the current minimal payload required by the existing execution path.

The main unresolved runtime characteristic is the embedding model: it is not
inside the image and is currently intended to download from Hugging Face into
`/tmp/huggingface`. This behavior was audited only and not redesigned.
