# Local Docker validation

## 1. Docker architecture

The `adaptive-phishing-detection` service runs FastAPI and Streamlit in one
CPU-only container:

```text
Browser -> Streamlit :8501 -> FastAPI :8000 -> existing detection pipeline
```

`docker/start.sh` starts FastAPI, waits for `/health`, starts Streamlit, and
keeps both processes supervised without changing backend detection logic.

## 2. Files created/modified

Created:

- `Dockerfile`
- `docker-compose.yml` was empty and is now the single service definition.
- `.dockerignore`
- `docker/start.sh`
- `reports/docker_local_validation.md`

Modified:

- `requirements.txt`: changed the CUDA-tagged Torch pin to `torch==2.14.0`
  for CPU-only container inference.
- `ui/README.md`: added Docker commands and runtime notes.

## 3. Runtime dependencies and paths

The Docker image uses `requirements.docker.txt`, a production-only runtime
manifest derived from the validated environment:

- Python base: `python:3.12-slim`.
- FastAPI: `0.141.1`.
- Uvicorn: `0.54.0`.
- Pydantic: `2.13.5`.
- NumPy: `2.5.3`.
- Pandas: `2.3.3`.
- Transformers: `4.57.6`.
- Tokenizers: `0.22.2`.
- Safetensors: `0.8.0`.
- Torch: CPU-only `2.14.0+cpu`.
- SymPy: `1.14.0` (required by Torch at runtime).
- Google GenAI: `2.24.0`.
- python-dotenv: `1.2.3`.
- httpx: `0.28.1`.
- Requests: `2.34.2`.
- Streamlit: `1.65.0`.

The working host environment was Python 3.13 with Torch
`2.14.0+cu126`, Transformers `4.57.6`, and NumPy `2.5.3`. The Docker image
does not use the host CUDA Torch build.

The image copies:

- `models/phishing_classifier/`: trained classifier and tokenizer artifacts.
- `data/processed/threat_memory_train_only.pkl`: frozen training memory.
- `src/` and `ui/`: application code.

The embedding model is loaded by the existing Hugging Face code. The local
Hugging Face cache contains `sentence-transformers/all-MiniLM-L6-v2` at
approximately 91 MB, but it is outside the project and was not copied into
the image. A first container startup therefore requires Hugging Face network
access to download it. No model behavior was changed.

The trained classifier directory is self-contained for inference. Only
`config.json`, `model.safetensors`, tokenizer files, and `vocab.txt` are
copied; checkpoints, CSV reports, and training metadata are excluded.

## 4. Ports and environment

- FastAPI listens on `0.0.0.0:8000`, mapped as `8000:8000`.
- Streamlit listens on `0.0.0.0:8501`, mapped as `8501:8501`.
- `API_BASE_URL=http://127.0.0.1:8000` is set inside the container.
- `GEMINI_API_KEY` is passed through from the host environment only.
- `.env` is excluded and is not copied into the image.

## 5. Memory handling

Frozen training memory is copied as a static image artifact. Adaptive memory
is mounted from `data/processed/adaptive_threat_memory.pkl` and remains
outside the image so feedback survives recreation and restart.

## 6. Docker Desktop/BuildKit diagnostics and validation

Diagnostics were run before the build:

- Docker Engine `29.8.1`, Docker Desktop, Linux `overlayfs`, 12 CPUs.
- Docker memory allocation reported by `docker info`: `7.593 GiB`.
- Host `C:` drive free space: `2.30 GB`; host `D:` drive free space:
  `280.33 GB`.
- Before cleanup, `docker system df` reported `6.669 GB` of build cache,
  including `2.713 GB` reclaimable/private cache.
- The `desktop-linux` builder was healthy: status `running`, BuildKit
  `v0.33.0`, and `overlayfs` snapshotter.

The only cleanup performed was the least destructive unused-cache operation:

```text
docker builder prune --force
```

It removed exactly `2.713 GB` of unused BuildKit cache. Images, containers,
and volumes were not pruned.

The requested single retry then succeeded:

```text
docker compose build --progress=plain
BUILD_DURATION_SECONDS=32.256
```

The final image was exported successfully with:

- Image ID:
  `sha256:a40b2cffe7feec900c96d209b70be76c88f25a0ee1646d9fb9996bb214fcc1c6`
- Exact image size: `2,756,309,630` bytes (`2,628.62 MiB` as reported by the
  inspection conversion).

## 7. Docker runtime validation

`docker compose up -d` succeeded in `1.130` seconds. The container exposed
FastAPI on port `8000` and Streamlit on port `8501`.

- `/health`: HTTP `200`; adaptive memory count before feedback: `5`.
- Streamlit `/`: HTTP `200`.
- `/detect`: succeeded in `0.626` seconds; returned `PHISHING`,
  `gemini_used=false`, and `retrieved_threat_count=1`.
- `/feedback`: succeeded in `0.035` seconds with `accepted=true`,
  `knowledge_updated=true`; adaptive memory count changed from `5` to `6`.
- After `docker compose restart`, `/health` returned count `6`, verifying
  adaptive-memory persistence across restart. Restart-to-health readiness was
  `13.955` seconds.
- The first detection after restart completed in `0.371` seconds.
- Inside the container, Torch reported `2.14.0+cpu` and
  `torch.cuda.is_available()` returned `False`.

The existing host browser validation remains documented in
`reports/local_ui_validation.md`; it is not substituted for Docker
validation.

## 8. Security checks

- No API key is present in the Dockerfile, source, compose file, or report.
- `.env` is excluded by `.dockerignore`.
- The compose file references `${GEMINI_API_KEY:-}` only as runtime
  environment interpolation.
- No AWS resources or deployment configuration are created by this phase.

## 9. Known limitations

- Local Docker timings are not AWS Lambda cold-start measurements.
- The embedding model may require network access during first startup unless
  it is already available in the image/cache.
- Adaptive memory uses a single local bind-mounted pickle and is not designed
  for concurrent multi-container writes.
