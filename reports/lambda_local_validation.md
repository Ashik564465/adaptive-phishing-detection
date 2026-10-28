# Local Lambda compatibility validation

## Status

Local Lambda-container validation completed successfully. No AWS resources,
credentials, registries, Lambda functions, API Gateway, S3 buckets, or IAM
configuration were created.

## 1. Lambda architecture

The intended AWS shape is:

```text
S3 static frontend -> API Gateway -> Lambda container
                                  -> existing FastAPI detection backend
```

The Lambda container contains the existing FastAPI backend, Transformer,
embedding/RAG, risk fusion, adaptive logic, and Gemini adapter. Streamlit is
not included in the Lambda dependency manifest or started by the Lambda image.
The existing local Docker image remains responsible for FastAPI plus Streamlit.

## 2. Files changed

- `Dockerfile.lambda`: separate AWS Lambda Python 3.12 container image.
- `requirements.lambda.txt`: Lambda backend dependencies.
- `src/lambda_handler.py`: Mangum adapter exposing the existing FastAPI app.
- `reports/lambda_local_validation.md`: this validation record.

The existing `Dockerfile`, `docker/start.sh`, and `docker-compose.yml` were
not changed.

## 3. Dependencies added

- `mangum==0.19.0`

The Lambda manifest intentionally omits `streamlit` and `uvicorn`. Existing
runtime pins, including CPU-only Torch installation in the Lambda Dockerfile,
are retained for backend compatibility.

## 4. Local validation method

The AWS Lambda Python base image's Runtime Interface Emulator was used through
the image's default Lambda entrypoint and
`src.lambda_handler.handler`. API Gateway HTTP API v2-style events were sent to
the local RIE endpoint:

```text
POST http://localhost:9000/2015-03-31/functions/function/invocations
```

## 5. Import-level validation completed

The project environment successfully imported both the existing FastAPI app
and the new handler:

```text
FASTAPI_ROUTES=/detect,/docs,/docs/oauth2-redirect,/feedback,/health,/openapi.json,/redoc
HANDLER_TYPE=Mangum
IMPORT_EXIT_CODE=0
IMPORT_DURATION_SECONDS=24.919
```

This confirms that the handler wraps the existing application and that no
second detection pipeline was introduced. The import was run in the existing
host environment, where Torch reported `2.14.0+cu126` and CUDA was available;
this is not a Lambda-container result.

## 6. Lambda-container build

The required build command was run exactly once after Docker Desktop recovered:

```text
docker build --progress=plain -f Dockerfile.lambda -t adaptive-phishing-lambda:validated .
```

The build exported successfully:

```text
BUILD_EXIT_CODE=0
BUILD_DURATION_SECONDS=347.661
```

Image metadata:

```text
IMAGE_ID=sha256:e0625db647663d7e0d2c347a51ba856209231b60daa1c3a951e35257eece4374
IMAGE_SIZE_BYTES=2947634262
IMAGE_SIZE_MIB=2811.08
ENTRYPOINT=["/lambda-entrypoint.sh"]
CMD=["src.lambda_handler.handler"]
```

The build log confirmed successful installation of `mangum==0.19.0` and
`torch==2.14.0+cpu`, followed by successful layer export, manifest export,
image naming, and unpacking.

## 6a. Docker/BuildKit state

```text
Docker context: desktop-linux
Docker engine: reachable
Docker CPUs: 12
Docker memory: 7.593 GiB
Build cache: approximately 4.984 GB
```

Both `default` and `desktop-linux` BuildKit builders were reported as running
before the build. No images, containers, or volumes were pruned.

## 7. Lambda Runtime Interface Emulator validation

The image contains the Runtime Interface Emulator at:

```text
/usr/local/bin/aws-lambda-rie
```

Torch inside the Lambda image reported:

```text
TORCH_VERSION=2.14.0+cpu
CUDA_AVAILABLE=False
```

The first successful health invocation returned the Mangum proxy response in
1.371 seconds. The response had HTTP status 200 and the expected JSON body:

```json
{
  "statusCode": 200,
  "body": "{\"status\":\"ok\",\"service\":\"adaptive-phishing-detection\",\"adaptive_memory_documents\":6}",
  "headers": {
    "content-length": "85",
    "content-type": "application/json"
  },
  "isBase64Encoded": false
}
```

The API Gateway v2-style endpoint checks used a JSON request body and
`content-type: application/json`.

### Detection

The established phishing-style test message returned:

```text
DETECT_EXIT_CODE=0
DETECT_LATENCY_SECONDS=1.540
statusCode=200
message_id=lambda-validation-20261011113135
channel=EMAIL
phishing_probability=0.999733030796051
risk_score=78.79
classification=PHISHING
retrieved_threat_count=1
gemini_used=false
```

The proxy response included `content-type: application/json` and the expected
detection response fields.

### Feedback and health

Confirmed-phishing feedback returned:

```text
FEEDBACK_EXIT_CODE=0
FEEDBACK_LATENCY_SECONDS=1.431
statusCode=200
accepted=true
knowledge_updated=true
adaptive_memory_documents=7
```

The subsequent health response returned status 200 and
`adaptive_memory_documents=7`.

Gemini was unavailable because `GEMINI_API_KEY` was not configured. The
application logged `Gemini provider unavailable` and continued with
`gemini_used=false`, confirming the safe fallback path in the local Lambda
container.

## 8. Measurements

These are **LOCAL CONTAINER** measurements and are not AWS Lambda
cold-start or production performance claims:

- Image size: `2,947,634,262` bytes (`2,811.08 MiB`).
- Build duration: `347.661` seconds.
- First successful health invocation: `1.371` seconds.
- Detection invocation: `1.540` seconds.
- Feedback invocation: `1.431` seconds.
- After-restart health invocation: `7.270` seconds externally.
- Runtime log INIT report after restart: `5485.004 ms`.

## 8a. Host-only regression checks

The following checks ran outside a Lambda container using the project virtual
environment:

```text
HANDLER_TYPE=Mangum
FASTAPI_ROUTES=/detect,/docs,/docs/oauth2-redirect,/feedback,/health,/openapi.json,/redoc
TORCH_VERSION=2.14.0+cu126
CUDA_AVAILABLE=True
IMPORT_DURATION_SECONDS=57.395
```

Focused tests passed:

```text
tests/test_ui_api_client.py
tests/test_detection_pipeline.py
tests/test_real_detector.py
18 passed in 16.16s
```

These checks validate application imports and existing behavior outside the
container. The container-specific CPU-only Torch, Runtime Interface Emulator,
proxy events, and filesystem results are recorded above.

## 9. Adaptive-memory behavior

The Lambda image copies the current local adaptive-memory artifact so that the
existing behavior can be tested locally. This is only a local validation
arrangement. AWS Lambda local storage is not treated as permanent persistence.
Before AWS deployment, adaptive-memory persistence must be moved to S3. DynamoDB
was not introduced.

The source implementation loads and saves
`data/processed/adaptive_threat_memory.pkl`. In the Lambda container, confirmed
phishing feedback increased the document count from 6 to 7. The same
validation container was stopped and started again; health then reported
`adaptive_memory_documents=7`, and the adaptive-memory file was present at
`/var/task/data/processed/adaptive_threat_memory.pkl`.

The Lambda Dockerfile sets `HF_HOME=/tmp/huggingface`. Transformers therefore
used that directory for the runtime embedding-model cache. After invocation
and restart validation, the directory was present with 22 files. This confirms
local cache availability/reuse across the tested container lifetime; it must
not be interpreted as permanent AWS persistence.

## 10. Known limitations

- S3-backed adaptive-memory storage was implemented after this local Lambda
  validation. The prior validation used the local file backend only.
- The updated `adaptive-phishing-lambda:s3-ready` build was attempted once
  after adding `boto3==1.43.111`. Dependencies and all source/model/memory
  copy steps completed, but final image unpacking failed after 319.869
  seconds:

  ```text
  failed to extract layer
  sha256:65df78ee29e9107f91d32dd3426953609e39342eab6c603b969dabd6188da8da:
  open /var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/
  snapshots/337/fs/var/task/transformers/trainer_utils.py:
  read-only file system
  ```

  No retry was performed. The updated image ID and size remain unavailable.
- The S3 adapter and conditional-write behavior are covered by mocked-client
  unit tests; no real S3 bucket or AWS credentials were used.
- Validation was local only; no AWS deployment or AWS-managed persistence was
  tested.
- Adaptive-memory persistence across restart was verified using the current
  local container filesystem. This does not establish permanent persistence in
  AWS Lambda.
- Hugging Face caching was observed under `/tmp/huggingface` locally. AWS
  warm-container reuse and eviction behavior remain untested.
- The local RIE process repeatedly initialized the application during the
  validation sequence. The measured timings above should therefore be treated
  as local invocation measurements, not AWS performance estimates.

## 11. AWS deployment prerequisites

Before any deployment work:

- Decide and implement S3-backed adaptive-memory persistence.
- Build and validate the Lambda image successfully with the Runtime Interface
  Emulator.
- Configure API Gateway integration and request/response handling.
- Configure an S3 static frontend separately from Lambda.
- Provide AWS credentials, ECR, Lambda, API Gateway, S3, and IAM configuration
  only as an explicitly approved deployment task.

None of these AWS steps has been performed or tested.
