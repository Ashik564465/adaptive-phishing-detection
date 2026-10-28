# Local Streamlit UI

## Purpose

This directory contains a separate Streamlit presentation layer for the existing adaptive phishing detection system. It does not implement detection, risk scoring, Gemini reasoning, retrieval, or adaptive-memory logic.

The UI communicates with the existing FastAPI backend over HTTP.

## Architecture

```text
Streamlit UI
    -> ui/api_client.py
    -> FastAPI /health, /detect, /feedback
    -> existing detection pipeline
```

The backend remains the only source of truth for risk scores, classification, explanations, Gemini status, and adaptive-memory updates.

## Installation

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The requirements include `streamlit`. The UI uses the existing `requests` dependency.

## Start FastAPI

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --reload --port 8000
```

## Start Streamlit

In another terminal:

```powershell
.\.venv\Scripts\python.exe -m streamlit run ui/app.py
```

## API URL configuration

The default backend URL is:

```text
http://127.0.0.1:8000
```

Configure it with the `API_BASE_URL` environment variable:

```powershell
$env:API_BASE_URL="http://127.0.0.1:8000"
.\.venv\Scripts\python.exe -m streamlit run ui/app.py
```

The URL can also be changed in the sidebar.

## Example usage

1. Start FastAPI.
2. Start Streamlit.
3. Select `EMAIL` or `SMS`.
4. Enter a message or load one of the synthetic examples.
5. Click **Analyze Message**.
6. Review the backend classification, risk score, evidence, threat count, and Gemini status.
7. Submit feedback after a detection if the result is validated.

An uploaded `.eml` file is sent as `raw_email` when provided. Missing sender, receiver, or authentication information is left unavailable; the UI does not fabricate it.

## Known limitations

- The UI displays only fields returned by the current API.
- The current backend response exposes explanation strings rather than structured per-layer evidence.
- Gemini status reflects `gemini_used`; fallback is displayed as fallback, not as Gemini reasoning.
- The UI does not perform URL extraction, URL reputation, domain reputation, or URL scoring.
- The browser UI must be validated manually for screenshots and visual presentation.

## Docker

The local Docker configuration runs FastAPI and Streamlit in one CPU-only
container:

```powershell
docker compose build
docker compose up
```

Open `http://localhost:8501` for the dashboard and
`http://localhost:8000/health` for the API. Stop the container with:

```powershell
docker compose down
```

The adaptive-memory file is mounted from
`data/processed/adaptive_threat_memory.pkl`, so validated feedback survives
container restarts. Set `GEMINI_API_KEY` in the host environment before
starting the compose service when Gemini access is desired. The key is passed
at runtime and is not copied into the image.
