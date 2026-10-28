# Local UI validation

## 1. UI architecture

The Streamlit UI is a separate presentation layer under `ui/`. It calls the existing FastAPI service through `ui/api_client.py` and does not duplicate detection, risk fusion, RAG, Gemini, or adaptive-memory logic.

Components:

- `ui/app.py`: page layout, input handling, session state, and orchestration.
- `ui/api_client.py`: HTTP client and friendly error handling.
- `ui/components/`: display components for status, results, risk signals, evidence, and feedback.

## 2. Backend integration

The client uses the existing endpoints and schemas:

- `GET /health`
- `POST /detect`
- `POST /feedback`

The default URL is `http://127.0.0.1:8000`. It can be overridden with `API_BASE_URL` or the sidebar field.

Email `.eml` uploads are sent as the existing `raw_email` field. Missing metadata is sent as null or empty values; the UI does not fabricate authentication or sender metadata.

## 3. Detection test

The UI is configured to send the backend's exact detection request fields. The requested synthetic phishing example is available through the **Load phishing example** control.

The UI displays backend-returned:

- classification
- risk score
- Transformer probability
- identity risk
- behavioral risk
- historical risk
- retrieved threat count
- explanation
- Gemini status

No risk score is calculated in Streamlit.

Browser smoke test completed against the local FastAPI service:

- Loaded the phishing example and submitted it through **Analyze Message**.
- Displayed `PHISHING`, risk score `79.99 / 100`, Transformer probability `99.98%`,
  identity risk `0.0000`, behavioral risk `0.0000`, historical risk `1.0000`,
  and `Retrieved Threats: 1`.
- Displayed the backend explanation that the Transformer and historical threat
  memory provided strong phishing evidence.
- The backend response used deterministic Gemini fallback; the UI did not
  present fallback as successful Gemini reasoning.

## 4. Feedback test

The feedback controls map to the existing backend feedback types:

- Confirm Phishing -> `confirmed_phishing`
- Confirm Legitimate -> `confirmed_legitimate`
- Incorrect Prediction -> `incorrect_prediction`

Feedback responses display whether knowledge was updated and the returned adaptive-memory count.
After feedback, the UI also calls `/health` to refresh and display the current adaptive-memory count.

One browser **Confirm Phishing** submission returned `Knowledge updated.` and
increased adaptive memory from 4 to 5 documents. The follow-up health refresh
reported the updated count.

## 5. Adaptive-memory persistence test

The UI refreshes the returned feedback count and can refresh the sidebar health status on rerun. Persistence remains implemented and owned by the existing backend. No Transformer retraining is claimed or initiated by the UI.

## 6. Gemini fallback behavior

The UI uses the backend's `gemini_used` field:

- `true`: “Gemini contextual reasoning used”
- `false`: “Gemini unavailable. Deterministic fallback used.”

Fallback is never labeled as successful Gemini reasoning.

## 7. Screenshots to capture manually

After starting FastAPI and Streamlit, capture:

1. Initial dashboard with API connected and adaptive-memory count.
2. Email input containing the phishing example.
3. Detection result showing classification, risk score, evidence cards, and threat count.
4. Gemini fallback status when `gemini_used=false`.
5. Feedback response showing knowledge update and new memory count.
6. Restarted backend with the persisted memory count visible.

## 8. Final test results

The UI API-client tests cover:

- successful health request
- health connection failure
- successful detection
- detection HTTP error
- detection timeout
- successful feedback
- feedback HTTP error
- malformed API response

The combined suite, including the UI API-client tests, completed at:

```text
108 passed, 1 skipped
```

The UI smoke test requires Streamlit installation and a manually running browser session. It must not call Gemini directly.

## 9. Known limitations

- Browser screenshots and visual interaction require manual validation.
- The current `/detect` response exposes explanation strings rather than structured per-layer evidence.
- The UI only displays fields returned by the backend.
- Gemini availability remains environment-dependent.
- URL extraction, URL reputation, domain reputation, URL blacklists, and URL scoring are intentionally absent.
