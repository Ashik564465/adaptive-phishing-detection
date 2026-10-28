from __future__ import annotations

import os
from uuid import uuid4

import streamlit as st

from ui.api_client import ApiClient, ApiClientError
from ui.components.detection_result import render_detection_result
from ui.components.evidence_panel import render_evidence_panel
from ui.components.feedback import render_feedback
from ui.components.risk_dashboard import render_risk_dashboard
from ui.components.system_status import render_system_status


DEFAULT_API_URL = "http://127.0.0.1:8000"
PHISHING_EXAMPLE = {
    "subject": "Urgent account verification",
    "body": (
        "Your company account requires immediate security verification. "
        "Confirm your password now to prevent account suspension."
    ),
    "sender": "security@example.com",
    "receiver": "",
}
LEGITIMATE_EXAMPLE = {
    "subject": "Team meeting tomorrow",
    "body": (
        "The team meeting is scheduled for tomorrow at 10:00 AM. "
        "Please bring the project status update."
    ),
    "sender": "team@example.com",
    "receiver": "",
}


st.set_page_config(
    page_title="Adaptive Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
)
st.markdown(
    """
    <style>
    .classification-card {
        border: 1px solid #334155;
        border-radius: 0.75rem;
        padding: 1.25rem;
        background: #0f172a;
        margin-bottom: 1rem;
    }
    .classification-label {
        color: #38bdf8;
        font-size: 2rem;
        font-weight: 700;
    }
    .risk-label { color: #94a3b8; margin-top: 0.5rem; }
    .risk-score { font-size: 1.5rem; font-weight: 600; }
    </style>
    """,
    unsafe_allow_html=True,
)


def _optional_value(value: str) -> str | None:
    value = value.strip()
    return value or None


def _load_example(example: dict[str, str]) -> None:
    st.session_state.subject = example["subject"]
    st.session_state.body = example["body"]
    st.session_state.sender = example["sender"]
    st.session_state.receiver = example["receiver"]


st.title("Adaptive Phishing Detection System")
st.caption("Multi-layer Email and SMS Threat Intelligence")

api_url = st.sidebar.text_input(
    "API URL",
    value=os.getenv("API_BASE_URL", DEFAULT_API_URL),
)
client = ApiClient(api_url)

health = None
health_error = None
try:
    health = client.get_health()
except ApiClientError as error:
    health_error = str(error)
render_system_status(health, health_error)

channel = st.sidebar.radio("Channel", ("EMAIL", "SMS"))
st.sidebar.caption("Backend risk scoring remains the source of truth.")

st.subheader("Message Details")
example_columns = st.columns(3)
with example_columns[0]:
    if st.button("Load phishing example"):
        _load_example(PHISHING_EXAMPLE)
with example_columns[1]:
    if st.button("Load legitimate example"):
        _load_example(LEGITIMATE_EXAMPLE)

if "subject" not in st.session_state:
    st.session_state.subject = ""
if "body" not in st.session_state:
    st.session_state.body = ""
if "sender" not in st.session_state:
    st.session_state.sender = ""
if "receiver" not in st.session_state:
    st.session_state.receiver = ""

sender = st.text_input("Sender", key="sender")
receiver = st.text_input("Receiver", key="receiver")
subject = ""
raw_email = None

if channel == "EMAIL":
    subject = st.text_input("Subject", key="subject")
    uploaded = st.file_uploader("Optional .eml file", type=["eml"])
    if uploaded is not None:
        raw_email = uploaded.getvalue().decode("utf-8", errors="replace")

body = st.text_area("Message Body", key="body", height=180)
message_id = st.text_input(
    "Message ID",
    value=f"ui-{uuid4().hex[:12]}",
)

if st.button("Analyze Message", type="primary"):
    if not body.strip():
        st.error("Message body is required.")
    else:
        try:
            st.session_state.detection_result = client.detect_message(
                message_id=message_id.strip(),
                channel=channel,
                body=body,
                subject=subject,
                sender=_optional_value(sender),
                receiver=_optional_value(receiver),
                raw_email=raw_email,
            )
            st.session_state.detection_input = {
                "message_id": message_id.strip(),
                "channel": channel,
                "body": body,
                "subject": subject,
                "sender": _optional_value(sender),
                "receiver": _optional_value(receiver),
            }
        except ApiClientError as error:
            st.error(str(error))

result = st.session_state.get("detection_result")
input_data = st.session_state.get("detection_input")
if isinstance(result, dict) and isinstance(input_data, dict):
    render_detection_result(result)
    render_risk_dashboard(result)
    render_evidence_panel(result)
    render_feedback(
        client.submit_feedback,
        client.get_health,
        **input_data,
    )
