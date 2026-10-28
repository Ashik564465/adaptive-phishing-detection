from __future__ import annotations

from typing import Any

import streamlit as st


def _format_value(value: Any, *, percent: bool = False) -> str:
    if not isinstance(value, (int, float)):
        return "Unavailable"
    if percent:
        return f"{float(value) * 100:.2f}%"
    return f"{float(value):.4f}"


def render_risk_dashboard(result: dict[str, Any]) -> None:
    st.subheader("Risk Dashboard")
    score = result.get("risk_score")
    if isinstance(score, (int, float)):
        st.progress(max(0.0, min(1.0, float(score) / 100.0)))

    cards = [
        ("NLP / Transformer", result.get("phishing_probability"), True),
        ("Identity", result.get("identity_risk"), False),
        ("Behavioral", result.get("behavioral_risk"), False),
        ("Historical Threat Memory", result.get("historical_risk"), False),
    ]
    columns = st.columns(4)
    for column, (label, value, percent) in zip(columns, cards):
        with column:
            st.metric(label, _format_value(value, percent=percent))

    retrieved = result.get("retrieved_threat_count")
    st.caption(
        "Retrieved Threats: "
        f"{retrieved if isinstance(retrieved, int) else 'Unavailable'}"
    )
