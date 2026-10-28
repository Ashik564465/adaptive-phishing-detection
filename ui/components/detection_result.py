from __future__ import annotations

from typing import Any

import streamlit as st


def render_detection_result(result: dict[str, Any]) -> None:
    classification = result.get("classification", "Unavailable")
    risk_score = result.get("risk_score")
    score_text = (
        f"{float(risk_score):.2f} / 100"
        if isinstance(risk_score, (int, float))
        else "Unavailable"
    )
    st.subheader("Detection Result")
    st.markdown(
        f"""
        <div class="classification-card">
            <div class="classification-label">{classification}</div>
            <div class="risk-label">Risk Score</div>
            <div class="risk-score">{score_text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
