from __future__ import annotations

from typing import Any

import streamlit as st


def render_evidence_panel(result: dict[str, Any]) -> None:
    st.subheader("Explainable Detection")
    explanation = result.get("explanation")
    if isinstance(explanation, list) and explanation:
        for item in explanation:
            if isinstance(item, str):
                st.info(item)
            else:
                st.json(item)
    elif isinstance(explanation, str) and explanation.strip():
        st.info(explanation)
    else:
        st.caption("No explanation was provided by the backend.")

    with st.expander("Threat intelligence details"):
        retrieved = result.get("retrieved_threat_count")
        st.write(
            "Retrieved threats:",
            retrieved if isinstance(retrieved, int) else "Unavailable",
        )
        gemini_used = result.get("gemini_used")
        if gemini_used is True:
            st.success("Gemini contextual reasoning used")
        elif gemini_used is False:
            st.warning("Gemini unavailable. Deterministic fallback used.")
        else:
            st.info("Gemini status unavailable.")
