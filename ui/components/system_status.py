from __future__ import annotations

from typing import Any

import streamlit as st


def render_system_status(
    health: dict[str, Any] | None,
    error: str | None = None,
) -> None:
    st.sidebar.subheader("System Status")
    if error:
        st.sidebar.error("API: Offline")
        st.sidebar.caption(error)
        return
    if not health:
        st.sidebar.warning("API: Unknown")
        return
    st.sidebar.success("API: Connected")
    st.sidebar.write(f"Service: `{health.get('service', 'Unavailable')}`")
    st.sidebar.write(
        "Adaptive Memory: "
        f"{health.get('adaptive_memory_documents', 'Unavailable')} documents"
    )
