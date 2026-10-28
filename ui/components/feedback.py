from __future__ import annotations

from typing import Any, Callable

import streamlit as st


def render_feedback(
    submit: Callable[..., dict[str, Any]],
    refresh_health: Callable[[], dict[str, Any]],
    *,
    message_id: str,
    channel: str,
    body: str,
    subject: str,
    sender: str | None,
    receiver: str | None,
) -> None:
    st.subheader("Adaptive Feedback")
    st.write("Was this detection correct?")
    columns = st.columns(3)
    actions = (
        ("Confirm Phishing", "confirmed_phishing", "phishing"),
        ("Confirm Legitimate", "confirmed_legitimate", "legitimate"),
        ("Incorrect Prediction", "incorrect_prediction", None),
    )
    for column, (label, feedback_type, corrected_label) in zip(
        columns,
        actions,
    ):
        with column:
            if st.button(label, key=f"feedback_{feedback_type}"):
                try:
                    response = submit(
                        message_id=message_id,
                        feedback_type=feedback_type,
                        corrected_label=corrected_label,
                        channel=channel,
                        body=body,
                        subject=subject,
                        sender=sender,
                        receiver=receiver,
                    )
                except Exception as error:
                    st.error(str(error))
                    continue
                if response.get("knowledge_updated") is True:
                    st.success("Knowledge updated.")
                else:
                    st.info(
                        "Feedback accepted without updating adaptive memory."
                    )
                count = response.get("adaptive_memory_documents")
                if isinstance(count, int):
                    st.write(f"Adaptive memory: {count} documents")
                try:
                    refreshed_health = refresh_health()
                except Exception as error:
                    st.warning(
                        f"Feedback succeeded, but health refresh failed: {error}"
                    )
                else:
                    refreshed_count = refreshed_health.get(
                        "adaptive_memory_documents"
                    )
                    if isinstance(refreshed_count, int):
                        st.write(
                            "Current adaptive memory: "
                            f"{refreshed_count} documents"
                        )
