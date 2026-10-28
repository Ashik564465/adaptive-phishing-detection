from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.layer1_identity.email_authentication import (
    EmailAuthenticationResult,
)


@dataclass(frozen=True)
class EmailIdentityFeatures:
    """
    Structured identity features derived from
    email authentication/header evidence.
    """

    spf_pass: Optional[int]
    spf_fail: Optional[int]

    dkim_pass: Optional[int]
    dkim_fail: Optional[int]

    dmarc_pass: Optional[int]
    dmarc_fail: Optional[int]

    from_reply_to_mismatch: Optional[int]
    from_return_path_mismatch: Optional[int]

    display_name_anomaly: Optional[int]

    authentication_available: int


def _binary_result(
    value: str,
    positive: str,
    negative: str,
) -> tuple[Optional[int], Optional[int]]:

    value = str(value).lower()

    if value == positive:

        return 1, 0

    if value == negative:

        return 0, 1

    return None, None


def build_identity_features(
    result: EmailAuthenticationResult,
) -> EmailIdentityFeatures:

    spf_pass, spf_fail = _binary_result(
        result.spf,
        "pass",
        "fail",
    )

    dkim_pass, dkim_fail = _binary_result(
        result.dkim,
        "pass",
        "fail",
    )

    dmarc_pass, dmarc_fail = _binary_result(
        result.dmarc,
        "pass",
        "fail",
    )

    if (
        result.from_reply_to_consistent
        == "fail"
    ):

        from_reply_to_mismatch = 1

    elif (
        result.from_reply_to_consistent
        == "pass"
    ):

        from_reply_to_mismatch = 0

    else:

        from_reply_to_mismatch = None

    if (
        result.from_return_path_consistent
        == "fail"
    ):

        from_return_path_mismatch = 1

    elif (
        result.from_return_path_consistent
        == "pass"
    ):

        from_return_path_mismatch = 0

    else:

        from_return_path_mismatch = None

    if (
        result.display_name_consistent
        == "neutral"
    ):

        display_name_anomaly = 1

    elif (
        result.display_name_consistent
        == "pass"
    ):

        display_name_anomaly = 0

    else:

        display_name_anomaly = None

    authentication_values = [
        result.spf,
        result.dkim,
        result.dmarc,
    ]

    authentication_available = int(
        any(
            value != "unknown"
            for value in authentication_values
        )
    )

    return EmailIdentityFeatures(
        spf_pass=spf_pass,
        spf_fail=spf_fail,
        dkim_pass=dkim_pass,
        dkim_fail=dkim_fail,
        dmarc_pass=dmarc_pass,
        dmarc_fail=dmarc_fail,
        from_reply_to_mismatch=(
            from_reply_to_mismatch
        ),
        from_return_path_mismatch=(
            from_return_path_mismatch
        ),
        display_name_anomaly=(
            display_name_anomaly
        ),
        authentication_available=(
            authentication_available
        ),
    )


def identity_features_to_dict(
    features: EmailIdentityFeatures,
) -> dict:

    return {
        "spf_pass": features.spf_pass,
        "spf_fail": features.spf_fail,
        "dkim_pass": features.dkim_pass,
        "dkim_fail": features.dkim_fail,
        "dmarc_pass": features.dmarc_pass,
        "dmarc_fail": features.dmarc_fail,
        "from_reply_to_mismatch": (
            features.from_reply_to_mismatch
        ),
        "from_return_path_mismatch": (
            features.from_return_path_mismatch
        ),
        "display_name_anomaly": (
            features.display_name_anomaly
        ),
        "authentication_available": (
            features.authentication_available
        ),
    }