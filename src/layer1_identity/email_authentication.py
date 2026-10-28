from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re


@dataclass(frozen=True)
class EmailAuthenticationResult:
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"

    from_address: str | None = None
    reply_to_address: str | None = None
    return_path_address: str | None = None

    display_name: str | None = None

    from_reply_to_consistent: str = "unknown"
    from_return_path_consistent: str = "unknown"
    display_name_consistent: str = "unknown"


_VALID_RESULTS = {"pass", "fail", "neutral", "none", "softfail", "temperror", "permerror"}


def _normalize_result(value: str | None) -> str:
    if not value:
        return "unknown"

    value = value.strip().lower()

    if value in _VALID_RESULTS:
        return value

    return "unknown"


def _extract_auth_result(
    authentication_results: list[str],
    mechanism: str,
) -> str:
    """
    Extract SPF/DKIM/DMARC result from Authentication-Results headers.

    Example:
        Authentication-Results: mx.example;
            spf=pass;
            dkim=pass;
            dmarc=pass
    """

    pattern = re.compile(
        rf"\b{re.escape(mechanism)}\s*=\s*"
        rf"(pass|fail|neutral|none|softfail|temperror|permerror)\b",
        re.IGNORECASE,
    )

    for header in authentication_results:
        match = pattern.search(header)
        if match:
            return _normalize_result(match.group(1))

    return "unknown"


def _extract_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None

    return address.rsplit("@", 1)[1].strip().lower()


def _compare_addresses(
    first: str | None,
    second: str | None,
) -> str:
    if not first or not second:
        return "unknown"

    first_domain = _extract_domain(first)
    second_domain = _extract_domain(second)

    if first_domain is None or second_domain is None:
        return "unknown"

    return "pass" if first_domain == second_domain else "fail"


def _display_name_consistency(
    display_name: str | None,
    from_address: str | None,
) -> str:
    """
    Conservative display-name check.

    A normal display name does not automatically count as suspicious.
    We only flag an obvious mismatch where the display name itself
    contains an email address whose domain differs from the From domain.
    """

    if not display_name or not from_address:
        return "unknown"

    embedded_email = re.search(
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        display_name,
    )

    if not embedded_email:
        return "neutral"

    display_domain = _extract_domain(embedded_email.group(0))
    from_domain = _extract_domain(from_address)

    if display_domain is None or from_domain is None:
        return "unknown"

    return "pass" if display_domain == from_domain else "fail"


def parse_eml_text(raw_text: str) -> EmailAuthenticationResult:
    """
    Parse a raw RFC-style email message.

    Important:
    This function parses authentication results stated in
    Authentication-Results headers. It does NOT independently
    perform SPF, DKIM, or DMARC verification.
    """

    raw_text = raw_text.lstrip("\r\n")
    message = Parser(policy=policy.default).parsestr(raw_text)

    from_header = message.get("From")
    reply_to_header = message.get("Reply-To")
    return_path_header = message.get("Return-Path")

    from_display_name, from_address = parseaddr(from_header or "")
    _, reply_to_address = parseaddr(reply_to_header or "")
    _, return_path_address = parseaddr(return_path_header or "")

    authentication_results = message.get_all(
        "Authentication-Results",
        [],
    )

    spf = _extract_auth_result(
        authentication_results,
        "spf",
    )

    dkim = _extract_auth_result(
        authentication_results,
        "dkim",
    )

    dmarc = _extract_auth_result(
        authentication_results,
        "dmarc",
    )

    return EmailAuthenticationResult(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        from_address=from_address or None,
        reply_to_address=reply_to_address or None,
        return_path_address=return_path_address or None,
        display_name=from_display_name or None,
        from_reply_to_consistent=_compare_addresses(
            from_address,
            reply_to_address,
        ),
        from_return_path_consistent=_compare_addresses(
            from_address,
            return_path_address,
        ),
        display_name_consistent=_display_name_consistency(
            from_display_name,
            from_address,
        ),
    )