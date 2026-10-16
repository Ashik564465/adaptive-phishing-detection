import socket
import ssl
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List


@lru_cache(maxsize=2048)
def analyze_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "unavailable",
        "source": "tls_handshake",
        "https": True,
        "certificate": {
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_until": None,
            "observed_at": None,
            "valid_at_observation": None,
            "validity_status": "unknown",
            "validation_status": "unknown",
            "hostname_match": None,
            "san": [],
        },
        "errors": [],
        "signals": [],
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                certificate = connection.getpeercert()
                observed_at = datetime.now(timezone.utc)
                valid_from = certificate.get("notBefore")
                valid_until = certificate.get("notAfter")
                valid_at_observation = _certificate_valid_at(
                    valid_from,
                    valid_until,
                    observed_at,
                )
                result["status"] = "available"
                result["certificate"].update(
                    {
                        "issuer": _flatten_name(certificate.get("issuer")),
                        "subject": _flatten_name(certificate.get("subject")),
                        "valid_from": valid_from,
                        "valid_until": valid_until,
                        "observed_at": observed_at.isoformat(),
                        "valid_at_observation": valid_at_observation,
                        "validity_status": (
                            "valid"
                            if valid_at_observation is True
                            else "invalid"
                            if valid_at_observation is False
                            else "unknown"
                        ),
                        "validation_status": "valid",
                        "hostname_match": True,
                        "san": [
                            value
                            for kind, value in certificate.get("subjectAltName", [])
                            if kind == "DNS"
                        ],
                    }
                )
                result["certificate"]["san_matched"] = _hostname_matches_san(
                    hostname,
                    result["certificate"]["san"],
                )
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", str(exc))
        observed_at = datetime.now(timezone.utc)
        is_hostname_mismatch = (
            getattr(exc, "verify_code", None) == 62
            or "hostname mismatch" in message.lower()
        )
        result["status"] = "available" if is_hostname_mismatch else "error"
        result["certificate"]["observed_at"] = observed_at.isoformat()
        result["certificate"]["validation_status"] = "invalid"
        if is_hostname_mismatch:
            result["certificate"]["hostname_match"] = False
            result["signals"].append(
                {"signal": "tls_hostname_mismatch", "severity": "high"}
            )
            error_type = "certificate"
        else:
            if any(
                marker in message.lower()
                for marker in ("expired", "not yet valid", "outside the validity period")
            ):
                result["certificate"]["validity_status"] = "invalid"
                result["certificate"]["valid_at_observation"] = False
            result["signals"].append(
                {"signal": "tls_certificate_invalid", "severity": "medium"}
            )
            error_type = "certificate_validation"
        result["errors"].append({"type": error_type, "message": message})
    except socket.timeout:
        result["status"] = "timeout"
        result["errors"].append({"type": "timeout", "message": "TLS connection timed out"})
    except (OSError, ssl.SSLError) as exc:
        result["status"] = "error"
        result["errors"].append({"type": "tls", "message": str(exc)})
    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


def _certificate_valid_at(
    valid_from: Any,
    valid_until: Any,
    observed_at: datetime,
) -> bool | None:
    if (
        not isinstance(valid_from, str)
        or not isinstance(valid_until, str)
        or observed_at.tzinfo is None
    ):
        return None
    try:
        starts_at = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(valid_from),
            timezone.utc,
        )
        expires_at = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(valid_until),
            timezone.utc,
        )
    except (OverflowError, OSError, ValueError):
        return None
    return starts_at <= observed_at <= expires_at


def _hostname_matches_san(hostname: str, san: List[str]) -> bool:
    hostname = hostname.lower().rstrip(".")
    for entry in san:
        pattern = entry.lower().rstrip(".")
        if pattern == hostname:
            return True
        if pattern.startswith("*.") and hostname.endswith(pattern[1:]):
            return hostname.count(".") == pattern.count(".")
    return False


def _flatten_name(name: Any) -> str | None:
    if not name:
        return None
    return ", ".join(
        f"{key}={value}"
        for part in name
        for key, value in part
    )
