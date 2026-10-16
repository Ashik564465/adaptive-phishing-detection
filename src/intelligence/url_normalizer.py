from functools import lru_cache
import ipaddress
import re
from typing import Any, Dict
from urllib.parse import urlsplit, urlunsplit

import tldextract


def validate_url_input(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("URL is malformed") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    if not hostname:
        raise ValueError("URL must include a hostname")
    if any(character.isspace() for character in hostname):
        raise ValueError("Hostname contains whitespace")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Hostname is malformed") from exc
    try:
        ipaddress.ip_address(ascii_hostname)
        return candidate
    except ValueError:
        pass
    labels = ascii_hostname.split(".")
    if len(ascii_hostname) > 253 or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Hostname is malformed")
    return candidate


@lru_cache(maxsize=2048)
def normalize_url(url: str) -> Dict[str, Any]:
    original = url
    candidate = validate_url_input(url)
    parsed = urlsplit(candidate)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        # validate_url_input already rejects malformed IDN hostnames.
        raise ValueError("Hostname is malformed")
    extracted = tldextract.extract(hostname)
    registered_domain = (
        f"{extracted.domain}.{extracted.suffix}".lower()
        if extracted.domain and extracted.suffix
        else extracted.domain.lower()
    )
    port = parsed.port
    if port is None and parsed.scheme.lower() in {"http", "https"}:
        port = 443 if parsed.scheme.lower() == "https" else 80
    normalized_url = urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.query,
            parsed.fragment,
        )
    )
    return {
        "original_url": original,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": extracted.subdomain.lower(),
        "scheme": parsed.scheme.lower(),
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
    }
