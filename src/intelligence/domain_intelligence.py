from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict

import requests

from src.intelligence.url_normalizer import normalize_url


@lru_cache(maxsize=2048)
def analyze_domain(url: str) -> Dict[str, Any]:
    normalized = normalize_url(url)
    result = {
        "status": "unknown",
        "reason": "domain_metadata_unavailable",
        "hostname": normalized["hostname"],
        "registered_domain": normalized["registered_domain"],
        "subdomain": normalized["subdomain"],
        "scheme": normalized["scheme"],
        "port": normalized["port"],
        "creation_date": None,
        "expiry_date": None,
        "registrar": None,
        "nameservers": [],
        "domain_age_days": None,
        "domain_age_known": False,
    }
    domain = normalized["registered_domain"]
    if not domain:
        result["reason"] = "registered_domain_unavailable"
        return result

    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "adaptive-phishing/1.0",
            },
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        result["reason"] = f"rdap_lookup_failed: {exc.__class__.__name__}"
        return result

    registration_date = _rdap_event_date(payload, "registration")
    expiry_date = _rdap_event_date(payload, "expiration")
    result.update(
        {
            "status": "available",
            "reason": "rdap_metadata",
            "creation_date": registration_date,
            "expiry_date": expiry_date,
            "registrar": _rdap_registrar(payload),
            "nameservers": [
                nameserver.get("ldhName")
                for nameserver in payload.get("nameservers", [])
                if nameserver.get("ldhName")
            ],
        }
    )
    if registration_date:
        created = _parse_rdap_date(registration_date)
        result["domain_age_days"] = max(
            0,
            (datetime.now(timezone.utc) - created).days,
        )
        result["domain_age_known"] = True
    return result


def _rdap_event_date(payload: Dict[str, Any], action: str) -> str | None:
    for event in payload.get("events", []):
        if event.get("eventAction") == action and event.get("eventDate"):
            return str(event["eventDate"])
    return None


def _parse_rdap_date(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _rdap_registrar(payload: Dict[str, Any]) -> str | None:
    for entity in payload.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        for item in entity.get("vcardArray", [None, []])[1]:
            if len(item) >= 4 and item[0] == "fn":
                return item[3]
    return None
