"""Passive domain-forensics collection using existing analyzers and public data."""

from datetime import datetime, timezone
import ipaddress
import json
import math
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import requests
import tldextract

import dns.exception
import dns.resolver

from src.intelligence.domain_intelligence import analyze_domain


CT_URL = "https://crt.sh/"
# CertSpotter supports the documented /v1/issuances endpoint. Its free tier
# limits full-domain queries, so fallback use is explicitly opt-in.
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
RIPE_NETWORK_INFO_URL = (
    "https://stat.ripe.net/data/network-info/data.json"
)
HTTP_TIMEOUT = (2.0, 4.0)
DNS_TIMEOUT = 0.75
RDAP_TIMEOUT = 5.0
CT_TIMEOUT = 2.0
CT_RETRIES = 1
CT_RETRY_BACKOFF = 0.2
DEFAULT_DEADLINE_SECONDS = 25.0
MAX_RESPONSE_BYTES = 2_000_000
MAX_CERTIFICATES = 50
MAX_SUBDOMAINS = 25
MAX_DNS_RECORDS_PER_TYPE = 10
MAX_IP_ASN_LOOKUPS = 3
MAX_TEXT_LENGTH = 512
MIN_REQUEST_BUDGET_SECONDS = 0.01
_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def investigate_domain(
    value: str,
    *,
    ct_timeout: float = CT_TIMEOUT,
    ct_retries: int = CT_RETRIES,
    retry_backoff: float = CT_RETRY_BACKOFF,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    use_certspotter_fallback: bool = True,
) -> Dict[str, Any]:
    """Collect bounded passive evidence for the registered domain in ``value``.

    The input may be a domain or an HTTP(S) URL. Subdomains in the input are
    normalized to their registrable domain before any external query.
    """
    if (
        not math.isfinite(ct_timeout)
        or not math.isfinite(retry_backoff)
        or not math.isfinite(deadline_seconds)
        or ct_timeout <= 0
        or retry_backoff < 0
        or deadline_seconds <= 0
    ):
        raise ValueError("Timeouts must be positive and retry backoff non-negative")
    if ct_retries < 0 or ct_retries > 3:
        raise ValueError("ct_retries must be between 0 and 3")
    started_at = time.monotonic()
    deadline = started_at + deadline_seconds
    collected_at = _utc_now()
    result: Dict[str, Any] = {
        "domain": None,
        "subdomains": [],
        "dns_records": {},
        "dns_interpretations": {},
        "registration": {"status": "unavailable", "data": None},
        "certificate_history": [],
        "certificate_history_status": "unavailable",
        "subdomain_discovery_status": "unavailable",
        "infrastructure": [],
        "collected_at": collected_at,
        "sources": {},
        "status": "unavailable",
        "errors": [],
        "unavailable_evidence": [],
    }

    try:
        domain = _normalize_registered_domain(value)
    except (TypeError, ValueError) as exc:
        result["status"] = "invalid_input"
        result["errors"].append({
            "source": "input_validation",
            "message": str(exc),
        })
        for section in (
            "subdomain_discovery",
            "dns",
            "registration",
            "certificate_history",
            "ip_asn",
        ):
            result["unavailable_evidence"].append(section)
        return result

    result["domain"] = domain

    dns_result = _collect_dns(domain, result, deadline)
    _collect_registration(domain, result, deadline)
    certificates = _collect_certificate_history(
        domain,
        result,
        deadline=deadline,
        ct_timeout=ct_timeout,
        ct_retries=ct_retries,
        retry_backoff=retry_backoff,
        use_certspotter_fallback=use_certspotter_fallback,
    )
    result["certificate_history"] = certificates
    subdomains = _subdomains_from_certificates(certificates, domain)
    result["subdomains"] = subdomains[:MAX_SUBDOMAINS]
    ct_source = result["sources"]["certificate_transparency"]
    query_status = ct_source["status"]
    if query_status == "unavailable":
        certificate_status = "unavailable"
        subdomain_status = "unavailable"
    else:
        certificate_status = "available" if certificates else "no_records"
        subdomain_status = "available" if subdomains else "no_records"
    result["certificate_history_status"] = certificate_status
    result["subdomain_discovery_status"] = subdomain_status
    result["sources"]["subdomain_discovery"] = {
        "status": subdomain_status,
        "source_ref": "certificate_transparency",
        "collected_at": ct_source["collected_at"],
    }
    if subdomain_status == "unavailable":
        _append_unavailable_evidence(result, "subdomain_discovery")
    _collect_ip_context(dns_result, result, deadline)

    source_statuses = [
        source["status"] for source in result["sources"].values()
    ]
    result["status"] = _overall_status(source_statuses)
    result["collected_at"] = _utc_now()
    return result


def _normalize_registered_domain(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("Domain input must be a string")
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        raise ValueError("Domain input is empty or too long")
    if any(ord(char) < 32 for char in candidate):
        raise ValueError("Domain input contains control characters")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("Domain input is not a valid URL or domain") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP(S) URLs or domain names are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials are not allowed in domain input")
    if not hostname:
        raise ValueError("Domain input does not contain a hostname")

    try:
        ascii_hostname = (
            hostname.rstrip(".").encode("idna").decode("ascii").lower()
        )
    except UnicodeError as exc:
        raise ValueError("Domain hostname is not valid IDNA") from exc
    try:
        ipaddress.ip_address(ascii_hostname)
    except ValueError:
        pass
    else:
        raise ValueError("An IP address is not a domain name")

    if len(ascii_hostname) > 253:
        raise ValueError("Domain hostname is too long")
    labels = ascii_hostname.split(".")
    if any(not _LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError("Domain hostname contains an invalid label")

    extracted = tldextract.extract(ascii_hostname)
    if not extracted.domain or not extracted.suffix:
        raise ValueError("A registered domain with a public suffix is required")
    return f"{extracted.domain}.{extracted.suffix}".lower()


def _collect_dns(
    domain: str,
    result: Dict[str, Any],
    deadline: float,
) -> Dict[str, Any]:
    record_types = ("A", "AAAA", "MX", "NS", "CNAME", "TXT")
    raw_records: Dict[str, List[str]] = {kind: [] for kind in record_types}
    outcomes: Dict[str, str] = {}
    errors = []
    resolver = dns.resolver.Resolver()

    for record_type in record_types:
        remaining = _remaining(deadline)
        if remaining <= MIN_REQUEST_BUDGET_SECONDS:
            outcomes[record_type] = "deadline_exceeded"
            errors.append({
                "record_type": record_type,
                "status": "deadline_exceeded",
                "message": "Overall collection deadline reached",
            })
            continue
        timeout = min(DNS_TIMEOUT, remaining)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            answer = resolver.resolve(domain, record_type, lifetime=timeout)
            raw_records[record_type] = [
                _limited_text(item.to_text())
                for item in list(answer)[:MAX_DNS_RECORDS_PER_TYPE]
            ]
            outcomes[record_type] = "available"
        except dns.resolver.NXDOMAIN:
            outcomes[record_type] = "nxdomain"
        except dns.resolver.NoAnswer:
            outcomes[record_type] = "no_answer"
        except dns.resolver.NoNameservers as exc:
            outcomes[record_type] = "resolver_failure"
            errors.append({
                "record_type": record_type,
                "status": "resolver_failure",
                "message": _limited_text(str(exc)),
            })
        except dns.exception.Timeout:
            outcomes[record_type] = "timeout"
            errors.append({
                "record_type": record_type,
                "status": "timeout",
                "message": "DNS query timed out",
            })
        except Exception as exc:
            outcomes[record_type] = "resolver_failure"
            errors.append({
                "record_type": record_type,
                "status": "resolver_failure",
                "message": _limited_text(str(exc)),
            })

    successes = sum(status == "available" for status in outcomes.values())
    failures = sum(
        status not in {"available", "no_answer", "nxdomain"}
        for status in outcomes.values()
    )
    status = (
        "partial"
        if successes and failures
        else "available"
        if successes
        else "unavailable"
        if failures
        else "no_records"
    )
    normalized_mx = [
        item.strip()
        for item in raw_records["MX"]
    ]
    null_mx = any(
        re.fullmatch(r"0\s+\.", item) is not None
        for item in normalized_mx
    )
    result["dns_records"] = raw_records
    result["dns_interpretations"] = {
        "record_status": outcomes,
        "null_mx": null_mx,
        "mx_hosts": [] if null_mx else normalized_mx,
    }
    result["sources"]["dns"] = {
        "name": "dnspython",
        "status": status,
        "url": "system-configured DNS resolvers",
        "collected_at": _utc_now(),
    }
    result["errors"].extend(
        {"source": "dns", **error}
        for error in errors
    )
    if status == "unavailable":
        _mark_unavailable(result, "dns", f"DNS collection status: {status}")
    return {
        "status": status,
        "hostname": domain,
        "records": raw_records,
        "record_status": outcomes,
        "errors": errors,
    }


def _collect_registration(
    domain: str,
    result: Dict[str, Any],
    deadline: float,
) -> None:
    timestamp = _utc_now()
    source_url = f"https://rdap.org/domain/{domain}"
    if _remaining(deadline) < RDAP_TIMEOUT:
        _set_registration_unavailable(
            result,
            timestamp,
            source_url,
            "Overall collection deadline reached before RDAP lookup",
        )
        return
    try:
        registration = analyze_domain(f"https://{domain}")
        retrieval_status = (
            "available"
            if registration.get("status") == "available"
            else "unavailable"
        )
        registration_status = (
            "registered"
            if retrieval_status == "available"
            else "unknown"
        )
        collected_at = _utc_now()
        created_raw = registration.get("creation_date")
        expiry_raw = registration.get("expiry_date")
        parsed_created = _parse_rdap_date(created_raw)
        expiry = _parse_rdap_date(expiry_raw)
        collected_datetime = datetime.fromisoformat(
            collected_at.replace("Z", "+00:00")
        )
        created = parsed_created
        if created is not None and created > collected_datetime:
            created = None
        if created is not None and expiry is not None and expiry < created:
            expiry = None
        age_days = None
        if created is not None and created <= collected_datetime:
            age_days = (collected_datetime - created).days

        malformed_dates = []
        if created_raw and (
            parsed_created is None
            or parsed_created > collected_datetime
        ):
            malformed_dates.append("creation_date")
        if expiry_raw and (
            _parse_rdap_date(expiry_raw) is None
            or (
                parsed_created is not None
                and _parse_rdap_date(expiry_raw) < parsed_created
            )
        ):
            malformed_dates.append("expiry_date")
        data = {
            "creation_date": (
                created.isoformat() if created is not None else None
            ),
            "expiry_date": expiry.isoformat() if expiry is not None else None,
            "registrar": _limited_text(registration.get("registrar")),
            "domain_age_days": age_days,
            "domain_age_known": age_days is not None,
            "nameservers": _clean_string_list(
                registration.get("nameservers"),
                MAX_SUBDOMAINS,
            ),
            "malformed_fields": malformed_dates,
        }
        result["registration"] = {
            "status": retrieval_status,
            "retrieval_status": retrieval_status,
            "registration_status": registration_status,
            "data": data,
            "collected_at": collected_at,
        }
        result["sources"]["registration"] = {
            "name": "RDAP via existing analyze_domain",
            "url": source_url,
            "status": retrieval_status,
            "registration_status": registration_status,
            "collected_at": collected_at,
        }
        if retrieval_status != "available":
            _mark_unavailable(
                result,
                "registration",
                registration.get(
                    "reason",
                    "RDAP registration data unavailable",
                ),
            )
        if malformed_dates:
            result["errors"].append({
                "source": "registration",
                "status": "malformed_data",
                "message": "Invalid RDAP date field(s): "
                + ", ".join(malformed_dates),
            })
    except (
        requests.RequestException,
        ImportError,
        RuntimeError,
        ValueError,
        TypeError,
        AttributeError,
    ) as exc:
        _set_registration_unavailable(
            result,
            _utc_now(),
            source_url,
            str(exc),
        )


def _set_registration_unavailable(
    result: Dict[str, Any],
    timestamp: str,
    source_url: str,
    message: str,
) -> None:
    result["registration"] = {
        "status": "unavailable",
        "retrieval_status": "unavailable",
        "registration_status": "unknown",
        "data": None,
        "collected_at": timestamp,
    }
    result["sources"]["registration"] = {
        "name": "RDAP via existing analyze_domain",
        "url": source_url,
        "status": "unavailable",
        "registration_status": "unknown",
        "collected_at": timestamp,
    }
    _mark_unavailable(result, "registration", message)


def _collect_certificate_history(
    domain: str,
    result: Dict[str, Any],
    *,
    deadline: float,
    ct_timeout: float,
    ct_retries: int,
    retry_backoff: float,
    use_certspotter_fallback: bool,
) -> List[Dict[str, Any]]:
    attempts: List[Dict[str, Any]] = []
    sources: List[Tuple[str, str, Dict[str, str], str]] = [
        (
            "crt.sh Certificate Transparency",
            CT_URL,
            {"q": f"%.{domain}", "output": "json"},
            "crt_sh",
        )
    ]
    if use_certspotter_fallback:
        sources.append(
            (
                "CertSpotter Certificate Transparency Search API",
                CERTSPOTTER_URL,
                {
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                },
                "certspotter",
            )
        )

    successful_query = False
    final_records: List[Dict[str, Any]] = []
    selected_name = sources[0][0]
    selected_url = sources[0][1]
    selected_key = sources[0][3]

    for source_name, source_url, params, source_key in sources:
        source_succeeded = False
        # CertSpotter's free tier has a low full-domain query quota, so only
        # query it once as an explicitly enabled fallback.
        max_attempts = ct_retries + 1 if source_key == "crt_sh" else 1
        for attempt in range(1, max_attempts + 1):
            remaining = _remaining(deadline)
            if remaining <= MIN_REQUEST_BUDGET_SECONDS:
                attempts.append({
                    "source": source_key,
                    "source_name": source_name,
                    "url": source_url,
                    "attempt": attempt,
                    "status": "deadline_exceeded",
                    "message": "Overall analysis deadline reached",
                    "collected_at": _utc_now(),
                })
                break
            if attempt > 1:
                backoff = min(
                    retry_backoff * (2 ** (attempt - 2)),
                    max(0.0, _remaining(deadline)),
                )
                if backoff:
                    time.sleep(backoff)
                remaining = _remaining(deadline)
                if remaining <= MIN_REQUEST_BUDGET_SECONDS:
                    attempts.append({
                        "source": source_key,
                        "source_name": source_name,
                        "url": source_url,
                        "attempt": attempt,
                        "status": "deadline_exceeded",
                        "message": "Overall analysis deadline reached during backoff",
                        "collected_at": _utc_now(),
                    })
                    break
            request_timeout = min(ct_timeout, remaining / 2)
            try:
                payload = _get_json(
                    source_url,
                    params=params,
                    timeout=(request_timeout, request_timeout),
                    max_bytes=MAX_RESPONSE_BYTES,
                )
                parsed_records = _parse_ct_response(
                    payload,
                    domain=domain,
                    source_key=source_key,
                )
                successful_query = True
                source_succeeded = True
                selected_name = source_name
                selected_url = source_url
                selected_key = source_key
                final_records = parsed_records
                attempts.append({
                    "source": source_key,
                    "source_name": source_name,
                    "url": source_url,
                    "attempt": attempt,
                    "status": "available" if parsed_records else "no_records",
                    "record_count": len(parsed_records),
                    "collected_at": _utc_now(),
                })
                break
            except (
                requests.RequestException,
                TimeoutError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ) as exc:
                status = (
                    "malformed_response"
                    if isinstance(
                        exc,
                        (
                            UnicodeDecodeError,
                            json.JSONDecodeError,
                            TypeError,
                            ValueError,
                        ),
                    )
                    else _ct_error_status(exc)
                )
                attempts.append({
                    "source": source_key,
                    "source_name": source_name,
                    "url": source_url,
                    "attempt": attempt,
                    "status": status,
                    "message": _limited_text(str(exc)),
                    "collected_at": _utc_now(),
                })
                if attempt >= max_attempts or not _is_retryable_ct_error(exc):
                    break
        if source_succeeded:
            break
        if source_key == "certspotter":
            break

    final_status = (
        "available"
        if final_records
        else "no_records"
        if successful_query
        else "unavailable"
    )
    timestamp = _utc_now()
    result["sources"]["certificate_transparency"] = {
        "name": "Certificate Transparency",
        "source": selected_key,
        "selected_source": selected_key,
        "selected_source_name": selected_name,
        "selected_source_url": selected_url,
        "status": final_status,
        "attempts": attempts,
        "collected_at": timestamp,
    }
    if final_status == "unavailable":
        _append_unavailable_evidence(result, "certificate_history")
    return final_records


def _parse_ct_response(
    payload: Any,
    *,
    domain: str,
    source_key: str,
) -> List[Dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("Certificate Transparency response was not a list")
    records_by_fingerprint: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for item in payload[:MAX_CERTIFICATES]:
        if not isinstance(item, dict):
            continue
        if source_key == "certspotter":
            names_value = item.get("dns_names", [])
            if not isinstance(names_value, list):
                raise ValueError("CertSpotter dns_names field was malformed")
            name_values = _clean_certificate_names(
                "\n".join(str(value) for value in names_value),
                domain,
            )
            identifier = item.get("id")
            common_name = None
            issuer = None
            not_before = item.get("not_before")
            not_after = item.get("not_after")
            logged_at = None
        else:
            name_values = _clean_certificate_names(
                item.get("name_value", ""),
                domain,
            )
            identifier = item.get("id")
            common_name = item.get("common_name")
            issuer = item.get("issuer_name")
            not_before = item.get("not_before")
            not_after = item.get("not_after")
            logged_at = item.get("entry_timestamp")
        if not name_values:
            continue
        stable_identifier = (
            str(identifier).strip()
            if isinstance(identifier, (str, int))
            and not isinstance(identifier, bool)
            and str(identifier).strip()
            else None
        )
        record = {
            "id": _limited_text(stable_identifier),
            "common_name": _limited_text(common_name),
            "name_values": name_values,
            "issuer": _limited_text(issuer),
            "not_before": _limited_text(not_before),
            "not_after": _limited_text(not_after),
            "logged_at": _limited_text(logged_at),
        }
        certificate_hash = item.get("cert_sha256")
        if (
            isinstance(certificate_hash, str)
            and re.fullmatch(r"[0-9a-fA-F]{64}", certificate_hash.strip())
        ):
            fingerprint = ("sha256", certificate_hash.strip().lower())
        elif stable_identifier is not None:
            fingerprint = (
                source_key,
                "id",
                stable_identifier,
            )
        else:
            fingerprint = (
                "certificate",
                *sorted(name_values),
                str(record["common_name"] or "").lower(),
                str(record["issuer"] or "").lower(),
                str(record["not_before"] or ""),
                str(record["not_after"] or ""),
            )
        records_by_fingerprint.setdefault(fingerprint, record)
    return list(records_by_fingerprint.values())


def _ct_error_status(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, requests.Timeout)):
        return "timeout"
    if isinstance(exc, requests.HTTPError):
        status_code = getattr(exc.response, "status_code", None)
        return f"http_{status_code}" if status_code else "http_error"
    if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
        return "malformed_response"
    return "request_failure"


def _is_retryable_ct_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, requests.Timeout, requests.ConnectionError)):
        return True
    if isinstance(exc, requests.HTTPError):
        status_code = getattr(exc.response, "status_code", None)
        return status_code == 429 or (
            isinstance(status_code, int) and 500 <= status_code <= 599
        )
    return False


def _collect_ip_context(
    dns_result: Dict[str, Any],
    result: Dict[str, Any],
    deadline: float,
) -> None:
    addresses: List[str] = []
    records = dns_result.get("records", {})
    for record_type in ("A", "AAAA"):
        for value in records.get(record_type, []):
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
    addresses = addresses[:MAX_IP_ASN_LOOKUPS]
    timestamp = _utc_now()
    result["sources"]["ip_prefix"] = {
        "name": "RIPEstat network-info",
        "url": RIPE_NETWORK_INFO_URL,
        "status": "unavailable",
        "collected_at": timestamp,
    }
    result["sources"]["asn"] = {
        "name": "RIPEstat network-info",
        "url": RIPE_NETWORK_INFO_URL,
        "status": "unavailable",
        "collected_at": timestamp,
    }
    if not addresses:
        _mark_unavailable(result, "ip_prefix", "No DNS IP addresses were available")
        _mark_unavailable(result, "asn", "No DNS IP addresses were available")
        result["sources"]["ip_asn"] = {
            "name": "RIPEstat network-info",
            "url": RIPE_NETWORK_INFO_URL,
            "status": "unavailable",
            "collected_at": timestamp,
        }
        return

    for address in addresses:
        remaining = _remaining(deadline)
        if remaining <= MIN_REQUEST_BUDGET_SECONDS:
            result["infrastructure"].append({
                "ip": address,
                "prefix": None,
                "asns": [],
                "prefix_status": "unavailable",
                "asn_status": "unavailable",
                "source": "RIPEstat network-info",
            })
            continue
        request_timeout = min(remaining / 2, HTTP_TIMEOUT[1])
        if request_timeout <= 0:
            continue
        try:
            payload = _get_json(
                RIPE_NETWORK_INFO_URL,
                params={"resource": address},
                timeout=(
                    min(HTTP_TIMEOUT[0], remaining / 2),
                    request_timeout,
                ),
                max_bytes=MAX_RESPONSE_BYTES,
            )
            data = payload.get("data", {}) if isinstance(payload, dict) else {}
            if not isinstance(data, dict):
                data = {}
            prefix = _validate_prefix(data.get("prefix"), address)
            asns = _validated_asns(data.get("asns"))
            prefix_status = "available" if prefix else "unavailable"
            asn_status = "available" if asns else "unavailable"
            result["infrastructure"].append({
                "ip": address,
                "prefix": prefix,
                "asns": asns,
                "prefix_status": prefix_status,
                "asn_status": asn_status,
                "status": (
                    "available"
                    if prefix and asns
                    else "partial"
                    if prefix or asns
                    else "no_data"
                ),
                "source": "RIPEstat network-info",
            })
            if not prefix:
                _mark_unavailable(
                    result,
                    "ip_prefix",
                    f"No valid prefix returned for {address}",
                )
            if not asns:
                _mark_unavailable(
                    result,
                    "asn",
                    f"No ASN data returned for {address}",
                )
        except (
            requests.RequestException,
            TimeoutError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            result["infrastructure"].append({
                "ip": address,
                "prefix": None,
                "asns": [],
                "prefix_status": "unavailable",
                "asn_status": "unavailable",
                "status": "unavailable",
                "source": "RIPEstat network-info",
            })
            result["errors"].append({
                "source": "ip_asn",
                "message": _limited_text(str(exc)),
            })

    for source_key, field, item_status_key in (
        ("ip_prefix", "prefix", "prefix_status"),
        ("asn", "asns", "asn_status"),
    ):
        available = any(
            item.get(field)
            for item in result["infrastructure"]
        )
        statuses = [
            item.get(item_status_key)
            for item in result["infrastructure"]
        ]
        result["sources"][source_key]["status"] = (
            "available"
            if available and all(status == "available" for status in statuses)
            else "partial"
            if available
            else "unavailable"
        )
        if result["sources"][source_key]["status"] != "available":
            _mark_unavailable(
                result,
                source_key,
                f"No complete {source_key} data was returned",
            )
    result["sources"]["ip_asn"] = {
        "name": "RIPEstat network-info",
        "url": RIPE_NETWORK_INFO_URL,
        "status": _overall_status([
            result["sources"]["ip_prefix"]["status"],
            result["sources"]["asn"]["status"],
        ]),
        "collected_at": _utc_now(),
    }


def _get_json(
    url: str,
    *,
    params: Dict[str, str],
    timeout: Tuple[float, float],
    max_bytes: int,
) -> Any:
    with requests.get(
        url,
        params=params,
        headers={
            "Accept": "application/json",
            "User-Agent": "adaptive-phishing/2.0",
        },
        timeout=timeout,
        stream=True,
    ) as response:
        response.raise_for_status()
        chunks = []
        size = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("Public-data response exceeded the size limit")
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


def _clean_certificate_names(value: Any, domain: str) -> List[str]:
    if not isinstance(value, str):
        return []
    names = []
    for item in value.splitlines():
        hostname = _normalize_certificate_hostname(item)
        if hostname is None:
            continue
        if _is_domain_or_subdomain(hostname, domain) and hostname not in names:
            names.append(hostname)
        if len(names) >= MAX_SUBDOMAINS:
            break
    return names


def _subdomains_from_certificates(
    certificates: Iterable[Dict[str, Any]],
    domain: str,
) -> List[str]:
    subdomains = set()
    for certificate in certificates:
        for hostname in certificate.get("name_values", []):
            if hostname != domain and _is_domain_or_subdomain(hostname, domain):
                subdomains.add(hostname)
    return sorted(subdomains)[:MAX_SUBDOMAINS]


def _is_domain_or_subdomain(hostname: str, domain: str) -> bool:
    normalized_domain = _normalize_certificate_hostname(domain)
    normalized_hostname = _normalize_certificate_hostname(hostname)
    if normalized_domain is None or normalized_hostname is None:
        return False
    if normalized_hostname == normalized_domain:
        return True
    if len(normalized_hostname) > 253 or not normalized_hostname.endswith(
        f".{normalized_domain}"
    ):
        return False
    labels = normalized_hostname.split(".")
    return all(_LABEL_PATTERN.fullmatch(label) for label in labels)


def _normalize_certificate_hostname(value: str) -> Optional[str]:
    hostname = value.strip()
    if not hostname or any(ord(character) < 33 for character in hostname):
        return None
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if hostname.endswith(".."):
        return None
    if hostname.endswith("."):
        hostname = hostname[:-1]
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(hostname) > 253:
        return None
    labels = hostname.split(".")
    if not labels or any(not _LABEL_PATTERN.fullmatch(label) for label in labels):
        return None
    return hostname


def _parse_rdap_date(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _clean_string_list(value: Any, limit: int) -> List[str]:
    if not isinstance(value, list):
        return []
    return [
        cleaned
        for item in value[:limit]
        if (cleaned := _limited_text(item))
    ]


def _validate_prefix(value: Any, address: str) -> Optional[str]:
    try:
        network = ipaddress.ip_network(value, strict=False)
        return str(network) if ipaddress.ip_address(address) in network else None
    except (TypeError, ValueError):
        return None


def _validated_asns(value: Any) -> List[int]:
    if not isinstance(value, list):
        return []
    asns = []
    for item in value:
        if isinstance(item, int):
            asn = item
        elif isinstance(item, str):
            candidate = item.upper().removeprefix("AS")
            if not candidate.isdigit():
                continue
            asn = int(candidate)
        else:
            continue
        if 0 < asn <= 4_294_967_295 and asn not in asns:
            asns.append(asn)
        if len(asns) == 5:
            break
    return asns


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _overall_status(statuses: List[str]) -> str:
    if not statuses:
        return "unavailable"
    completed_statuses = {"available", "no_records"}
    if all(status in completed_statuses for status in statuses):
        if all(status == "no_records" for status in statuses):
            return "no_records"
        return "available"
    if any(status == "partial" for status in statuses):
        return "partial"
    if any(status == "available" for status in statuses):
        return "partial"
    return "unavailable"


def _mark_unavailable(
    result: Dict[str, Any],
    evidence: str,
    message: str,
) -> None:
    if evidence not in result["unavailable_evidence"]:
        result["unavailable_evidence"].append(evidence)
    if message:
        result["errors"].append({
            "source": evidence,
            "message": _limited_text(message),
        })


def _append_unavailable_evidence(
    result: Dict[str, Any],
    evidence: str,
) -> None:
    if evidence not in result["unavailable_evidence"]:
        result["unavailable_evidence"].append(evidence)


def _limited_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)[:MAX_TEXT_LENGTH]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
