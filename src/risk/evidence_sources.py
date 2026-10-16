"""Normalize existing intelligence-provider outputs for audit and arbitration."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping

from src.risk.models import Evidence, EvidenceDirection


_ALLOWED_STATUSES = {
    "available",
    "partial",
    "unknown",
    "unavailable",
    "error",
}

_SOURCE_DEFINITIONS = (
    ("url_normalization", "url_validation", "input_validation"),
    ("brand_identity", "brand_engine", "brand_identity"),
    ("threat_intelligence", "threat_intelligence", "threat_reputation"),
    ("dns", "dns", "network_infrastructure"),
    ("domain_registration", "domain", "registration"),
    ("tls", "tls", "transport_security"),
    ("domain_forensics", "domain_forensics", "historical_infrastructure"),
    ("typosquatting", "typosquatting", "identity_impersonation"),
    ("homograph", "homograph", "identity_impersonation"),
    ("machine_learning", "machine_learning", "model_support"),
    ("validated_case", "validated_case", "validated_case"),
)


def _valid_score(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False
    value = result.get("raw_model_score", result.get("phishing_probability"))
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0.0 <= value <= 1.0
    )


def _canonical_status(status: Any) -> str:
    if not isinstance(status, str):
        return "unknown"
    if status in {"known_phishing", "known_malware", "no_records"}:
        return "available"
    if status == "timeout":
        return "unavailable"
    if status in _ALLOWED_STATUSES:
        return status
    return "unknown"


def _source_status(name: str, result: Any) -> str:
    if name == "url_normalization":
        return "available"
    if name == "machine_learning":
        if isinstance(result, Mapping) and result.get("status") == "not_run":
            return "unknown"
        if isinstance(result, Mapping) and result.get("status") in {
            "unavailable",
            "error",
        }:
            return str(result["status"])
        return "available" if _valid_score(result) else "unavailable"
    if not isinstance(result, Mapping):
        return "unavailable"

    if name == "brand_identity":
        return "available"
    if name in {"typosquatting", "homograph"}:
        return "available"
    if name == "validated_case":
        return "available" if result else "unknown"
    if name == "domain_registration":
        status = result.get("retrieval_status", result.get("status"))
    elif name == "dns":
        status = result.get("status")
    elif name == "tls":
        status = result.get("status")
    elif name == "domain_forensics":
        status = result.get("status")
    else:
        status = result.get("status")

    if name == "threat_intelligence":
        provider_results = result.get("sources")
        statuses = [
            item.get("status")
            for item in provider_results
            if isinstance(item, Mapping)
            and isinstance(item.get("status"), str)
        ] if isinstance(provider_results, list) else []
        if statuses:
            if all(value == "error" for value in statuses):
                return "error"
            if any(value == "error" for value in statuses):
                return "partial"
            if any(
                value in {"known_phishing", "known_malware"}
                for value in statuses
            ):
                return "available"
            if all(value == "unknown" for value in statuses):
                return "unknown"
    return _canonical_status(status)


def _compact_observed(name: str, result: Any) -> Any:
    if not isinstance(result, Mapping):
        return result

    if name == "dns":
        records = result.get("records")
        record_counts = {
            record_type: len(values)
            for record_type, values in records.items()
            if isinstance(values, list)
        } if isinstance(records, Mapping) else {}
        return {
            "status": result.get("status"),
            "hostname": result.get("hostname"),
            "record_counts": record_counts,
            "record_status": result.get("interpretations", {}).get(
                "record_status",
                {},
            ) if isinstance(result.get("interpretations"), Mapping) else {},
            "null_mx": result.get("interpretations", {}).get(
                "null_mx",
                False,
            ) if isinstance(result.get("interpretations"), Mapping) else False,
        }
    if name == "domain_forensics":
        sources = result.get("sources")
        registration = result.get("registration")
        registration_data = (
            registration.get("data")
            if isinstance(registration, Mapping)
            and isinstance(registration.get("data"), Mapping)
            else {}
        )
        return {
            "domain": result.get("domain"),
            "status": result.get("status"),
            "collected_at": result.get("collected_at"),
            "registration": {
                key: registration_data.get(key)
                for key in (
                    "creation_date",
                    "expiry_date",
                    "registrar",
                    "domain_age_days",
                )
                if key in registration_data
            },
            "certificate_history_status": result.get(
                "certificate_history_status",
            ),
            "certificate_history_count": len(
                result.get("certificate_history", [])
            ) if isinstance(result.get("certificate_history"), list) else 0,
            "subdomain_discovery_status": result.get(
                "subdomain_discovery_status",
            ),
            "subdomain_count": len(
                result.get("subdomains", [])
            ) if isinstance(result.get("subdomains"), list) else 0,
            "infrastructure_count": len(
                result.get("infrastructure", [])
            ) if isinstance(result.get("infrastructure"), list) else 0,
            "sources": {
                key: value.get("status", "unknown")
                for key, value in sources.items()
                if isinstance(value, Mapping)
            } if isinstance(sources, Mapping) else {},
            "unavailable_evidence": result.get("unavailable_evidence", []),
        }
    if name == "threat_intelligence":
        sources = result.get("sources")
        return {
            "status": result.get("status"),
            "known_phishing": result.get("known_phishing"),
            "known_malware": result.get("known_malware"),
            "phishing_sources": result.get("phishing_sources", []),
            "malware_sources": result.get("malware_sources", []),
            "sources": [
                {
                    "source": item.get("source"),
                    "status": item.get("status"),
                }
                for item in sources
                if isinstance(item, Mapping)
            ] if isinstance(sources, list) else [],
        }
    if name == "tls":
        certificate = result.get("certificate")
        selected_certificate = {
            key: certificate[key]
            for key in (
                "hostname_match",
                "san_matched",
                "issuer",
                "valid_from",
                "valid_until",
                "observed_at",
                "valid_at_observation",
                "validity_status",
                "validation_status",
            )
            if isinstance(certificate, Mapping) and key in certificate
        }
        signals = result.get("signals")
        return {
            "status": result.get("status"),
            "source": result.get("source"),
            "collected_at": result.get("collected_at"),
            "certificate": selected_certificate,
            "signals": signals[:10] if isinstance(signals, list) else [],
        }
    if name == "machine_learning":
        contributions = result.get("top_feature_contributions")
        valid_score = _valid_score(result)
        raw_score = result.get("raw_model_score")
        legacy_score = result.get("phishing_probability")
        return {
            "raw_model_score": raw_score if valid_score else None,
            "phishing_probability": (
                legacy_score
                if isinstance(legacy_score, (int, float))
                and not isinstance(legacy_score, bool)
                and 0.0 <= legacy_score <= 1.0
                else None
            ),
            "score_valid": valid_score,
            "score_semantics": result.get("score_semantics"),
            "top_feature_contributions": (
                contributions[:5] if isinstance(contributions, list) else []
            ),
        }
    fields_by_source = {
        "url_normalization": (
            "hostname",
            "registered_domain",
            "scheme",
            "port",
        ),
        "brand_identity": (
            "hostname",
            "registered_domain",
            "detected_brands",
            "registered_brand_matches",
            "official_brand_matches",
            "verified_hosted_brand_matches",
            "unmatched_brands",
            "brand",
            "official_domain",
            "brand_match_method",
            "brand_mismatch",
        ),
        "threat_intelligence": (),
        "dns": (),
        "domain_registration": (
            "status",
            "retrieval_status",
            "registration_status",
            "creation_date",
            "expiry_date",
            "domain_age_days",
            "domain_age_known",
            "registrar",
            "collected_at",
        ),
        "tls": (),
        "domain_forensics": (),
        "typosquatting": (
            "registered_domain",
            "possible_typosquatting",
            "is_typosquat",
            "matched_brand",
            "target",
            "similarity",
            "attack_type",
        ),
        "homograph": (
            "is_deceptive",
            "mixed_scripts",
            "has_confusable_characters",
            "has_punycode",
        ),
        "machine_learning": (),
        "validated_case": (
            "domain",
            "decision",
            "reason",
        ),
    }
    return {
        key: result[key]
        for key in fields_by_source[name]
        if key in result
    }


def _provenance(result: Any, name: str) -> Dict[str, Any]:
    provenance: Dict[str, Any] = {"provider": name}
    if not isinstance(result, Mapping):
        return provenance
    for key in ("source", "source_url", "source_urls", "collected_at", "observed_at"):
        if key in result and result[key] is not None:
            provenance[key] = result[key]
    sources = result.get("sources")
    if isinstance(sources, list):
        provenance["sources"] = [
            {
                "source": item.get("source"),
                "status": item.get("status"),
            }
            for item in sources
            if isinstance(item, Mapping)
        ]
    elif isinstance(sources, Mapping):
        provenance["sources"] = {
            key: (
                value.get("status", "unknown")
                if isinstance(value, Mapping)
                else str(value)[:128]
            )
            for key, value in sources.items()
        }
    return provenance


def _errors(result: Any) -> list[Any]:
    if not isinstance(result, Mapping):
        return []
    errors = result.get("errors")
    if isinstance(errors, list):
        normalized_errors = []
        for error in errors[:10]:
            if isinstance(error, Mapping):
                normalized_errors.append({
                    key: str(error[key])[:256]
                    for key in (
                        "source",
                        "type",
                        "status",
                        "record_type",
                        "message",
                        "error",
                    )
                    if key in error and error[key] is not None
                })
            else:
                normalized_errors.append({"message": str(error)[:256]})
        return normalized_errors
    if result.get("error") is not None:
        return [{"message": str(result["error"])[:256]}]
    return []


def _source_envelope(
    source: str,
    status: str,
    observed: Any,
    findings: list[Dict[str, Any]],
    category: str,
    reliability: float | None,
    provenance: Dict[str, Any],
    decision_impact: bool,
    errors: list[Any],
    raw_observations: Any,
) -> Dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "observed": observed,
        "findings": findings,
        "evidence_category": category,
        "reliability": reliability,
        "provenance": provenance,
        "decision_impact": decision_impact,
        "errors": errors,
        "raw_observations": raw_observations,
    }


def normalize_evidence_sources(
    normalized_url: Mapping[str, Any],
    component_results: Mapping[str, Any],
    forensic_result: Mapping[str, Any],
    evidence: Iterable[Evidence],
    *,
    decision_basis: str,
) -> Dict[str, Dict[str, Any]]:
    """Create one normalized, provenance-carrying envelope per evidence source.

    `observed` is a bounded, source-specific summary suitable for compact
    responses. Full provider values remain in `raw_observations` for detailed
    responses and audit.
    """
    results = dict(component_results)
    evidence_items = tuple(evidence)
    results["url_validation"] = normalized_url
    results["domain_forensics"] = forensic_result
    if "registration" in forensic_result and isinstance(
        forensic_result.get("registration"), Mapping
    ):
        registration = dict(forensic_result["registration"])
        data = registration.get("data")
        if isinstance(data, Mapping):
            registration.update(data)
        results["domain"] = registration

    source_evidence: Dict[str, list[Evidence]] = {
        raw_key: []
        for _, raw_key, _ in _SOURCE_DEFINITIONS
    }
    source_evidence["brand_engine"] = []
    source_evidence["machine_learning"] = []
    source_evidence["domain"] = []
    for item in evidence_items:
        if item.source == "brand_engine":
            source_evidence["brand_engine"].append(item)
        elif item.source == "ml_xgboost":
            source_evidence["machine_learning"].append(item)
        elif item.source == "domain_intelligence":
            source_evidence["domain"].append(item)
        else:
            source_evidence.setdefault(item.source, []).append(item)

    normalized: Dict[str, Dict[str, Any]] = {}
    for public_name, raw_key, category in _SOURCE_DEFINITIONS:
        result = results.get(raw_key)
        findings = source_evidence.get(raw_key, [])
        normalized_findings = [
            {
                "signal": item.signal,
                "value": item.value,
                "direction": item.direction.value,
                "strength": item.strength.name.lower(),
                "reliability": item.reliability,
                "reason": item.reason,
            }
            for item in findings
        ]
        domain_age_corroborates_ml = (
            public_name == "domain_registration"
            and decision_basis == "corroborated_ml_suspicion"
            and not any(
                item.source != "ml_xgboost"
                and item.direction == EvidenceDirection.MALICIOUS
                for item in evidence_items
            )
            and isinstance(result, Mapping)
            and isinstance(result.get("domain_age_days"), int)
            and not isinstance(result.get("domain_age_days"), bool)
            and 0 <= result["domain_age_days"] < 30
        )
        if domain_age_corroborates_ml:
            normalized_findings.append({
                "signal": "recent_registration_corroborates_ml",
                "value": result["domain_age_days"],
                "direction": "neutral",
                "strength": "contextual",
                "reliability": None,
                "reason": (
                    "Recent registration only contributed as context alongside "
                    "a separate malicious signal; domain age alone is not a "
                    "malicious finding."
                ),
            })
        normalized[public_name] = {
            "source": public_name,
            "status": _source_status(public_name, result),
            "observed": _compact_observed(public_name, result),
            "findings": normalized_findings,
            "evidence_category": category,
            "reliability": max(
                (item.reliability for item in findings),
                default=None,
            ),
            "provenance": _provenance(result, public_name),
            "decision_impact": any(
                item.direction != EvidenceDirection.NEUTRAL
                for item in findings
            ) or domain_age_corroborates_ml,
            "errors": _errors(result),
            "raw_observations": result,
        }

    threat_result = component_results.get("threat_intelligence")
    provider_results = (
        threat_result.get("sources")
        if isinstance(threat_result, Mapping)
        else None
    )
    provider_keys = {
        "phishtank": "phishtank",
        "openphish": "openphish",
        "urlhaus": "urlhaus",
    }
    aggregate_threat_evidence = source_evidence.get("threat_intelligence", [])
    if isinstance(provider_results, list):
        for provider_result in provider_results:
            if not isinstance(provider_result, Mapping):
                continue
            provider = provider_result.get("source")
            if not isinstance(provider, str):
                continue
            provider_name = provider_keys.get(provider.lower())
            if provider_name is None:
                continue
            provider_status = _canonical_status(provider_result.get("status"))
            provider_raw_status = provider_result.get("status")
            matches = (
                isinstance(provider_raw_status, str)
                and provider_raw_status in {
                    "known_phishing",
                    "known_malware",
                }
            )
            provider_findings = []
            matched_evidence = next(
                (
                    item for item in aggregate_threat_evidence
                    if item.direction == EvidenceDirection.MALICIOUS
                    and item.signal == provider_raw_status
                ),
                None,
            )
            if matches:
                provider_findings.append({
                    "signal": provider_raw_status,
                    "value": True,
                    "direction": "malicious",
                    "strength": (
                        matched_evidence.strength.name.lower()
                        if matched_evidence is not None
                        else "unknown"
                    ),
                    "reliability": (
                        matched_evidence.reliability
                        if matched_evidence is not None
                        else None
                    ),
                    "reason": (
                        f"{provider} reported a confirmed threat match."
                    ),
                })
            normalized[provider_name] = _source_envelope(
                source=provider_name,
                status=provider_status,
                observed={
                    "source": provider,
                    "status": provider_raw_status,
                    "matched": matches,
                },
                findings=provider_findings,
                category="threat_reputation",
                reliability=(
                    matched_evidence.reliability
                    if matched_evidence is not None
                    else None
                ),
                provenance={"provider": provider},
                decision_impact=(
                    matches and matched_evidence is not None
                ),
                errors=_errors(provider_result),
                raw_observations=provider_result,
            )

    source_metadata = forensic_result.get("sources")
    if not isinstance(source_metadata, Mapping):
        source_metadata = {}
    unavailable = forensic_result.get("unavailable_evidence")
    unavailable_names = (
        {value for value in unavailable if isinstance(value, str)}
        if isinstance(unavailable, list)
        else set()
    )
    forensic_components = (
        (
            "certificate_transparency",
            "certificate_history_status",
            "certificate_history",
            "historical_infrastructure",
        ),
        (
            "subdomain_discovery",
            "subdomain_discovery_status",
            "subdomain_discovery",
            "domain_context",
        ),
        (
            "ip_prefix",
            "ip_prefix",
            "ip_prefix",
            "network_infrastructure",
        ),
        (
            "asn",
            "asn",
            "asn",
            "network_infrastructure",
        ),
    )
    infrastructure = forensic_result.get("infrastructure")
    if not isinstance(infrastructure, list):
        infrastructure = []
    certificates = forensic_result.get("certificate_history")
    if not isinstance(certificates, list):
        certificates = []
    subdomains = forensic_result.get("subdomains")
    if not isinstance(subdomains, list):
        subdomains = []
    for source_name, status_key, unavailable_key, category in forensic_components:
        metadata = source_metadata.get(source_name)
        if not isinstance(metadata, Mapping):
            metadata = {}
        observed_status = forensic_result.get(status_key)
        if observed_status is None:
            observed_status = metadata.get("status")
        if observed_status is None and unavailable_key in unavailable_names:
            observed_status = "unavailable"
        status = _canonical_status(observed_status)
        if source_name == "certificate_transparency":
            observed = {
                "status": observed_status,
                "certificate_count": len(certificates),
            }
            raw_observations = {
                "source": metadata,
                "certificate_history": certificates,
            }
            finding_value = {"certificate_count": len(certificates)}
            explanation = (
                "Certificate history is historical context, not proof of "
                "legitimacy or maliciousness."
            )
        elif source_name == "subdomain_discovery":
            observed = {
                "status": observed_status,
                "subdomain_count": len(subdomains),
            }
            raw_observations = {
                "source": metadata,
                "subdomains": subdomains,
            }
            finding_value = {"subdomain_count": len(subdomains)}
            explanation = (
                "Discovered subdomains are contextual and do not indicate "
                "maliciousness by count."
            )
        elif source_name == "ip_prefix":
            prefixes = sorted({
                item.get("prefix")
                for item in infrastructure
                if isinstance(item, Mapping)
                and isinstance(item.get("prefix"), str)
            })
            observed = {
                "status": observed_status,
                "prefixes": prefixes[:50],
            }
            raw_observations = {
                "source": metadata,
                "infrastructure": infrastructure,
            }
            finding_value = {"prefixes": prefixes[:50]}
            explanation = (
                "Network prefixes identify infrastructure, not reputation."
            )
        else:
            asns = sorted({
                asn
                for item in infrastructure
                if isinstance(item, Mapping)
                for asn in (
                    item.get("asns")
                    if isinstance(item.get("asns"), list)
                    else []
                )
                if isinstance(asn, int) and not isinstance(asn, bool)
            })
            observed = {
                "status": observed_status,
                "asns": asns,
            }
            raw_observations = {
                "source": metadata,
                "infrastructure": infrastructure,
            }
            finding_value = {"asns": asns}
            explanation = (
                "ASN attribution identifies infrastructure, not reputation."
            )
        provenance = {
            "provider": metadata.get("name", source_name),
            "source": metadata.get("source", source_name),
            "collected_at": forensic_result.get("collected_at"),
        }
        for key in ("source_url", "source_urls"):
            if key in metadata:
                provenance[key] = metadata[key]
        component_errors = metadata.get("errors")
        if not isinstance(component_errors, list):
            aliases = {
                "certificate_transparency": (
                    "certificate_transparency",
                    "crtsh",
                    "crt.sh",
                    "certspotter",
                ),
                "ip_prefix": ("ip_prefix", "ripestat", "prefix"),
                "asn": ("asn", "ripestat"),
            }.get(source_name, (source_name,))
            component_errors = [
                error
                for error in (
                    forensic_result.get("errors")
                    if isinstance(forensic_result.get("errors"), list)
                    else []
                )
                if isinstance(error, Mapping)
                and any(
                    alias in str(error.get("source", "")).lower()
                    for alias in aliases
                )
            ]
        normalized[source_name] = _source_envelope(
            source=source_name,
            status=status,
            observed=observed,
            findings=[{
                "signal": f"{source_name}_observed",
                "value": finding_value,
                "direction": "neutral",
                "strength": "contextual",
                "reliability": None,
                "reason": explanation,
            }],
            category=category,
            reliability=None,
            provenance=provenance,
            decision_impact=False,
            errors=_errors({"errors": component_errors}),
            raw_observations=raw_observations,
        )
    return normalized
