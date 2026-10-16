from dataclasses import dataclass, field
from enum import Enum
import math
import re
from typing import Any, List, Dict
from urllib.parse import urlsplit

from src.intelligence.url_normalizer import normalize_url
from src.risk.policy import DEFAULT_RISK_POLICY

class EvidenceDirection(Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    NEUTRAL = "neutral"

class EvidenceStrength(Enum):
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    CRITICAL = 4

class DecisionState(Enum):
    SAFE = "safe"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALWARE = "malware"

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Evidence:
    source: str
    signal: str
    value: Any
    strength: EvidenceStrength
    reliability: float  # 0.0 to 1.0
    direction: EvidenceDirection
    reason: str

@dataclass
class Override:
    override_type: str
    reason: str
    affected_signal: str

@dataclass
class FinalDecision:
    url: str
    decision: DecisionState
    risk_level: RiskLevel
    risk_score: int
    confidence: int  # 0 to 100
    decision_basis: str
    evidence: List[Evidence] = field(default_factory=list)
    malicious_signals: List[Evidence] = field(default_factory=list)
    benign_signals: List[Evidence] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    overrides: List[Override] = field(default_factory=list)
    machine_learning: Dict[str, Any] = field(default_factory=dict)
    threat_intelligence: Dict[str, Any] = field(default_factory=dict)
    identity: Dict[str, Any] = field(default_factory=dict)
    domain: Dict[str, Any] = field(default_factory=dict)
    dns: Dict[str, Any] = field(default_factory=dict)
    tls: Dict[str, Any] = field(default_factory=dict)
    rag: Dict[str, Any] = field(default_factory=dict)
    evidence_agreement: str = "insufficient"
    evidence_quality: str = "unknown"
    reasons: List[str] = field(default_factory=list)
    recommended_action: str = "allow"
    domain_forensics: Dict[str, Any] = field(default_factory=dict)
    collection_details: Dict[str, Any] = field(default_factory=dict)
    risk_score_breakdown: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_details: bool = False) -> Dict[str, Any]:
        """Serialize a compact API response; optionally include forensic raw data."""
        normalized = normalize_url(self.url)
        raw_evidence = self.evidence
        identity_evidence = self._identity_output(raw_evidence)
        ml_raw_score = self._ml_raw_score()
        domain = self.domain if isinstance(self.domain, dict) else {}
        dns = self.dns if isinstance(self.dns, dict) else {}
        tls = self.tls if isinstance(self.tls, dict) else {}
        forensic = self.domain_forensics if isinstance(
            self.domain_forensics, dict
        ) else {}
        threats = self._compact_threat_intelligence()
        dns_records = dns.get("records")
        if not isinstance(dns_records, dict):
            dns_records = {}
        dns_interpretations = dns.get("interpretations")
        if not isinstance(dns_interpretations, dict):
            dns_interpretations = {}
        record_status = dns_interpretations.get("record_status", {})
        if not isinstance(record_status, dict):
            record_status = {}
        dns_status = dns.get("status", "unknown")
        if dns_status == "no_records" and any(
            status == "timeout" for status in record_status.values()
        ):
            dns_status = "partial"

        tls_certificate = tls.get("certificate")
        if not isinstance(tls_certificate, dict):
            tls_certificate = {}
        try:
            is_https = urlsplit(self.url if "://" in self.url else f"https://{self.url}").scheme.lower() == "https"
        except ValueError:
            is_https = False

        summary_identity = {
            "brand": identity_evidence.get("brand"),
            "official_domain": identity_evidence.get("official_domain", False),
        }
        analysis_summary = self._decision_message(summary_identity)
        forensic_summary = self._compact_forensics(forensic)
        reasoning = self._compact_reasoning(forensic)
        probability = (
            round(float(ml_raw_score), 6)
            if isinstance(ml_raw_score, (int, float))
            and not isinstance(ml_raw_score, bool)
            else None
        )
        fallback = self.collection_details.get("decision_fallback", {})
        if not isinstance(fallback, dict):
            fallback = {}
        ml_used = fallback.get("ml_used") is True
        support_direction = (
            EvidenceDirection.BENIGN
            if self.decision == DecisionState.SAFE
            else EvidenceDirection.MALICIOUS
            if self.decision in {
                DecisionState.PHISHING,
                DecisionState.MALWARE,
                DecisionState.SUSPICIOUS,
            }
            else None
        )

        def signal_details(direction: EvidenceDirection) -> list[Dict[str, Any]]:
            return [
                {
                    "source": item.source,
                    "signal": item.signal,
                    "value": item.value,
                    "reason": item.reason,
                }
                for item in raw_evidence
                if item.direction == direction
            ]

        normalized_sources = self.collection_details.get(
            "normalized_evidence_sources",
            {},
        )
        if not isinstance(normalized_sources, dict):
            normalized_sources = {}
        unavailable_sources = sorted(
            source
            for source, result in normalized_sources.items()
            if isinstance(result, dict)
            and result.get("status") in {"unavailable", "error"}
        )

        response = {
            "url": self.url,
            "analysis": {
                "decision": self.decision.value,
                "risk_level": self.risk_level.value,
                "confidence": float(self.confidence),
                "decision_basis": self.decision_basis,
                "recommended_action": self.recommended_action,
                "summary": analysis_summary,
                "independent_evidence_status": fallback.get(
                    "independent_evidence_status",
                    "unknown",
                ),
                "ml_used": ml_used,
                "ml_fallback_reason": fallback.get("ml_fallback_reason"),
                "supporting_signals": (
                    signal_details(support_direction)
                    if support_direction is not None
                    else []
                ),
                "contradicting_signals": (
                    signal_details(
                        EvidenceDirection.MALICIOUS
                        if support_direction == EvidenceDirection.BENIGN
                        else EvidenceDirection.BENIGN
                    )
                    if support_direction is not None
                    else signal_details(EvidenceDirection.MALICIOUS)
                    + signal_details(EvidenceDirection.BENIGN)
                ),
                "unavailable_sources": unavailable_sources,
            },
            "scores": {
                "ml_phishing_probability": probability,
                "ml_raw_score": probability,
                "ml_score_semantics": (
                    "Legacy field name; value is the raw XGBoost "
                    "predict_proba output, not a validated calibrated "
                    "probability"
                ),
                "final_risk_score": self.risk_score,
                "final_risk_score_explanation": (
                    self.risk_score_breakdown
                    or {
                        "risk_increasing_evidence_points": None,
                        "risk_mitigating_evidence_points": None,
                        "net_before_clamp": None,
                        "final_score": self.risk_score,
                        "meaning": (
                            "Weighted evidence points, not a probability. "
                            "A zero score does not mean zero model suspicion."
                        ),
                    }
                ),
                "score_type": "post_arbitration_weighted_risk_points",
                "score_range": (
                    "0-100 weighted points; not a probability; zero means "
                    "the clamped net evidence weight is non-positive"
                ),
            },
            "identity": {
                "registered_domain": normalized.get("registered_domain"),
                "hostname": normalized.get("hostname"),
                "identity_status": identity_evidence.get(
                    "identity_status",
                    "unknown",
                ),
                "detected_brand": identity_evidence.get("brand"),
                "official_domain": identity_evidence.get("official_domain", False),
                "brand_mismatch": identity_evidence.get("brand_mismatch", False),
                "typosquatting": identity_evidence.get(
                    "_typosquat_detected",
                    False,
                ),
                "homograph": identity_evidence.get(
                    "_homograph_detected",
                    False,
                ),
                "punycode": identity_evidence.get("_punycode_detected", False),
                "mixed_script": identity_evidence.get(
                    "_homograph_detected",
                    False,
                ),
            },
            "threat_intelligence": threats,
            "domain_intelligence": {
                "status": domain.get("status", "unknown"),
                "age_days": domain.get("domain_age_days"),
                "creation_date": domain.get("creation_date"),
                "expiry_date": domain.get("expiry_date"),
                "registrar": domain.get("registrar"),
            },
            "dns": {
                "status": dns_status,
                "a_count": self._list_count(dns_records.get("A")),
                "aaaa_count": self._list_count(dns_records.get("AAAA")),
                "mx_count": self._list_count(dns_records.get("MX")),
                "ns_count": self._list_count(dns_records.get("NS")),
                "cname_count": self._list_count(dns_records.get("CNAME")),
                "txt_count": self._list_count(dns_records.get("TXT")),
                "null_mx": dns_interpretations.get("null_mx", False),
                "signals": self._compact_dns_signals(dns),
                "errors": self._compact_errors(dns.get("errors")),
            },
            "tls": {
                "status": tls.get("status", "unknown"),
                "source": tls.get("source", "tls_handshake"),
                "collected_at": tls.get("collected_at"),
                "https": is_https,
                "hostname_match": tls_certificate.get("hostname_match"),
                "san_matched": tls_certificate.get("san_matched"),
                "issuer": tls_certificate.get("issuer"),
                "valid_from": tls_certificate.get("valid_from"),
                "valid_until": tls_certificate.get("valid_until"),
                "certificate_observed_at": tls_certificate.get("observed_at"),
                "valid_at_observation": tls_certificate.get(
                    "valid_at_observation"
                ),
                "validity_status": tls_certificate.get(
                    "validity_status",
                    "unknown",
                ),
                "validation_status": tls_certificate.get(
                    "validation_status",
                    "unknown",
                ),
            },
            "domain_forensics": forensic_summary,
            "evidence_sources": {
                source: {
                    key: value
                    for key, value in result.items()
                    if key != "raw_observations"
                }
                for source, result in (
                    self.collection_details.get(
                        "normalized_evidence_sources",
                        {},
                    ).items()
                    if isinstance(
                        self.collection_details.get(
                            "normalized_evidence_sources",
                        ),
                        dict,
                    )
                    else []
                )
            },
            "reasoning": reasoning,
            "rag": {
                "status": self.rag.get("status", "unavailable"),
                "summary": self.rag.get("investigation"),
            },
            "metadata": {
                "engine": "Adaptive Evidence Risk Engine",
                "version": "2.0",
                "schema_version": "2.1",
                "confidence_semantics": (
                    "Heuristic 10-100 evidence-support measure; not a "
                    "calibrated probability"
                ),
                "ml_thresholds": {
                    "review": DEFAULT_RISK_POLICY.ml_review_threshold,
                    "strong": DEFAULT_RISK_POLICY.ml_strong_threshold,
                    "benign": DEFAULT_RISK_POLICY.ml_benign_threshold,
                    "status": "provisional; configurable via RISK_ML_* variables",
                },
            },
        }
        if include_details:
            response["details"] = {
                "domain_forensics": forensic.get("raw", {}),
                "evidence_sources": {
                    source: (
                        {
                            **{
                                key: value
                                for key, value in result.items()
                                if key != "raw_observations"
                            },
                            "raw_observations_ref": (
                                "details.domain_forensics"
                            ),
                        }
                        if source == "domain_forensics"
                        else result
                    )
                    for source, result in (
                        self.collection_details.get(
                            "normalized_evidence_sources",
                            {},
                        ).items()
                        if isinstance(
                            self.collection_details.get(
                                "normalized_evidence_sources",
                            ),
                            dict,
                        )
                        else []
                    )
                },
            }
        return response

    def to_combined_dict(
        self,
        include_details: bool = False,
    ) -> Dict[str, Any]:
        """Backward-compatible method name for the canonical API response."""
        return self.to_dict(include_details=include_details)

    def _ml_raw_score(self) -> Any:
        ml_result = self.collection_details.get("machine_learning")
        if isinstance(ml_result, dict):
            probability = ml_result.get(
                "raw_model_score",
                ml_result.get("phishing_probability"),
            )
            if (
                isinstance(probability, (int, float))
                and not isinstance(probability, bool)
                and math.isfinite(probability)
                and 0 <= probability <= 1
            ):
                return probability
        return next(
            (
                item.value
                for item in self.evidence
                if item.source == "ml_xgboost"
                and item.signal == "phishing_probability"
                and isinstance(item.value, (int, float))
                and not isinstance(item.value, bool)
                and math.isfinite(item.value)
                and 0 <= item.value <= 1
            ),
            None,
        )

    def _compact_threat_intelligence(self) -> Dict[str, Any]:
        result = self.collection_details.get("threat_intelligence")
        if not isinstance(result, dict):
            result = {}
        source_results = result.get("sources", [])
        source_statuses = {
            item.get("source"): item.get("status")
            for item in source_results
            if isinstance(item, dict)
        } if isinstance(source_results, list) else {}
        status = result.get("status")
        if status not in {
            "known_phishing",
            "known_malware",
            "error",
            "unknown",
        }:
            status = self._threat_intelligence_output(self.evidence)["status"]
        return {
            "status": status,
            "known_phishing": bool(
                result.get("known_phishing")
                or status == "known_phishing"
            ),
            "known_malware": bool(
                result.get("known_malware")
                or status == "known_malware"
            ),
            "sources": {
                "phishtank": source_statuses.get("phishtank", status),
                "openphish": source_statuses.get("openphish", status),
                "urlhaus": source_statuses.get("urlhaus", status),
            },
        }

    @staticmethod
    def _list_count(value: Any) -> int:
        return len(value) if isinstance(value, list) else 0

    @staticmethod
    def _compact_dns_signals(dns: Dict[str, Any]) -> List[Dict[str, Any]]:
        signals = dns.get("signals")
        if not isinstance(signals, list):
            return []
        return [
            {
                "signal": item.get("signal"),
                "interpretation": item.get("interpretation"),
            }
            for item in signals[:10]
            if isinstance(item, dict)
        ]

    @staticmethod
    def _compact_errors(errors: Any, limit: int = 10) -> List[Dict[str, Any]]:
        if not isinstance(errors, list):
            return []
        compact = []
        for error in errors[:limit]:
            if isinstance(error, dict):
                compact.append({
                    key: str(value)[:256]
                    for key, value in error.items()
                    if key in {"source", "type", "status", "record_type", "message", "error"}
                    and value is not None
                })
            else:
                compact.append({"message": str(error)[:256]})
        return compact

    @classmethod
    def _compact_forensics(cls, forensic: Dict[str, Any]) -> Dict[str, Any]:
        raw = forensic.get("raw")
        if not isinstance(raw, dict):
            raw = {}
        sources = raw.get("sources")
        if not isinstance(sources, dict):
            sources = forensic.get("sources", {})
        if not isinstance(sources, dict):
            sources = {}
        infrastructure = raw.get("infrastructure")
        if not isinstance(infrastructure, list):
            infrastructure = []
        registration = raw.get("registration")
        if not isinstance(registration, dict):
            registration = {}
        unavailable = raw.get("unavailable_evidence")
        if not isinstance(unavailable, list):
            unavailable = forensic.get("unknown_evidence", [])
        if not isinstance(unavailable, list):
            unavailable = []
        unique_asns = sorted({
            asn
            for item in infrastructure
            if isinstance(item, dict)
            for asn in (
                item.get("asns")
                if isinstance(item.get("asns"), list)
                else []
            )
            if isinstance(asn, int) and not isinstance(asn, bool)
        })
        findings = forensic.get("findings")
        compact_findings = []
        if isinstance(findings, list):
            for finding in findings[:20]:
                if not isinstance(finding, dict):
                    continue
                compact_findings.append({
                    key: finding.get(key)
                    for key in (
                        "name",
                        "interpretation",
                        "importance",
                        "evidence_role",
                        "source",
                        "influenced_decision",
                    )
                    if key in finding
                })
        subdomains = raw.get("subdomains")
        certificates = raw.get("certificate_history")
        return {
            "status": forensic.get("status", raw.get("status", "unavailable")),
            "subdomain_count": cls._list_count(subdomains),
            "certificate_history_count": cls._list_count(certificates),
            "infrastructure_ip_count": len({
                item.get("ip")
                for item in infrastructure
                if isinstance(item, dict) and item.get("ip")
            }),
            "unique_asns": unique_asns,
            "registration_status": registration.get(
                "retrieval_status",
                registration.get("status", "unavailable"),
            ),
            "registration_state": registration.get(
                "registration_status",
                "unknown",
            ),
            "certificate_history_status": raw.get(
                "certificate_history_status",
                "unavailable",
            ),
            "subdomain_discovery_status": raw.get(
                "subdomain_discovery_status",
                "unavailable",
            ),
            "sources": {
                name: item.get("status", "unknown")
                for name, item in sources.items()
                if isinstance(item, dict)
            },
            "findings": compact_findings,
            "suspicious_signals": (
                forensic.get("suspicious_signals", [])
                if isinstance(forensic.get("suspicious_signals"), list)
                else []
            ),
            "errors": cls._compact_errors(forensic.get("errors")),
            "unavailable_evidence": unavailable,
        }

    def _compact_reasoning(self, forensic: Dict[str, Any]) -> Dict[str, Any]:
        positives = [
            {
                "signal": item.signal,
                "source": item.source,
                "description": item.reason,
            }
            for item in self.benign_signals
            if item.source != "threat_intelligence"
            and item.signal != "tls_hostname_verified"
        ]
        negatives = [
            {
                "signal": item.signal,
                "source": item.source,
                "description": item.reason,
            }
            for item in self.evidence
            if item.direction == EvidenceDirection.MALICIOUS
        ]
        contradictions = []
        forensic_contradictions = forensic.get("contradictions")
        if isinstance(forensic_contradictions, list):
            contradictions.extend(
                item for item in forensic_contradictions
                if isinstance(item, dict)
            )
        known_descriptions = {
            item.get("description")
            for item in contradictions
            if isinstance(item, dict)
        }
        for description in self.contradictions:
            if description not in known_descriptions:
                contradictions.append({
                    "type": "evidence_conflict",
                    "description": description,
                    "resolution": "retained_for_decision_review",
                })
                known_descriptions.add(description)
        return {
            "positive_signals": positives,
            "negative_signals": negatives,
            "contradictions": contradictions,
            "evidence_agreement": self.evidence_agreement,
            "evidence_quality": self.evidence_quality,
            "evidence_coverage": self._evidence_coverage(),
            "contextual_observations": self._contextual_observations(forensic),
            "risk_score_explanation": (
                self.risk_score_breakdown
                or {
                    "final_score": self.risk_score,
                    "meaning": (
                        "Weighted evidence points, not a probability. "
                        "A zero score does not mean zero model suspicion."
                    ),
                }
            ),
        }

    def _evidence_coverage(self) -> Dict[str, Any]:
        machine_learning = self.collection_details.get("machine_learning")
        ml_available = isinstance(machine_learning, dict) and isinstance(
            self._ml_raw_score(),
            (int, float),
        )
        threat = self.collection_details.get("threat_intelligence")
        dns = self.collection_details.get("dns")
        tls = self.collection_details.get("tls")
        domain = self.collection_details.get("domain")
        forensic = self.domain_forensics.get("raw")
        forensic_status = (
            forensic.get("status", "unavailable")
            if isinstance(forensic, dict)
            else self.domain_forensics.get("status", "unavailable")
        )
        return {
            "machine_learning": "available" if ml_available else "unavailable",
            "threat_intelligence": (
                threat.get("status", "unknown")
                if isinstance(threat, dict)
                else "unavailable"
            ),
            "brand_identity": (
                "available"
                if isinstance(self.collection_details.get("brand"), dict)
                and any(
                    key in self.collection_details["brand"]
                    for key in (
                        "official_domain",
                        "official_brand_matches",
                        "detected_brands",
                    )
                )
                else "unavailable"
            ),
            "typosquatting": (
                "available"
                if isinstance(self.collection_details.get("typosquatting"), dict)
                and any(
                    key in self.collection_details["typosquatting"]
                    for key in (
                        "is_typosquat",
                        "possible_typosquatting",
                        "registered_domain",
                    )
                )
                else "unavailable"
            ),
            "domain": (
                domain.get("status", "unknown")
                if isinstance(domain, dict)
                else "unavailable"
            ),
            "dns": (
                dns.get("status", "unknown")
                if isinstance(dns, dict)
                else "unavailable"
            ),
            "tls": (
                tls.get("status", "unknown")
                if isinstance(tls, dict)
                else "unavailable"
            ),
            "domain_forensics": forensic_status,
        }

    def _contextual_observations(
        self,
        forensic: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        observations: List[Dict[str, Any]] = []
        age = self.domain.get("domain_age_days")
        if isinstance(age, int) and not isinstance(age, bool):
            observations.append({
                "source": "domain_registration",
                "observation": "registration_age",
                "value": age,
                "interpretation": (
                    "Context only; age does not establish legitimacy."
                ),
            })
        if self.dns:
            observations.append({
                "source": "dns",
                "observation": "resolution_status",
                "value": self.dns.get("status", "unknown"),
                "interpretation": (
                    "DNS availability and record counts do not establish "
                    "legitimacy."
                ),
            })
        certificate = self.tls.get("certificate")
        if isinstance(certificate, dict) and (
            certificate.get("hostname_match") is not None
            or certificate.get("valid_at_observation") is not None
        ):
            observations.append({
                "source": "tls",
                "observation": "certificate_hostname_and_validity",
                "hostname_match": certificate.get("hostname_match"),
                "valid_at_observation": certificate.get(
                    "valid_at_observation"
                ),
                "observed_at": certificate.get("observed_at"),
                "interpretation": (
                    "Certificate facts do not verify brand ownership or "
                    "site legitimacy."
                ),
            })
        raw = forensic.get("raw")
        if isinstance(raw, dict):
            observations.append({
                "source": "domain_forensics",
                "observation": "collection_status",
                "value": raw.get("status", "unavailable"),
                "certificate_history_status": raw.get(
                    "certificate_history_status",
                    "unavailable",
                ),
                "subdomain_discovery_status": raw.get(
                    "subdomain_discovery_status",
                    "unavailable",
                ),
                "interpretation": (
                    "Forensic collection status and infrastructure records "
                    "are contextual, not reputation verdicts."
                ),
            })
        return observations

    def to_pipeline_dict(self) -> Dict[str, Any]:
        """Return the legacy field shape using canonical decision semantics."""
        from src.intelligence.trust import is_allowlisted
        from src.intelligence.url_normalizer import normalize_url

        normalized = normalize_url(self.url)
        tls_certificate = self.tls.get("certificate", {})
        tls_valid = (
            self.tls.get("status") == "available"
            and tls_certificate.get("hostname_match") is True
        )
        san_matched = tls_certificate.get(
            "san_matched",
            tls_certificate.get("hostname_match") is True,
        )
        allowlisted = is_allowlisted(self.url)
        domain_age = self.domain.get("domain_age_days")

        brand = self.identity.get("brand")
        spoofing = bool(
            self.identity.get("brand_mismatch")
            or self.identity.get("_typosquat_detected")
            or self.identity.get("_homograph_detected")
        )
        reasons = list(self.reasons)
        if domain_age is None:
            reasons.append(
                "Domain age is unavailable and was not used to determine the decision."
            )
        if not reasons:
            reasons.append("No decisive evidence was available.")
        ml_raw_score = self._ml_raw_score()

        return {
            "url": self.url,
            "parsed_domain": {
                "subdomain": normalized["subdomain"],
                "domain": normalized["registered_domain"].removesuffix(
                    "." + normalized["registered_domain"].split(".", 1)[1]
                ) if "." in normalized["registered_domain"] else normalized["registered_domain"],
                "tld": normalized["registered_domain"].split(".", 1)[1]
                if "." in normalized["registered_domain"] else "",
            },
            "infrastructure_checks": {
                "dns_valid": bool(
                    self.dns.get("records", {}).get("A")
                    or self.dns.get("records", {}).get("AAAA")
                ),
                "domain_age_days": domain_age,
                "tls_valid": tls_valid,
                "san_matched": bool(san_matched),
                "cert_issuer": tls_certificate.get("issuer"),
            },
            "is_allowlisted": allowlisted,
            "brand_spoofing_detected": spoofing,
            "matched_brand": brand.title() if brand else "NONE",
            "phishing_score": (
                round(float(ml_raw_score), 6)
                if isinstance(ml_raw_score, (int, float))
                else None
            ),
            "final_decision": (
                "LEGITIMATE"
                if self.decision == DecisionState.SAFE
                else self.decision.value.upper()
            ),
            "reasons": reasons,
        }

    @staticmethod
    def _identity_output(evidence: List[Evidence]) -> Dict[str, Any]:
        identity: Dict[str, Any] = {
            "brand": None,
            "official_domain": False,
            "brand_mismatch": False,
            "_typosquat_detected": False,
            "_typosquat_method": None,
            "_homograph_detected": False,
            "_punycode_detected": False,
        }

        for item in evidence:
            if item.signal == "official_domain":
                identity["official_domain"] = True
                match = re.search(
                    r"official ([\w-]+) (?:domain|hostname)",
                    item.reason,
                )
                if match:
                    identity["brand"] = match.group(1).title()
            elif item.signal == "brand_mismatch":
                identity["brand_mismatch"] = True
                match = re.search(r"Brand '([^']+)'", item.reason)
                if match:
                    identity["brand"] = match.group(1).title()
            elif item.signal == "typosquat_detected":
                identity["_typosquat_detected"] = True
                identity["_typosquat_method"] = "visual_similarity"
            elif item.signal == "mixed_script_deception":
                identity["_homograph_detected"] = True
            elif item.signal == "punycode_detected":
                identity["_punycode_detected"] = True

        identity["identity_status"] = (
            "brand_impersonation"
            if identity["brand_mismatch"]
            else "typosquatting"
            if identity["_typosquat_detected"]
            else "homograph"
            if identity["_homograph_detected"]
            else "official"
            if identity["official_domain"]
            else "punycode_review"
            if identity["_punycode_detected"]
            else "unknown"
        )
        return identity

    def _threat_intelligence_output(
        self,
        evidence: List[Evidence],
    ) -> Dict[str, Any]:
        known_phishing = any(
            item.signal == "known_phishing" for item in evidence
        )
        known_malware = any(
            item.signal == "known_malware" for item in evidence
        )
        status = (
            "known_phishing"
            if known_phishing
            else "known_malware"
            if known_malware
            else "unknown"
        )
        return {
            "status": status,
            "known_phishing": known_phishing,
            "known_malware": known_malware,
            "sources": {
                "phishtank": status,
                "openphish": status,
                "urlhaus": status,
            },
        }

    def _decision_message(self, identity: Dict[str, Any]) -> str:
        if self.decision_basis == "conflicting_evidence":
            risk_increasing_points = self.risk_score_breakdown.get(
                "risk_increasing_evidence_points"
            )
            risk_mitigating_points = self.risk_score_breakdown.get(
                "risk_mitigating_evidence_points"
            )
            raw_model_score = self._ml_raw_score()
            ml_summary = (
                f"The raw XGBoost output is {float(raw_model_score):.6f} on its "
                "0-1 scale; "
                if isinstance(raw_model_score, (int, float))
                else ""
            )
            score_summary = (
                f"Weighted risk points are {self.risk_score} after "
                f"{risk_increasing_points} risk-increasing points and "
                f"{risk_mitigating_points} risk-mitigating points offset."
                if isinstance(risk_increasing_points, int)
                and isinstance(risk_mitigating_points, int)
                else (
                    f"Weighted risk points are {self.risk_score}; this is "
                    "not the model score."
                )
            )
            conflict_summary = (
                f" {self.contradictions[0]}"
                if self.contradictions
                else ""
            )
            return (
                "Evidence conflicts, so the URL requires review rather than "
                "being treated as safe or confirmed malicious. "
                + ml_summary
                + score_summary
                + conflict_summary
                + " The model score is not calibrated."
            )
        ml_conflict = any(
            "ML returned an elevated raw score" in item
            or "ML score (" in item
            for item in self.contradictions
        )
        raw_model_score = self._ml_raw_score()
        if (
            self.decision == DecisionState.SAFE
            and identity.get("brand")
        ):
            summary = (
                f"The URL belongs to an official {identity['brand']} domain."
            )
            if ml_conflict and isinstance(raw_model_score, (int, float)):
                summary += (
                    f" The uncalibrated raw XGBoost score is "
                    f"{float(raw_model_score):.6f}; this model-only signal "
                    "conflicts with verified identity and did not override it."
                )
            return summary
        if self.decision == DecisionState.SAFE:
            return "The URL matched verified legitimate identity evidence."
        if self.decision == DecisionState.PHISHING:
            if self.decision_basis == "known_threat_intelligence":
                return (
                    "A trusted threat-intelligence source confirmed this "
                    "URL as phishing."
                )
            if self.decision_basis in {
                "strong_impersonation_evidence",
                "multiple_independent_signals",
            }:
                return (
                    "Independent identity evidence indicates an attempt to "
                    "impersonate a protected brand."
                )
            return "The URL contains strong phishing indicators."
        if self.decision == DecisionState.MALWARE:
            return (
                "A trusted threat-intelligence source associated this URL "
                "with malware."
            )
        if self.decision == DecisionState.SUSPICIOUS:
            if self.decision_basis == "corroborated_ml_suspicion":
                corroborators = sorted({
                    item.source
                    for item in self.malicious_signals
                    if item.source != "ml_xgboost"
                })
                detail = (
                    " Recent registration also contributed contextual risk."
                    if any(
                        item.signal == "new_domain"
                        for item in self.evidence
                    )
                    else ""
                )
                if corroborators:
                    detail = (
                        " It is corroborated by "
                        + ", ".join(corroborators)
                        + " evidence."
                    )
                return (
                    "The elevated uncalibrated XGBoost output is supported "
                    "by other evidence and warrants review, but does not "
                    "confirm phishing."
                    + detail
                )
            return (
                "The uncalibrated model score warrants review, but does not "
                "confirm a phishing incident by itself."
            )
        if self.decision_basis == "ml_requires_corroboration":
            raw_model_score = self._ml_raw_score()
            score_detail = (
                f" The uncalibrated raw XGBoost score is "
                f"{float(raw_model_score):.6f}."
                if isinstance(raw_model_score, (int, float))
                else ""
            )
            return (
                "The model signaled phishing-like features, but independent "
                "evidence is insufficient to classify the URL."
                + score_detail
                + " The result remains unknown for review."
            )
        if self.decision == DecisionState.UNKNOWN:
            return (
                "Available evidence is insufficient to establish either "
                "legitimacy or maliciousness; review is recommended."
            )
        return "The URL requires further investigation."