from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Mapping

from src.risk.models import (
    Evidence,
    EvidenceDirection,
    EvidenceStrength,
    FinalDecision,
    Override,
    DecisionState,
    RiskLevel,
)
from src.risk.collector import EvidenceCollector
from src.risk.analyzer import ContradictionAnalyzer
from src.risk.evidence_sources import normalize_evidence_sources
try:
    from src.rag.rag_provider import RAGEvidenceProvider
    RAG_AVAILABLE = True
except ImportError:
    RAGEvidenceProvider = None
    RAG_AVAILABLE = False
from src.intelligence.domain_intelligence import analyze_domain
from src.intelligence.dns_intelligence import analyze_dns
from src.intelligence.tls_intelligence import analyze_tls
from src.intelligence.url_normalizer import normalize_url
from src.intelligence.domain_forensics import investigate_domain

class RiskEngine:
    def __init__(self):
        self.rag_provider = RAGEvidenceProvider() if RAG_AVAILABLE else None

    def evaluate_url(self, url: str) -> FinalDecision:
        normalized = normalize_url(url)
        forensic_raw = self._collect_domain_forensics(url)
        forensic_domain = self._domain_context_from_forensics(
            forensic_raw,
            normalized,
        )
        forensic_dns = self._dns_context_from_forensics(forensic_raw)
        component_details: Dict[str, Any] = {}

        # Reuse forensic DNS/RDAP observations where available to avoid a
        # second independent query for the same underlying evidence.
        raw_evidence = EvidenceCollector.gather_all_evidence(
            url,
            domain_context=forensic_domain,
            dns_context=forensic_dns,
            component_details=component_details,
            include_ml=False,
            ml_not_run_reason="Independent evidence is being evaluated first.",
        )
        independent_status = self._independent_evidence_status(
            raw_evidence,
            component_details,
        )
        ml_fallback_reason = None
        if self._should_use_ml_fallback(raw_evidence):
            ml_fallback_reason = (
                "Independent evidence was "
                f"{independent_status}; XGBoost was used as supporting fallback evidence."
            )
            EvidenceCollector.add_machine_learning_evidence(
                url,
                raw_evidence,
                component_details=component_details,
            )
        component_details["decision_fallback"] = {
            "independent_evidence_status": independent_status,
            "ml_used": ml_fallback_reason is not None,
            "ml_fallback_reason": ml_fallback_reason,
        }
        # 2. Analyze for contradictions and apply overrides
        active_evidence, overrides, contradictions = ContradictionAnalyzer.analyze(raw_evidence)
        
        # 3. Categorize signals
        malicious = [e for e in active_evidence if e.direction == EvidenceDirection.MALICIOUS]
        benign = [e for e in active_evidence if e.direction == EvidenceDirection.BENIGN]
        
        # 4. Retrieve historical threat-intelligence cases. RAG is advisory;
        # the normalized evidence and contradiction engine remain authoritative.
        component_summaries = self._build_component_summaries(raw_evidence)
        domain_context = forensic_domain or analyze_domain(url)
        dns_context = forensic_dns or analyze_dns(normalized["hostname"])
        tls_context = component_details.get("tls") or analyze_tls(
            normalized["hostname"],
            normalized["port"] or 443,
        )
        rag_context = self._investigate_with_rag(
            url=url,
            context={
                "machine_learning": component_summaries["machine_learning"],
                "threat_intelligence": component_summaries[
                    "threat_intelligence"
                ],
                "brand_analysis": component_summaries["identity"],
                "typosquatting": {
                    "detected": any(
                        e.signal == "typosquat_detected"
                        for e in active_evidence
                    )
                },
                "homograph_analysis": {
                    "detected": any(
                        e.signal == "mixed_script_deception"
                        for e in active_evidence
                    ),
                    "punycode": any(
                        e.signal == "punycode_detected"
                        for e in active_evidence
                    ),
                },
                "domain_intelligence": domain_context,
                "dns": dns_context,
                "tls": tls_context,
                "malicious_count": len(malicious),
            },
        )

        domain_forensics = self._build_domain_forensics_context(
            forensic_raw,
            raw_evidence,
            domain_context,
            dns_context,
        )
        for contradiction in domain_forensics["contradictions"]:
            text = contradiction["description"]
            if text not in contradictions:
                contradictions.append(text)
        # 5. Core Decision Logic
        contextual_signals = self._contextual_signals(
            domain_context=domain_context,
        )
        decision, risk_level, decision_basis, recommended_action = self._compute_decision(
            malicious,
            benign,
            contextual_signals=contextual_signals,
        )
        non_ml_malicious_support = any(
            item.source != "ml_xgboost"
            and item.direction == EvidenceDirection.MALICIOUS
            for item in raw_evidence
        )
        if (
            decision_basis == "corroborated_ml_suspicion"
            and "newly_registered_domain" in contextual_signals
            and not non_ml_malicious_support
        ):
            for finding in domain_forensics["findings"]:
                if finding.get("name") == "domain_maturity":
                    finding["influenced_decision"] = True
                    finding["importance"] = "supporting"
                    finding["interpretation"] = (
                        "Registration under 30 days corroborated a separate "
                        "high ML signal for review; age alone is not malicious "
                        "evidence."
                    )
        component_details["normalized_evidence_sources"] = (
            normalize_evidence_sources(
                normalized,
                component_details,
                forensic_raw,
                raw_evidence,
                decision_basis=decision_basis,
            )
        )
        evidence_agreement = self._evidence_agreement(
            raw_evidence,
            contradictions,
        )
        evidence_quality = self._evidence_quality(raw_evidence)
        
        # 6. Calculate independent confidence and score
        confidence = self._calculate_confidence(
            raw_evidence,
            contradictions,
            decision_basis=decision_basis,
        )
        risk_score_breakdown = self._risk_score_breakdown(
            malicious,
            benign,
            decision=decision.value,
            decision_basis=decision_basis,
            recommended_action=recommended_action,
        )
        risk_score = risk_score_breakdown["final_score"]
        
        # 7. Generate explanations
        reasons = self._generate_explanations(malicious, benign, overrides)
        return FinalDecision(
            url=url,
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            decision_basis=decision_basis,
            evidence=raw_evidence,
            malicious_signals=malicious,
            benign_signals=benign,
            contradictions=contradictions,
            overrides=overrides,
            machine_learning=component_summaries["machine_learning"],
            threat_intelligence=component_summaries["threat_intelligence"],
            identity=component_summaries["identity"],
            domain=domain_context,
            dns=dns_context,
            tls=tls_context,
            rag=rag_context,
            domain_forensics=domain_forensics,
            evidence_agreement=evidence_agreement,
            evidence_quality=evidence_quality,
            reasons=reasons,
            recommended_action=recommended_action,
            collection_details=component_details,
            risk_score_breakdown=risk_score_breakdown,
        )

    @staticmethod
    def _independent_evidence_status(
        evidence: List[Evidence],
        component_details: Dict[str, Any],
    ) -> str:
        independent = [
            item for item in evidence if item.source != "ml_xgboost"
        ]
        malicious = [
            item for item in independent
            if item.direction == EvidenceDirection.MALICIOUS
        ]
        benign = [
            item for item in independent
            if item.direction == EvidenceDirection.BENIGN
        ]
        threat = component_details.get("threat_intelligence")
        if any(
            item.signal in {"known_phishing", "known_malware"}
            for item in independent
        ) or (
            isinstance(threat, Mapping)
            and threat.get("status") in {
                "known_phishing",
                "known_malware",
            }
        ):
            return "confirmed_malicious"
        if malicious and benign:
            return "conflicting"
        malicious_groups = {
            group
            for item in malicious
            if (group := RiskEngine._independent_evidence_group(item)) is not None
        }
        if len(malicious_groups) > 1:
            return "conclusive"
        if any(
            item.signal in {
                "official_domain",
                "validated_legitimate_domain",
            }
            for item in benign
        ):
            return "conclusive"
        source_statuses = []
        for key in ("threat_intelligence", "domain", "dns", "tls"):
            source = component_details.get(key)
            if isinstance(source, Mapping):
                source_statuses.append(source.get("status"))
        if source_statuses and all(
            status in {"unavailable", "error", None}
            for status in source_statuses
        ):
            return "unavailable"
        return "inconclusive"

    @staticmethod
    def _should_use_ml_fallback(evidence: List[Evidence]) -> bool:
        independent = [
            item for item in evidence if item.source != "ml_xgboost"
        ]
        malicious = [
            item for item in independent
            if item.direction == EvidenceDirection.MALICIOUS
        ]
        benign = [
            item for item in independent
            if item.direction == EvidenceDirection.BENIGN
        ]
        if any(
            item.signal in {"known_phishing", "known_malware"}
            for item in malicious
        ):
            return False
        malicious_groups = {
            group
            for item in malicious
            if (group := RiskEngine._independent_evidence_group(item)) is not None
        }
        if len(malicious_groups) > 1:
            return False
        if malicious and benign:
            return True
        if any(
            item.signal in {
                "official_domain",
                "validated_legitimate_domain",
            }
            for item in benign
        ):
            return False
        return True

    @staticmethod
    def _collect_domain_forensics(url: str) -> Dict[str, Any]:
        try:
            result = investigate_domain(url)
        except Exception as exc:
            message = f"{type(exc).__name__}: {str(exc)}"[:512]
            return {
                "domain": None,
                "subdomains": [],
                "dns_records": {},
                "dns_interpretations": {},
                "registration": {"status": "unavailable", "data": None},
                "certificate_history": [],
                "certificate_history_status": "unavailable",
                "subdomain_discovery_status": "unavailable",
                "infrastructure": [],
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "sources": {},
                "status": "unavailable",
                "errors": [{
                    "source": "domain_forensics",
                    "status": "provider_exception",
                    "message": message,
                }],
                "unavailable_evidence": [
                    "registration",
                    "dns",
                    "certificate_history",
                    "subdomain_discovery",
                    "ip_asn",
                ],
            }
        if not isinstance(result, dict):
            return {
                "domain": None,
                "subdomains": [],
                "dns_records": {},
                "dns_interpretations": {},
                "registration": {"status": "unavailable", "data": None},
                "certificate_history": [],
                "certificate_history_status": "unavailable",
                "subdomain_discovery_status": "unavailable",
                "infrastructure": [],
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "sources": {},
                "status": "unavailable",
                "errors": [{
                    "source": "domain_forensics",
                    "status": "malformed_result",
                    "message": "Provider returned a non-object result",
                }],
                "unavailable_evidence": [
                    "registration",
                    "dns",
                    "certificate_history",
                    "subdomain_discovery",
                    "ip_asn",
                ],
            }
        try:
            json.dumps(result, allow_nan=False)
        except (TypeError, ValueError) as exc:
            return {
                "domain": None,
                "subdomains": [],
                "dns_records": {},
                "dns_interpretations": {},
                "registration": {"status": "unavailable", "data": None},
                "certificate_history": [],
                "certificate_history_status": "unavailable",
                "subdomain_discovery_status": "unavailable",
                "infrastructure": [],
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "sources": {},
                "status": "unavailable",
                "errors": [{
                    "source": "domain_forensics",
                    "status": "malformed_result",
                    "message": f"Provider result is not JSON serializable: {type(exc).__name__}",
                }],
                "unavailable_evidence": [
                    "registration",
                    "dns",
                    "certificate_history",
                    "subdomain_discovery",
                    "ip_asn",
                ],
            }
        return result

    @staticmethod
    def _domain_context_from_forensics(
        raw: Dict[str, Any],
        normalized: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        domain = raw.get("domain")
        registration = raw.get("registration")
        if not isinstance(domain, str) or not isinstance(registration, dict):
            return None
        data = registration.get("data")
        if not isinstance(data, dict):
            data = {}
        age = data.get("domain_age_days")
        if not isinstance(age, int) or isinstance(age, bool) or age < 0:
            age = None
        retrieval_status = registration.get(
            "retrieval_status",
            registration.get("status"),
        )
        return {
            "status": (
                "available"
                if retrieval_status == "available"
                else "unknown"
            ),
            "reason": "domain_forensics_registration",
            "hostname": normalized.get("hostname"),
            "registered_domain": domain,
            "subdomain": normalized.get("subdomain"),
            "scheme": normalized.get("scheme"),
            "port": normalized.get("port"),
            "creation_date": data.get("creation_date"),
            "expiry_date": data.get("expiry_date"),
            "registrar": data.get("registrar"),
            "nameservers": data.get("nameservers", []),
            "domain_age_days": age,
            "domain_age_known": bool(data.get("domain_age_known") and age is not None),
        }

    @staticmethod
    def _dns_context_from_forensics(
        raw: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        records = raw.get("dns_records")
        sources = raw.get("sources")
        interpretations = raw.get("dns_interpretations")
        if (
            not isinstance(records, dict)
            or not isinstance(sources, dict)
            or not isinstance(sources.get("dns"), dict)
        ):
            return None
        source_status = sources["dns"].get("status")
        if source_status not in {
            "available",
            "partial",
            "no_records",
            "unavailable",
        }:
            return None
        clean_records = {
            record_type: values if isinstance(values, list) else []
            for record_type, values in records.items()
        }
        raw_errors = raw.get("errors")
        if not isinstance(raw_errors, list):
            raw_errors = []
        return {
            "status": source_status,
            "hostname": raw.get("domain"),
            "records": clean_records,
            "errors": [
                error for error in raw_errors
                if isinstance(error, dict) and error.get("source") == "dns"
            ],
            "signals": [],
            "interpretations": (
                interpretations if isinstance(interpretations, dict) else {}
            ),
            "source": sources["dns"],
        }

    def _build_domain_forensics_context(
        self,
        raw: Dict[str, Any],
        evidence: List[Evidence],
        domain: Dict[str, Any],
        dns: Dict[str, Any],
    ) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        supporting_signals: List[Dict[str, Any]] = []
        suspicious_signals: List[Dict[str, Any]] = []
        unavailable = raw.get("unavailable_evidence")
        unknown_evidence = [
            item for item in unavailable if isinstance(item, str)
        ] if isinstance(unavailable, list) else []
        registration = raw.get("registration")
        registration_data = (
            registration.get("data", {})
            if isinstance(registration, dict)
            and isinstance(registration.get("data"), dict)
            else {}
        )
        domain_age = domain.get("domain_age_days")
        if isinstance(domain_age, int) and not isinstance(domain_age, bool):
            interpretation = (
                "recent_registration"
                if domain_age < 30
                else "established_registration"
                if domain_age > 365
                else "registration_age_context"
            )
            findings.append({
                "name": "domain_maturity",
                "observed": {
                    "domain_age_days": domain_age,
                    "creation_date": registration_data.get("creation_date"),
                },
                "interpretation": interpretation,
                "importance": "contextual",
                "evidence_role": "domain_registration",
                "source": "RDAP",
                "influenced_decision": False,
            })
        else:
            unknown_evidence.append("registration_age")

        interpretations = dns.get("interpretations")
        record_status = (
            interpretations.get("record_status", {})
            if isinstance(interpretations, dict)
            else {}
        )
        findings.append({
            "name": "dns_observation",
            "observed": {
                "status": dns.get("status", "unavailable"),
                "record_status": record_status,
                "records": dns.get("records", {}),
            },
            "interpretation": "DNS data is contextual; absent record types are not malicious by themselves.",
            "importance": "contextual",
            "evidence_role": "infrastructure",
            "source": "domain_forensics",
            "influenced_decision": any(
                item.signal == "dns_anomaly" for item in evidence
            ),
        })

        certificates = raw.get("certificate_history")
        if not isinstance(certificates, list):
            certificates = []
            unknown_evidence.append("certificate_history")
        findings.append({
            "name": "certificate_transparency_history",
            "observed": {
                "status": raw.get(
                    "certificate_history_status",
                    "unavailable",
                ),
                "certificate_count": len(certificates),
            },
            "interpretation": "CT entries show logged certificates, not domain legitimacy.",
            "importance": "contextual",
            "evidence_role": "historical_infrastructure",
            "source": "certificate_transparency",
            "influenced_decision": False,
        })
        subdomains = raw.get("subdomains")
        if not isinstance(subdomains, list):
            subdomains = []
            unknown_evidence.append("subdomain_discovery")
        findings.append({
            "name": "passive_subdomain_discovery",
            "observed": {"count": len(subdomains), "domains": subdomains},
            "interpretation": "Discovered names are context only; their count does not indicate maliciousness.",
            "importance": "contextual",
            "evidence_role": "domain_context",
            "source": "certificate_transparency",
            "influenced_decision": False,
        })
        infrastructure = raw.get("infrastructure")
        if not isinstance(infrastructure, list):
            infrastructure = []
            unknown_evidence.append("ip_asn")
        findings.append({
            "name": "network_infrastructure",
            "observed": {"items": infrastructure},
            "interpretation": "IP, prefix, and ASN data identify infrastructure and are not reputation evidence by themselves.",
            "importance": "contextual",
            "evidence_role": "infrastructure",
            "source": "RIPEstat",
            "influenced_decision": False,
        })

        return {
            "status": raw.get("status", "unavailable"),
            "raw": raw,
            "normalized": {
                "domain": raw.get("domain"),
                "registration": {
                    "status": (
                        registration.get("retrieval_status",
                                         registration.get("status"))
                        if isinstance(registration, dict)
                        else "unavailable"
                    ),
                    "domain_age_days": domain_age,
                    "creation_date": registration_data.get("creation_date"),
                    "expiry_date": registration_data.get("expiry_date"),
                    "registrar": registration_data.get("registrar"),
                },
                "dns": {
                    "status": dns.get("status", "unavailable"),
                    "records": dns.get("records", {}),
                    "record_status": record_status,
                },
                "certificate_history": {
                    "status": raw.get("certificate_history_status", "unavailable"),
                    "count": len(certificates),
                },
                "subdomains": subdomains,
                "infrastructure": infrastructure,
            },
            "findings": findings,
            "supporting_signals": supporting_signals,
            "suspicious_signals": suspicious_signals,
            "contradictions": [],
            "unknown_evidence": sorted(set(unknown_evidence)),
            "errors": (
                raw.get("errors")
                if isinstance(raw.get("errors"), list)
                else []
            ),
            "sources": (
                raw.get("sources")
                if isinstance(raw.get("sources"), dict)
                else {}
            ),
        }

    def _investigate_with_rag(
        self,
        url: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        if self.rag_provider is None:
            return {
                "status": "unavailable",
                "closest_case": None,
                "supporting_knowledge": [],
                "investigation": None,
            }
        return self.rag_provider.investigate(url=url, context=context)

    def _compute_decision(
        self,
        malicious: List[Evidence],
        benign: List[Evidence],
        *,
        contextual_signals: set[str] | None = None,
    ):
        malicious_signals = {e.signal for e in malicious}
        benign_signals = {e.signal for e in benign}
        signals = malicious_signals | benign_signals
        strong_benign = any(
            e.signal in {
                "official_domain",
                "validated_legitimate_domain",
            }
            and e.strength == EvidenceStrength.STRONG
            for e in benign
        )
        strong_non_ml_malicious = any(
            e.strength in {EvidenceStrength.STRONG, EvidenceStrength.CRITICAL}
            and e.source != "ml_xgboost"
            for e in malicious
        )
        
        # Tier 1 checks
        if "known_malware" in signals:
            return DecisionState.MALWARE, RiskLevel.CRITICAL, "known_threat_intelligence", "block"
        if "known_phishing" in signals:
            return DecisionState.PHISHING, RiskLevel.CRITICAL, "known_threat_intelligence", "block"

        # Tier 2 Impersonation checks
        identity_impersonation = {
            "brand_mismatch",
            "typosquat_detected",
            "mixed_script_deception",
            "tls_hostname_mismatch",
        } & signals
        independent_malicious_groups = {
            group
            for item in malicious
            if item.source != "ml_xgboost"
            and (group := self._independent_evidence_group(item)) is not None
        }
        if len(independent_malicious_groups) > 1:
            return DecisionState.PHISHING, RiskLevel.HIGH, "multiple_independent_signals", "block"

        if "punycode_detected" in signals:
            return (
                DecisionState.SUSPICIOUS,
                RiskLevel.MEDIUM,
                "punycode_domain_review",
                "quarantine",
            )

        ml_malicious = [
            item for item in malicious if item.source == "ml_xgboost"
        ]
        independent_support = any(
            item.source != "ml_xgboost"
            and item.direction == EvidenceDirection.MALICIOUS
            for item in malicious
        )
        if strong_benign and independent_support:
            return (
                DecisionState.UNKNOWN,
                RiskLevel.MEDIUM,
                "conflicting_evidence",
                "monitor",
            )
        if (
            "official_domain" in benign_signals
            and not independent_support
        ):
            return (
                DecisionState.SAFE,
                RiskLevel.LOW,
                "official_identity_verified",
                "allow",
            )

        if (
            "validated_legitimate_domain" in benign_signals
            and not independent_support
        ):
            return (
                DecisionState.SAFE,
                RiskLevel.LOW,
                "validated_legitimate_case",
                "allow",
            )

        if strong_benign and strong_non_ml_malicious:
            return DecisionState.UNKNOWN, RiskLevel.MEDIUM, "conflicting_evidence", "monitor"

        if identity_impersonation:
            if strong_benign:
                return (
                    DecisionState.UNKNOWN,
                    RiskLevel.MEDIUM,
                    "conflicting_evidence",
                    "monitor",
                )
            return (
                DecisionState.SUSPICIOUS,
                RiskLevel.MEDIUM,
                "unconfirmed_impersonation_signal",
                "quarantine",
            )

        if ml_malicious:
            recent_registration = (
                "newly_registered_domain"
                in (contextual_signals or set())
            )
            if independent_support or recent_registration:
                return (
                    DecisionState.SUSPICIOUS,
                    RiskLevel.MEDIUM,
                    "corroborated_ml_suspicion",
                    "quarantine",
                )
            return (
                DecisionState.UNKNOWN,
                RiskLevel.LOW,
                "ml_requires_corroboration",
                "monitor",
            )

        # No strong signals in either direction
        return DecisionState.UNKNOWN, RiskLevel.LOW, "insufficient_evidence", "monitor"

    def _evidence_agreement(
        self,
        evidence: List[Evidence],
        contradictions: List[str],
    ) -> str:
        malicious_groups = set()
        benign_groups = set()
        for item in evidence:
            if item.direction == EvidenceDirection.NEUTRAL:
                continue
            group = self._independent_evidence_group(item)
            if group is None:
                continue
            if item.direction == EvidenceDirection.MALICIOUS:
                malicious_groups.add(group)
            elif item.direction == EvidenceDirection.BENIGN:
                benign_groups.add(group)

        if contradictions and malicious_groups and benign_groups:
            return "strong_contradiction"
        if malicious_groups and benign_groups:
            return "mixed"
        supporting_groups = malicious_groups or benign_groups
        if len(supporting_groups) >= 2:
            return "strong_agreement"
        if supporting_groups:
            return "moderate_agreement"
        return "insufficient"

    @staticmethod
    def _independent_evidence_group(evidence: Evidence) -> str | None:
        if evidence.source == "domain_intelligence":
            return None
        if evidence.signal == "tls_hostname_verified":
            return None
        if evidence.source == "brand_engine":
            if evidence.signal == "official_domain":
                return "verified_brand_identity"
            return "identity_impersonation"
        if evidence.source in {"typosquatting", "homograph"}:
            return "identity_impersonation"
        return evidence.source

    @staticmethod
    def _evidence_quality(evidence: List[Evidence]) -> str:
        relevant = [
            item for item in evidence
            if item.direction != EvidenceDirection.NEUTRAL
            and RiskEngine._independent_evidence_group(item) is not None
        ]
        if any(
            item.strength == EvidenceStrength.CRITICAL
            and item.reliability >= 0.9
            for item in relevant
        ):
            return "high"
        if any(item.strength == EvidenceStrength.STRONG for item in relevant):
            return "moderate"
        if relevant:
            return "low"
        return "unknown"

    def _calculate_confidence(
        self,
        evidence: List[Evidence],
        contradictions: List[str],
        *,
        decision_basis: str | None = None,
    ) -> int:
        base_confidence = 50

        relevant = [
            item for item in evidence
            if item.direction != EvidenceDirection.NEUTRAL
            and self._independent_evidence_group(item) is not None
        ]
        if any(
            e.strength == EvidenceStrength.CRITICAL and e.reliability >= 0.9
            for e in relevant
        ):
            base_confidence += 40
        elif any(e.strength == EvidenceStrength.STRONG for e in relevant):
            base_confidence += 30
            
        independent_groups = {
            self._independent_evidence_group(item)
            for item in relevant
        }
        if len(independent_groups) > 1:
            base_confidence += 10
            
        malicious_support = max(
            (
                item.strength.value * item.reliability
                for item in relevant
                if item.direction == EvidenceDirection.MALICIOUS
            ),
            default=0.0,
        )
        benign_support = max(
            (
                item.strength.value * item.reliability
                for item in relevant
                if item.direction == EvidenceDirection.BENIGN
            ),
            default=0.0,
        )
        if (
            contradictions
            and malicious_support > 0
            and benign_support > 0
        ):
            relative_support = (
                min(malicious_support, benign_support)
                / max(malicious_support, benign_support)
            )
            base_confidence -= 10 + round(25 * relative_support)
        elif contradictions:
            base_confidence -= 10
        if decision_basis in {
            "ml_requires_corroboration",
            "corroborated_ml_suspicion",
        }:
            base_confidence = min(base_confidence, 55)
            
        return max(10, min(100, base_confidence))

    @staticmethod
    def _contextual_signals(
        *,
        domain_context: Dict[str, Any] | None = None,
    ) -> set[str]:
        signals: set[str] = set()
        age_days = (
            domain_context.get("domain_age_days")
            if isinstance(domain_context, dict)
            and domain_context.get("domain_age_known") is True
            else None
        )
        if (
            isinstance(age_days, int)
            and not isinstance(age_days, bool)
            and 0 <= age_days < 30
        ):
            signals.add("newly_registered_domain")
        return signals

    def _calculate_risk_score(
        self,
        malicious: List[Evidence],
        benign: List[Evidence],
    ) -> int:
        return self._risk_score_breakdown(malicious, benign)["final_score"]

    def _risk_score_breakdown(
        self,
        malicious: List[Evidence],
        benign: List[Evidence],
        *,
        decision: str | None = None,
        decision_basis: str | None = None,
        recommended_action: str | None = None,
    ) -> Dict[str, Any]:
        weights = {
            EvidenceStrength.WEAK: 10,
            EvidenceStrength.MODERATE: 25,
            EvidenceStrength.STRONG: 50,
            EvidenceStrength.CRITICAL: 100
        }
        group_weights: Dict[
            tuple[str, EvidenceDirection],
            Dict[str, Any],
        ] = {}
        for item in [*malicious, *benign]:
            group = self._independent_evidence_group(item)
            if group is None:
                continue
            weight = weights.get(item.strength, 0)
            if item.source in {"dns", "tls"}:
                weight *= 2
            key = (group, item.direction)
            existing = group_weights.get(key)
            if existing is None or weight > existing["points"]:
                group_weights[key] = {
                    "points": weight,
                    "sources": {item.source},
                    "signals": {item.signal},
                }
            elif weight == existing["points"]:
                existing["sources"].add(item.source)
                existing["signals"].add(item.signal)

        def serialize(direction: EvidenceDirection) -> List[Dict[str, Any]]:
            components = []
            for (group, item_direction), values in sorted(
                group_weights.items(),
                key=lambda entry: (entry[0][0], entry[0][1].value),
            ):
                if item_direction != direction:
                    continue
                components.append({
                    "group": group,
                    "points": values["points"],
                    "sources": sorted(values["sources"]),
                    "signals": sorted(values["signals"]),
                })
            return components

        positive_components = serialize(EvidenceDirection.MALICIOUS)
        mitigating_components = serialize(EvidenceDirection.BENIGN)
        positive_points = sum(
            item["points"] for item in positive_components
        )
        mitigating_points = sum(
            item["points"] for item in mitigating_components
        )
        net_before_clamp = positive_points - mitigating_points
        final_score = max(0, min(100, net_before_clamp))
        breakdown = {
            "risk_increasing_evidence_points": positive_points,
            "risk_mitigating_evidence_points": mitigating_points,
            "net_before_clamp": net_before_clamp,
            "final_score": final_score,
            "risk_increasing_components": positive_components,
            "risk_mitigating_components": mitigating_components,
            "meaning": (
                "Weighted directional evidence points, not a probability. "
                "A zero is a non-positive net after evidence offsets and "
                "clamping; it does not mean zero model suspicion."
            ),
        }
        if decision is not None:
            breakdown["decision"] = decision
            breakdown["decision_basis"] = decision_basis
            breakdown["recommended_action"] = recommended_action
        return breakdown

    def _generate_explanations(
        self,
        malicious: List[Evidence],
        benign: List[Evidence],
        overrides: List[Override],
    ) -> List[str]:
        reasons = []
        for o in overrides:
            reasons.append(f"OVERRIDE: {o.reason}")
        for m in malicious:
            reasons.append(f"RISK: {m.reason}")
        for b in benign:
            reasons.append(f"TRUST: {b.reason}")
        if not reasons:
            reasons.append("No definitive evidence found. URL status is unknown.")
        return reasons

    def _build_component_summaries(
        self,
        evidence: List[Evidence],
    ) -> Dict[str, Dict[str, Any]]:
        """Expose normalized evidence grouped by its producing component."""
        machine_learning: Dict[str, Any] = {}
        threat_intelligence: Dict[str, Any] = {}
        identity: Dict[str, Any] = {}

        for item in evidence:
            if item.source == "ml_xgboost":
                machine_learning[item.signal] = item.value
            elif item.source == "threat_intelligence":
                threat_intelligence[item.signal] = item.value
            elif item.source in {
                "brand_engine",
                "typosquatting",
                "homograph",
            }:
                identity[item.signal] = item.value

        return {
            "machine_learning": machine_learning,
            "threat_intelligence": threat_intelligence,
            "identity": identity,
        }