import math
from typing import Any, Dict, List, Mapping
from src.risk.models import Evidence, EvidenceDirection, EvidenceStrength
from src.risk.policy import DEFAULT_RISK_POLICY
from src.intelligence.threat_intelligence import check_threat_intelligence
from src.intelligence.brand_engine import analyze_brand
from src.intelligence.typosquatting import analyze_typosquatting
from src.intelligence.homograph import analyze_homograph
from src.intelligence.domain_intelligence import analyze_domain
from src.intelligence.dns_intelligence import analyze_dns
from src.intelligence.tls_intelligence import analyze_tls
from src.intelligence.url_normalizer import normalize_url
from src.rag.cases import ValidatedCaseStore


def predict_url(url: str) -> Dict[str, Any]:
    """Load and invoke XGBoost lazily so optional model failure is reportable."""
    try:
        from src.ml.predict import predict_url as model_predict_url

        result = model_predict_url(url)
    except Exception as exc:
        return {
            "status": "unavailable",
            "error": f"{type(exc).__name__}: {str(exc)}"[:512],
        }
    if not isinstance(result, Mapping):
        return {
            "status": "error",
            "error": "Model provider returned a non-object result",
        }
    return dict(result)


class EvidenceCollector:
    """Collects and normalizes raw intelligence into standard Evidence objects."""
    
    @staticmethod
    def gather_all_evidence(
        url: str,
        *,
        domain_context: Mapping | None = None,
        dns_context: Mapping | None = None,
        component_details: Dict[str, Any] | None = None,
        include_ml: bool = True,
        ml_not_run_reason: str | None = None,
    ) -> List[Evidence]:
        evidence_list = []
        validated_case = ValidatedCaseStore().find_for_url(url)
        if component_details is not None:
            component_details["validated_case"] = validated_case
        if validated_case and validated_case["decision"] == "confirmed_legitimate":
            evidence_list.append(Evidence(
                source="validated_case",
                signal="validated_legitimate_domain",
                value=validated_case["domain"],
                strength=EvidenceStrength.STRONG,
                reliability=0.98,
                direction=EvidenceDirection.BENIGN,
                reason=validated_case["reason"],
            ))
        normalized = normalize_url(url)
        domain_result = (
            domain_context
            if domain_context is not None
            else analyze_domain(url)
        )
        domain_age = domain_result.get("domain_age_days")
        if (
            isinstance(domain_age, int)
            and not isinstance(domain_age, bool)
            and domain_age < 30
        ):
            evidence_list.append(Evidence(
                source="domain_intelligence",
                signal="new_domain",
                value=domain_age,
                strength=EvidenceStrength.WEAK,
                reliability=0.70,
                direction=EvidenceDirection.NEUTRAL,
                reason=f"Domain registration age is {domain_age} days; contextual only",
            ))
        elif (
            isinstance(domain_age, int)
            and not isinstance(domain_age, bool)
            and domain_age > 365
        ):
            evidence_list.append(Evidence(
                source="domain_intelligence",
                signal="established_domain",
                value=domain_age,
                strength=EvidenceStrength.WEAK,
                reliability=0.70,
                direction=EvidenceDirection.NEUTRAL,
                reason=f"Domain registration age is {domain_age} days; contextual only",
            ))
        dns_result = (
            dns_context
            if dns_context is not None
            else analyze_dns(normalized["hostname"])
        )
        tls_result = analyze_tls(
            normalized["hostname"],
            normalized["port"] or 443,
        )
        if component_details is not None:
            component_details["domain"] = domain_result
            component_details["dns"] = dns_result
            component_details["tls"] = tls_result
        
        # 1. Threat Intelligence (Tier 1)
        ti_result = check_threat_intelligence(url)
        if component_details is not None:
            component_details["threat_intelligence"] = ti_result
        if isinstance(ti_result, Mapping):
            ti_status = ti_result.get("status")
        else:
            # Keep compatibility with callers/tests that provide the legacy
            # status string rather than the aggregate result dictionary.
            ti_status = ti_result

        if ti_status in ["known_phishing", "known_malware"]:
            evidence_list.append(Evidence(
                source="threat_intelligence",
                signal=ti_status,
                value=True,
                strength=EvidenceStrength.CRITICAL,
                reliability=0.99,
                direction=EvidenceDirection.MALICIOUS,
                reason=f"URL present in confirmed {ti_status} feed"
            ))
        elif ti_status == "unknown":
            evidence_list.append(Evidence(
                source="threat_intelligence",
                signal="unknown",
                value=True,
                strength=EvidenceStrength.WEAK,
                reliability=0.50,
                direction=EvidenceDirection.NEUTRAL,
                reason="URL not found in threat intelligence feeds (NOT explicitly safe)"
            ))

        # 2. Brand Identity (Tier 2)
        brand_result = analyze_brand(url) or {}
        if component_details is not None:
            component_details["brand"] = brand_result
        official_brand_matches = brand_result.get("official_brand_matches")
        if not isinstance(official_brand_matches, list):
            official_brand_matches = []
        detected_brands = brand_result.get("detected_brands")
        if not isinstance(detected_brands, list):
            detected_brands = []
        detected_brands = [
            item for item in detected_brands
            if isinstance(item, str) and item
        ]
        official_brand_matches = [
            item for item in official_brand_matches
            if isinstance(item, str) and item
        ]
        registered_brand_matches = brand_result.get(
            "registered_brand_matches"
        )
        if not isinstance(registered_brand_matches, list):
            registered_brand_matches = official_brand_matches
        registered_brand_matches = [
            item for item in registered_brand_matches
            if isinstance(item, str) and item
        ]
        official_domain = brand_result.get("official_domain") is True or bool(
            official_brand_matches
        )
        if (
            brand_result.get("brand")
            and not detected_brands
            and not official_domain
        ):
            detected_brands = [brand_result["brand"]]
        brand = (
            official_brand_matches[0]
            if official_brand_matches
            else detected_brands[0]
            if detected_brands
            else brand_result.get("brand")
        )

        if official_domain:
            verified_hosted_brand_matches = brand_result.get(
                "verified_hosted_brand_matches",
                [],
            )
            verified_hosted_brand_matches = (
                verified_hosted_brand_matches
                if isinstance(verified_hosted_brand_matches, list)
                else []
            )
            if brand in verified_hosted_brand_matches:
                identity_reason = (
                    f"Hostname matches explicitly verified official "
                    f"{brand} hostname under "
                    f"{brand_result.get('registered_domain')}"
                )
            else:
                identity_reason = (
                    f"Registered domain matches official {brand} domain"
                )
            evidence_list.append(Evidence(
                source="brand_engine",
                signal="official_domain",
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.95,
                direction=EvidenceDirection.BENIGN,
                reason=identity_reason,
            ))
        mismatched_brands = [
            item for item in detected_brands
            if item not in registered_brand_matches
            and item not in official_brand_matches
        ]
        legacy_brand_result = not any(
            key in brand_result
            for key in (
                "brand_mismatch",
                "detected_brands",
                "registered_brand_matches",
            )
        )
        if brand_result.get("brand_mismatch") is True or mismatched_brands or (
            legacy_brand_result and brand and not official_domain
        ):
            mismatched_brand = (
                mismatched_brands[0]
                if mismatched_brands
                else brand
            )
            evidence_list.append(Evidence(
                source="brand_engine",
                signal="brand_mismatch",
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.90,
                direction=EvidenceDirection.MALICIOUS,
                reason=(
                    f"Brand '{mismatched_brand}' detected but the hostname "
                    "does not match its official domain"
                )
            ))

        # 3. Typosquatting (Tier 2)
        typo_result = analyze_typosquatting(url) or {}
        if component_details is not None:
            component_details["typosquatting"] = typo_result
        is_typosquat = typo_result.get("possible_typosquatting")
        if is_typosquat is None:
            is_typosquat = typo_result.get("is_typosquat")

        if is_typosquat is True:
            evidence_list.append(Evidence(
                source="typosquatting",
                signal="typosquat_detected",
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.85,
                direction=EvidenceDirection.MALICIOUS,
                reason="Domain visually resembles a known protected brand"
            ))

        tls_signals = tls_result.get("signals", [])
        if not isinstance(tls_signals, list):
            tls_signals = []
        if any(
            isinstance(signal, Mapping)
            and signal.get("signal") == "tls_hostname_mismatch"
            for signal in tls_signals
        ):
            evidence_list.append(Evidence(
                source="tls",
                signal="tls_hostname_mismatch",
                value=True,
                strength=EvidenceStrength.CRITICAL,
                reliability=0.95,
                direction=EvidenceDirection.MALICIOUS,
                reason="TLS certificate hostname does not match the requested hostname",
            ))
        elif any(
            isinstance(signal, Mapping)
            and signal.get("signal") == "tls_certificate_invalid"
            for signal in tls_signals
        ):
            evidence_list.append(Evidence(
                source="tls",
                signal="tls_certificate_invalid",
                value=True,
                strength=EvidenceStrength.MODERATE,
                reliability=0.85,
                direction=EvidenceDirection.MALICIOUS,
                reason="TLS certificate validation failed; this is a security warning, not proof of phishing",
            ))
        elif tls_result.get("status") == "available" and tls_result.get("certificate", {}).get("hostname_match") is True:
            evidence_list.append(Evidence(
                source="tls",
                signal="tls_hostname_verified",
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.92,
                direction=EvidenceDirection.NEUTRAL,
                reason="TLS certificate matches the requested hostname; this does not verify brand ownership",
            ))

        # 4. Homograph (Tier 2)
        homo_result = analyze_homograph(url) or {}
        if component_details is not None:
            component_details["homograph"] = homo_result
        has_punycode = homo_result.get("has_punycode") is True
        has_deceptive_homograph = (
            homo_result.get("is_deceptive") is True
            or homo_result.get("mixed_scripts") is True
            or homo_result.get("has_confusable_characters") is True
        )
        if has_deceptive_homograph:
            evidence_list.append(Evidence(
                source="homograph",
                signal="mixed_script_deception",
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.95,
                direction=EvidenceDirection.MALICIOUS,
                reason="Suspicious unicode characters used to bypass visual inspection"
            ))
        elif has_punycode:
            evidence_list.append(Evidence(
                source="homograph",
                signal="punycode_detected",
                value=True,
                strength=EvidenceStrength.MODERATE,
                reliability=0.80,
                direction=EvidenceDirection.MALICIOUS,
                reason="Punycode hostname requires additional identity verification",
            ))

        if include_ml:
            EvidenceCollector.add_machine_learning_evidence(
                url,
                evidence_list,
                component_details=component_details,
            )
        elif component_details is not None:
            component_details["machine_learning"] = {
                "status": "not_run",
                "reason": ml_not_run_reason or (
                    "Independent evidence produced a reliable finding."
                ),
            }

        return evidence_list

    @staticmethod
    def add_machine_learning_evidence(
        url: str,
        evidence_list: List[Evidence],
        *,
        component_details: Dict[str, Any] | None = None,
    ) -> None:
        """Collect an ML fallback result and append its normalized evidence."""
        ml_result = predict_url(url)
        if component_details is not None:
            component_details["machine_learning"] = ml_result
        if ml_result.get("status") in {"unavailable", "error"}:
            return
        prob = ml_result.get(
            "raw_model_score",
            ml_result.get("phishing_probability"),
        )
        if (
            isinstance(prob, (int, float))
            and not isinstance(prob, bool)
            and math.isfinite(prob)
            and 0.0 <= prob <= 1.0
        ):
            if prob >= DEFAULT_RISK_POLICY.ml_review_threshold:
                strength = (
                    EvidenceStrength.STRONG
                    if prob >= DEFAULT_RISK_POLICY.ml_strong_threshold
                    else EvidenceStrength.MODERATE
                )
                direction = EvidenceDirection.MALICIOUS
                reason = (
                    f"Uncalibrated XGBoost score is {prob:.1%}; this indicates "
                    "phishing-like learned features, not a calibrated probability"
                )
                reliability = 0.70
            elif prob < DEFAULT_RISK_POLICY.ml_benign_threshold:
                strength = EvidenceStrength.WEAK
                direction = EvidenceDirection.BENIGN
                reason = (
                    f"Uncalibrated XGBoost score is {prob:.1%}; this weak "
                    "model signal does not establish legitimacy"
                )
                reliability = 0.60
            else:
                strength = EvidenceStrength.WEAK
                direction = EvidenceDirection.NEUTRAL
                reason = "Uncalibrated XGBoost score is inconclusive"
                reliability = 0.70

            contribution_notes = []
            contributions = ml_result.get("top_feature_contributions")
            if isinstance(contributions, list):
                for item in contributions:
                    if not isinstance(item, Mapping):
                        continue
                    name = item.get("feature")
                    contribution = item.get("contribution")
                    if (
                        isinstance(name, str)
                        and isinstance(contribution, (int, float))
                        and not isinstance(contribution, bool)
                        and math.isfinite(contribution)
                        and contribution > 0
                    ):
                        contribution_notes.append(
                            f"{name} ({contribution:+.2f} log-odds)"
                        )
                    if len(contribution_notes) == 3:
                        break
            if contribution_notes:
                reason += (
                    "; strongest positive model contributions: "
                    + ", ".join(contribution_notes)
                )

            evidence_list.append(Evidence(
                source="ml_xgboost",
                signal="phishing_probability",
                value=prob,
                strength=strength,
                reliability=reliability,
                direction=direction,
                reason=reason,
            ))
