from typing import List, Tuple
from src.risk.models import Evidence, Override, EvidenceDirection

class ContradictionAnalyzer:
    @staticmethod
    def analyze(evidence: List[Evidence]) -> Tuple[List[Evidence], List[Override], List[str]]:
        active_evidence = []
        overrides = []
        contradictions = []

        # Map signals for easy correlation
        signals = {e.signal: e for e in evidence}
        
        has_brand_mismatch = "brand_mismatch" in signals
        has_typosquat = "typosquat_detected" in signals
        has_deceptive_homograph = "mixed_script_deception" in signals
        has_confirmed_threat = any(
            e.signal in {"known_phishing", "known_malware"}
            for e in evidence
        )
        has_trusted_identity = any(
            e.signal in {
                "official_domain",
                "validated_legitimate_domain",
            }
            for e in evidence
        )
        if has_confirmed_threat and has_trusted_identity:
            contradictions.append(
                "Confirmed threat-intelligence evidence conflicts with "
                "verified legitimate identity; the confirmed threat match "
                "remains decisive."
            )
        if has_trusted_identity and (
            has_brand_mismatch or has_typosquat or has_deceptive_homograph
        ):
            contradictions.append(
                "Verified identity conflicts with an impersonation "
                "signal; both are retained, and the explicit impersonation "
                "signal remains eligible to determine the decision."
            )

        for ev in evidence:
            # Handle ML False Positives (Official Domain + High ML)
            if ev.source == "ml_xgboost" and ev.direction == EvidenceDirection.MALICIOUS:
                if has_trusted_identity:
                    overrides.append(Override(
                        override_type="ml_downgrade",
                        reason=(
                            "Verified identity evidence makes the "
                            "ML-only alert conflicting evidence; preserve the "
                            "prediction and require arbitration."
                        ),
                        affected_signal="ml_xgboost"
                    ))
                    contradictions.append(
                        f"ML returned an elevated raw score ({ev.value}) while legitimate identity is verified; the uncalibrated score is retained for arbitration."
                    )
            
            # Handle ML False Negatives (Strong Identity Malice + Low ML)
            if ev.source == "ml_xgboost" and ev.direction == EvidenceDirection.BENIGN:
                if has_brand_mismatch or has_typosquat or has_deceptive_homograph:
                    overrides.append(Override(
                        override_type="ml_override",
                        reason=(
                            "Strong independent impersonation evidence is "
                            "decisive despite the low model score; preserve "
                            "both observations."
                        ),
                        affected_signal="ml_xgboost"
                    ))
                    contradictions.append(
                        f"ML score ({ev.value}) was low, but independent "
                        "impersonation evidence remains decisive."
                    )

            active_evidence.append(ev)

        return active_evidence, overrides, contradictions