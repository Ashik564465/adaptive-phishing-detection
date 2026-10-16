import unittest
from unittest.mock import patch

from src.intelligence.brand_engine import analyze_brand
from src.risk.collector import EvidenceCollector
from src.risk.models import (
    DecisionState,
    Evidence,
    EvidenceDirection,
    EvidenceStrength,
    RiskLevel,
)
from src.risk.risk_engine import RiskEngine


class TestEvidenceFirstFallback(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    @staticmethod
    def evidence(
        source,
        signal,
        direction,
        strength=EvidenceStrength.STRONG,
    ):
        return Evidence(
            source=source,
            signal=signal,
            value=True,
            strength=strength,
            reliability=0.95,
            direction=direction,
            reason=f"{source} reported {signal}",
        )

    def evaluate(
        self,
        evidence,
        ml_result,
        *,
        threat_status="unknown",
        other_source_status="available",
        forensic_status="available",
    ):
        components = {
            "threat_intelligence": {
                "status": threat_status,
                "sources": [
                    {"source": "phishtank", "status": threat_status},
                    {"source": "openphish", "status": threat_status},
                    {"source": "urlhaus", "status": threat_status},
                ],
                "errors": [],
            },
            "brand": {"brand": None, "official_domain": False},
            "typosquatting": {"is_typosquat": False},
            "homograph": {"is_deceptive": False, "has_punycode": False},
            "domain": {
                "status": other_source_status,
                "domain_age_days": 1000,
                "domain_age_known": True,
            },
            "dns": {
                "status": other_source_status,
                "records": {},
                "errors": [],
                "signals": [],
            },
            "tls": {
                "status": other_source_status,
                "certificate": {},
                "signals": [],
            },
            "validated_case": None,
        }
        forensic = {
            "domain": "example.com",
            "status": forensic_status,
            "sources": {
                "dns": {"status": other_source_status},
                "registration": {"status": other_source_status},
                "certificate_transparency": {
                    "status": other_source_status,
                },
                "subdomain_discovery": {
                    "status": other_source_status,
                },
                "ip_asn": {"status": other_source_status},
            },
            "errors": [],
        }

        def collect(url, **kwargs):
            self.assertEqual(url, "https://example.com")
            kwargs["component_details"].update(components)
            if not kwargs.get("include_ml", True):
                kwargs["component_details"]["machine_learning"] = {
                    "status": "not_run",
                    "reason": kwargs.get("ml_not_run_reason"),
                }
            return list(evidence)

        with (
            patch.object(self.engine, "_collect_domain_forensics", return_value=forensic),
            patch.object(
                self.engine,
                "_domain_context_from_forensics",
                return_value=components["domain"],
            ),
            patch.object(
                self.engine,
                "_dns_context_from_forensics",
                return_value=components["dns"],
            ),
            patch.object(
                self.engine,
                "_build_domain_forensics_context",
                return_value={
                    "status": "available",
                    "raw": forensic,
                    "findings": [],
                    "contradictions": [],
                },
            ),
            patch.object(
                self.engine,
                "_investigate_with_rag",
                return_value={"status": "unavailable"},
            ),
            patch.object(
                EvidenceCollector,
                "gather_all_evidence",
                side_effect=collect,
            ) as gather,
            patch(
                "src.risk.collector.predict_url",
                return_value=ml_result,
            ) as predict,
        ):
            result = self.engine.evaluate_url("https://example.com")
        return result, gather, predict

    def test_confirmed_phishing_skips_ml_and_remains_decisive(self):
        finding = self.evidence(
            "threat_intelligence",
            "known_phishing",
            EvidenceDirection.MALICIOUS,
            EvidenceStrength.CRITICAL,
        )
        result, _, predict = self.evaluate(
            [finding],
            {"phishing_probability": 0.01},
            threat_status="known_phishing",
        )
        low_ml = self.evidence(
            "ml_xgboost",
            "phishing_probability",
            EvidenceDirection.BENIGN,
            EvidenceStrength.WEAK,
        )
        self.assertEqual(
            self.engine._compute_decision([finding, low_ml], [])[0],
            DecisionState.PHISHING,
        )
        self.assertEqual(result.decision, DecisionState.PHISHING)
        predict.assert_not_called()
        payload = result.to_dict()
        self.assertFalse(payload["analysis"]["ml_used"])
        self.assertEqual(
            payload["analysis"]["independent_evidence_status"],
            "confirmed_malicious",
        )

    def test_verified_official_identity_skips_ml_without_conflict(self):
        official = self.evidence(
            "brand_engine",
            "official_domain",
            EvidenceDirection.BENIGN,
        )
        result, _, predict = self.evaluate(
            [official],
            {"phishing_probability": 0.999},
        )
        self.assertEqual(result.decision, DecisionState.SAFE)
        predict.assert_not_called()
        payload = result.to_dict()
        self.assertFalse(payload["analysis"]["ml_used"])
        self.assertEqual(
            payload["evidence_sources"]["machine_learning"]["status"],
            "unknown",
        )
        self.assertNotIn("machine_learning", payload["analysis"]["unavailable_sources"])

    def test_inconclusive_independent_sources_use_ml_fallback(self):
        result, gather, predict = self.evaluate(
            [],
            {"raw_model_score": 0.98},
        )
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        gather.assert_called_once()
        gather.assert_called_once_with(
            "https://example.com",
            domain_context=unittest.mock.ANY,
            dns_context=unittest.mock.ANY,
            component_details=unittest.mock.ANY,
            include_ml=False,
            ml_not_run_reason="Independent evidence is being evaluated first.",
        )
        predict.assert_called_once_with("https://example.com")
        analysis = result.to_dict()["analysis"]
        self.assertTrue(analysis["ml_used"])
        self.assertIn(
            analysis["independent_evidence_status"],
            analysis["ml_fallback_reason"],
        )

    def test_unavailable_threat_feeds_use_ml_fallback(self):
        unavailable = self.evidence(
            "threat_intelligence",
            "unknown",
            EvidenceDirection.NEUTRAL,
            EvidenceStrength.WEAK,
        )
        result, _, predict = self.evaluate(
            [unavailable],
            {"status": "unavailable", "error": "model file missing"},
            threat_status="error",
        )
        predict.assert_called_once()
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertIsNone(result.to_dict()["scores"]["ml_raw_score"])
        self.assertIn(
            "machine_learning",
            result.to_dict()["analysis"]["unavailable_sources"],
        )

    def test_all_independent_providers_unavailable_use_ml_fallback(self):
        unavailable = self.evidence(
            "threat_intelligence",
            "unknown",
            EvidenceDirection.NEUTRAL,
            EvidenceStrength.WEAK,
        )
        result, _, predict = self.evaluate(
            [unavailable],
            {"raw_model_score": 0.5},
            threat_status="error",
            other_source_status="unavailable",
            forensic_status="unavailable",
        )
        predict.assert_called_once()
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(
            result.to_dict()["analysis"]["independent_evidence_status"],
            "unavailable",
        )
        self.assertTrue({
            "threat_intelligence",
            "dns",
            "tls",
            "domain_registration",
            "domain_forensics",
        }.issubset(result.to_dict()["analysis"]["unavailable_sources"]))

    def test_high_ml_score_without_independent_support_is_unknown(self):
        result, _, _ = self.evaluate(
            [],
            {"raw_model_score": 0.999},
        )
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(result.decision_basis, "ml_requires_corroboration")

    def test_low_ml_does_not_override_confirmed_malicious_evidence(self):
        malicious = self.evidence(
            "threat_intelligence",
            "known_malware",
            EvidenceDirection.MALICIOUS,
            EvidenceStrength.CRITICAL,
        )
        low_ml = self.evidence(
            "ml_xgboost",
            "phishing_probability",
            EvidenceDirection.BENIGN,
            EvidenceStrength.WEAK,
        )
        decision = self.engine._compute_decision(
            [malicious, low_ml],
            [],
        )
        self.assertEqual(decision[0], DecisionState.MALWARE)
        self.assertEqual(decision[1], RiskLevel.CRITICAL)

    def test_conflicting_identity_and_malicious_evidence_requires_review(self):
        official = self.evidence(
            "brand_engine",
            "official_domain",
            EvidenceDirection.BENIGN,
        )
        anomaly = self.evidence(
            "dns",
            "dns_anomaly",
            EvidenceDirection.MALICIOUS,
            EvidenceStrength.MODERATE,
        )
        result, _, predict = self.evaluate(
            [official, anomaly],
            {"raw_model_score": 0.99},
        )
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(result.decision_basis, "conflicting_evidence")
        predict.assert_called_once()
        analysis = result.to_dict()["analysis"]
        self.assertEqual(
            analysis["independent_evidence_status"],
            "conflicting",
        )
        self.assertTrue(analysis["contradicting_signals"])
        self.assertEqual(
            result.to_dict()["scores"]["ml_raw_score"],
            0.99,
        )
        self.assertTrue(
            any("ML returned an elevated raw score" in item
                for item in result.contradictions)
        )

    def test_lookalike_and_deceptive_subdomains_are_not_official(self):
        lookalike = analyze_brand("https://usa-gov.example.com")
        deceptive = analyze_brand("https://usa.gov.attacker.example/")
        usa_gov = analyze_brand("https://www.usa.gov/")
        self.assertFalse(lookalike["official_domain"])
        self.assertFalse(deceptive["official_domain"])
        self.assertTrue(usa_gov["official_domain"])

    def test_missing_model_is_unavailable_not_benign(self):
        evidence = []
        with patch(
            "src.risk.collector.predict_url",
            return_value={
                "status": "unavailable",
                "error": "model file missing",
            },
        ):
            EvidenceCollector.add_machine_learning_evidence(
                "https://example.com",
                evidence,
            )
        self.assertEqual(evidence, [])

    def test_inconclusive_independent_and_ml_results_remain_unknown(self):
        result, _, _ = self.evaluate(
            [],
            {"raw_model_score": 0.5},
        )
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(result.decision_basis, "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
