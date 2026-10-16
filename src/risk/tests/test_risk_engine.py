import unittest
import json
from contextlib import ExitStack
from unittest.mock import patch
from src.risk.risk_engine import RiskEngine
from src.risk.evidence_sources import normalize_evidence_sources
from src.risk.models import (
    DecisionState,
    Evidence,
    EvidenceDirection,
    EvidenceStrength,
    RiskLevel,
)
from src.intelligence.brand_engine import analyze_brand
from src.intelligence.url_normalizer import normalize_url


def _forensic_result(
    *,
    age_days=1000,
    status="available",
    dns_status="available",
    domain="example.com",
):
    return {
        "domain": domain,
        "subdomains": ["www.example.com"],
        "dns_records": {
            "A": ["203.0.113.10"],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "CNAME": [],
            "TXT": [],
        },
        "dns_interpretations": {
            "record_status": {
                "A": "available",
                "AAAA": "no_answer",
                "MX": "no_answer",
                "NS": "no_answer",
                "CNAME": "no_answer",
                "TXT": "no_answer",
            },
            "null_mx": False,
            "mx_hosts": [],
        },
        "registration": {
            "status": "available" if age_days is not None else "unavailable",
            "retrieval_status": (
                "available" if age_days is not None else "unavailable"
            ),
            "registration_status": (
                "registered" if age_days is not None else "unknown"
            ),
            "data": {
                "creation_date": "2020-01-01T00:00:00+00:00",
                "expiry_date": "2027-01-01T00:00:00+00:00",
                "registrar": "Example Registrar",
                "domain_age_days": age_days,
                "domain_age_known": age_days is not None,
                "nameservers": ["ns1.example.com"],
                "malformed_fields": [],
            } if age_days is not None else None,
            "collected_at": "2026-10-10T10:00:00+00:00",
        },
        "certificate_history": [{
            "id": "ct-1",
            "common_name": None,
            "name_values": ["example.com", "www.example.com"],
            "issuer": None,
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
            "logged_at": None,
        }],
        "certificate_history_status": "available",
        "subdomain_discovery_status": "available",
        "infrastructure": [{
            "ip": "203.0.113.10",
            "prefix": "203.0.113.0/24",
            "asns": [],
            "prefix_status": "available",
            "asn_status": "unavailable",
            "status": "partial",
            "source": "RIPEstat network-info",
        }],
        "collected_at": "2026-10-10T10:00:00+00:00",
        "sources": {
            "dns": {"status": dns_status, "name": "dnspython"},
            "registration": {
                "status": "available" if age_days is not None else "unavailable",
                "name": "RDAP",
            },
            "certificate_transparency": {"status": "available"},
            "subdomain_discovery": {"status": "available"},
            "ip_prefix": {"status": "available"},
            "asn": {"status": "unavailable"},
            "ip_asn": {"status": "partial"},
        },
        "status": status,
        "errors": [],
        "unavailable_evidence": ["asn"] if age_days is not None else [
            "registration",
            "asn",
        ],
    }


class TestEvidenceFusionRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()
        self.forensic_result = _forensic_result()
        self.forensic_patcher = patch(
            "src.risk.risk_engine.investigate_domain",
            return_value=self.forensic_result,
        )
        self.mock_forensics = self.forensic_patcher.start()
        self.addCleanup(self.forensic_patcher.stop)

    def _evaluate_scenario(
        self,
        url,
        *,
        age_days=1000,
        probability=0.5,
        threat_status="unknown",
        brand=None,
        official=False,
        typosquat=False,
        homograph_result=None,
        ml_contributions=None,
        tls_result=None,
    ):
        domain = normalize_url(url)["registered_domain"]
        self.forensic_result = _forensic_result(
            age_days=age_days,
            domain=domain,
        )
        self.mock_forensics.return_value = self.forensic_result
        ti_result = {
            "status": threat_status,
            "known_phishing": threat_status == "known_phishing",
            "known_malware": threat_status == "known_malware",
            "sources": [
                {"source": name, "status": threat_status}
                for name in ("phishtank", "openphish", "urlhaus")
            ],
        }
        with ExitStack() as stack:
            stack.enter_context(patch(
                "src.rag.cases.ValidatedCaseStore.find_for_url",
                return_value=None,
            ))
            self.mock_submitted_ti = stack.enter_context(patch(
                "src.risk.collector.check_threat_intelligence",
                return_value=ti_result,
            ))
            self.mock_submitted_brand = stack.enter_context(patch(
                "src.risk.collector.analyze_brand",
                return_value={
                    "brand": brand,
                    "official_domain": official,
                },
            ))
            stack.enter_context(patch(
                "src.risk.collector.analyze_typosquatting",
                return_value={
                    "is_typosquat": typosquat,
                    "target": "google" if typosquat else None,
                },
            ))
            stack.enter_context(patch(
                "src.risk.collector.analyze_homograph",
                return_value=homograph_result or {
                    "is_deceptive": False,
                    "has_punycode": False,
                },
            ))
            ml_result = (
                {
                    "phishing_probability": probability,
                    "top_feature_contributions": ml_contributions or [],
                }
                if probability is not None
                else {}
            )
            stack.enter_context(patch(
                "src.risk.collector.predict_url",
                return_value=ml_result,
            ))
            stack.enter_context(patch(
                "src.risk.collector.analyze_tls",
                return_value=tls_result or {
                    "status": "unavailable",
                    "certificate": {},
                    "signals": [],
                },
            ))
            stack.enter_context(patch.object(
                self.engine,
                "_investigate_with_rag",
                return_value={"status": "unavailable"},
            ))
            return self.engine.evaluate_url(url)

    def test_forensics_are_called_once_reused_and_serialized(self):
        with (
            patch("src.risk.collector.analyze_domain") as mock_domain,
            patch("src.risk.collector.analyze_dns") as mock_dns,
        ):
            result = self.engine.evaluate_url("https://example.com")

        self.mock_forensics.assert_called_once_with("https://example.com")
        mock_domain.assert_not_called()
        mock_dns.assert_not_called()
        domain_age_signals = [
            item for item in result.evidence
            if item.source == "domain_intelligence"
        ]
        self.assertEqual(len(domain_age_signals), 1)
        self.assertEqual(result.domain["domain_age_days"], 1000)
        self.assertEqual(result.dns["records"]["A"], ["203.0.113.10"])

        payload = result.to_combined_dict()
        forensic = payload["domain_forensics"]
        self.assertNotIn("raw", forensic)
        self.assertIn("findings", forensic)
        self.assertIn("sources", forensic)
        self.assertEqual(forensic["certificate_history_status"], "available")
        self.assertEqual(forensic["subdomain_discovery_status"], "available")
        self.assertEqual(forensic["registration_status"], "available")
        self.assertEqual(forensic["registration_state"], "registered")
        self.assertEqual(
            payload["evidence_sources"]["certificate_transparency"]["status"],
            "available",
        )
        self.assertEqual(
            payload["evidence_sources"]["subdomain_discovery"]["status"],
            "available",
        )
        self.assertFalse(
            payload["evidence_sources"]["certificate_transparency"][
                "decision_impact"
            ]
        )
        self.assertFalse(
            payload["evidence_sources"]["subdomain_discovery"][
                "decision_impact"
            ]
        )
        self.assertEqual(payload["analysis"]["decision"], "unknown")
        expected_probability = next(
            item.value
            for item in result.evidence
            if item.source == "ml_xgboost"
            and item.signal == "phishing_probability"
        )
        self.assertEqual(
            payload["scores"]["ml_phishing_probability"],
            round(expected_probability, 6),
        )
        self.assertNotIn("pipeline", payload)
        self.assertNotIn("infrastructure_checks", payload)
        self.assertNotIn("parsed_domain", payload)
        self.assertEqual(
            json.loads(json.dumps(payload))["analysis"]["decision"],
            "unknown",
        )
        detailed = result.to_combined_dict(include_details=True)
        self.assertEqual(
            detailed["details"]["domain_forensics"],
            self.forensic_result,
        )
        normalized_sources = payload["evidence_sources"]
        required_source_fields = {
            "source",
            "status",
            "observed",
            "findings",
            "evidence_category",
            "reliability",
            "provenance",
            "decision_impact",
            "errors",
        }
        for source, normalized_source in normalized_sources.items():
            with self.subTest(source=source):
                self.assertTrue(
                    required_source_fields.issubset(normalized_source)
                )
                self.assertNotIn("raw_observations", normalized_source)
                self.assertIn(
                    normalized_source["status"],
                    {
                        "available",
                        "partial",
                        "unknown",
                        "unavailable",
                        "error",
                    },
                )
        detailed_sources = detailed["details"]["evidence_sources"]
        self.assertEqual(
            detailed_sources["domain_forensics"]["raw_observations_ref"],
            "details.domain_forensics",
        )
        self.assertFalse(
            detailed_sources["domain_forensics"]["decision_impact"]
        )
        self.assertEqual(normalized_sources["dns"]["status"], "available")
        self.assertEqual(
            normalized_sources["domain_registration"]["observed"][
                "domain_age_days"
            ],
            1000,
        )
        self.assertEqual(
            detailed["analysis"]["decision"],
            payload["analysis"]["decision"],
        )

    def test_normalized_provider_statuses_preserve_partial_and_independent_results(self):
        forensic = _forensic_result(status="partial")
        forensic["certificate_history_status"] = "unavailable"
        forensic["subdomain_discovery_status"] = "available"
        forensic["sources"]["certificate_transparency"] = {
            "status": "unavailable",
            "name": "crt.sh",
        }
        forensic["sources"]["subdomain_discovery"] = {
            "status": "available",
            "name": "crt.sh",
        }
        components = {
            "threat_intelligence": {
                "status": "unknown",
                "sources": [
                    {
                        "source": "phishtank",
                        "status": "error",
                        "error": "provider timeout",
                    },
                    {"source": "openphish", "status": "unknown"},
                    {"source": "urlhaus", "status": "unknown"},
                ],
            },
            "brand_engine": {},
            "dns": {"status": "partial"},
            "typosquatting": {},
            "homograph": {},
            "machine_learning": {},
        }
        normalized = normalize_evidence_sources(
            normalize_url("https://example.com"),
            components,
            forensic,
            [],
            decision_basis="insufficient_evidence",
        )

        self.assertEqual(
            normalized["threat_intelligence"]["status"],
            "partial",
        )
        self.assertEqual(normalized["phishtank"]["status"], "error")
        self.assertEqual(normalized["openphish"]["status"], "unknown")
        self.assertEqual(normalized["urlhaus"]["status"], "unknown")
        self.assertEqual(
            normalized["certificate_transparency"]["status"],
            "unavailable",
        )
        self.assertEqual(
            normalized["subdomain_discovery"]["status"],
            "available",
        )
        self.assertFalse(
            normalized["certificate_transparency"]["decision_impact"]
        )
        self.assertFalse(
            normalized["subdomain_discovery"]["decision_impact"]
        )

    def test_forensic_provider_exception_is_reported_without_crashing(self):
        self.mock_forensics.side_effect = RuntimeError("forensic lookup failed")
        with (
            patch(
                "src.risk.collector.analyze_domain",
                return_value={
                    "domain_age_days": None,
                    "domain_age_known": False,
                },
            ),
            patch(
                "src.risk.collector.analyze_dns",
                return_value={
                    "status": "unavailable",
                    "records": {},
                    "errors": [],
                    "signals": [],
                },
            ),
            patch(
                "src.risk.risk_engine.analyze_domain",
                return_value={"domain_age_days": None},
            ),
            patch(
                "src.risk.risk_engine.analyze_dns",
                return_value={"status": "unavailable", "records": {}},
            ),
            patch("src.risk.collector.analyze_tls", return_value={"signals": []}),
            patch("src.risk.risk_engine.analyze_tls", return_value={"signals": []}),
        ):
            result = self.engine.evaluate_url("https://example.com")

        output = result.to_dict()["domain_forensics"]
        self.assertEqual(output["status"], "unavailable")
        self.assertEqual(output["errors"][0]["status"], "provider_exception")
        self.assertIn("registration", output["unavailable_evidence"])
        json.dumps(result.to_combined_dict())

    def test_malformed_forensic_response_is_explicit(self):
        self.mock_forensics.return_value = None
        with (
            patch(
                "src.risk.collector.analyze_domain",
                return_value={"domain_age_days": None},
            ),
            patch(
                "src.risk.collector.analyze_dns",
                return_value={
                    "status": "unavailable",
                    "records": {},
                    "errors": [],
                    "signals": [],
                },
            ),
            patch(
                "src.risk.risk_engine.analyze_domain",
                return_value={"domain_age_days": None},
            ),
            patch(
                "src.risk.risk_engine.analyze_dns",
                return_value={"status": "unavailable", "records": {}},
            ),
            patch("src.risk.collector.analyze_tls", return_value={"signals": []}),
            patch("src.risk.risk_engine.analyze_tls", return_value={"signals": []}),
        ):
            result = self.engine.evaluate_url("https://example.com")

        forensic = result.to_dict()["domain_forensics"]
        self.assertEqual(forensic["status"], "unavailable")
        self.assertEqual(forensic["errors"][0]["status"], "malformed_result")

    def test_partial_forensics_preserve_successful_dns_and_errors(self):
        self.forensic_result = _forensic_result(
            age_days=None,
            status="partial",
            dns_status="partial",
        )
        self.mock_forensics.return_value = self.forensic_result
        self.forensic_result["errors"] = [{
            "source": "registration",
            "message": "RDAP timeout",
        }]
        result = self.engine.evaluate_url("https://example.com")
        forensic = result.to_dict()["domain_forensics"]

        self.assertEqual(result.dns["status"], "partial")
        self.assertEqual(result.dns["records"]["A"], ["203.0.113.10"])
        self.assertEqual(forensic["errors"], self.forensic_result["errors"])
        self.assertIn("registration", forensic["unavailable_evidence"])

    @patch("src.risk.collector.predict_url")
    @patch("src.risk.collector.analyze_homograph")
    @patch("src.risk.collector.analyze_typosquatting")
    @patch("src.risk.collector.analyze_brand")
    @patch("src.risk.collector.check_threat_intelligence")
    def test_high_ml_and_old_domain_do_not_treat_maturity_as_benign_evidence(
        self,
        mock_ti,
        mock_brand,
        mock_typo,
        mock_homo,
        mock_ml,
    ):
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.99}

        result = self.engine.evaluate_url("https://example.com")
        forensic = result.to_dict()["domain_forensics"]

        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(result.decision_basis, "ml_requires_corroboration")
        self.assertEqual(result.recommended_action, "monitor")
        self.assertEqual(result.confidence, 55)
        self.assertFalse(any(
            item["name"] == "domain_maturity"
            and item["influenced_decision"]
            for item in forensic["findings"]
        ))
        self.assertEqual(result.evidence_agreement, "moderate_agreement")
        self.assertTrue(any(
            item.signal == "phishing_probability"
            for item in result.evidence
        ))
        self.assertIn(
            "independent evidence is insufficient",
            result.to_combined_dict()["analysis"]["summary"],
        )

    def test_recent_registration_only_corroborates_a_high_ml_signal(self):
        for age_days, expected in (
            (4, DecisionState.SUSPICIOUS),
            (29, DecisionState.SUSPICIOUS),
            (30, DecisionState.UNKNOWN),
        ):
            with self.subTest(age_days=age_days):
                result = self._evaluate_scenario(
                    "https://new-example.invalid",
                    age_days=age_days,
                    probability=0.99,
                )
                payload = result.to_combined_dict()

                self.assertEqual(result.decision, expected)
                if age_days < 30:
                    self.assertEqual(
                        result.decision_basis,
                        "corroborated_ml_suspicion",
                    )
                    maturity = next(
                        item for item in payload["domain_forensics"]["findings"]
                        if item["name"] == "domain_maturity"
                    )
                    self.assertTrue(maturity["influenced_decision"])
                    self.assertEqual(maturity["importance"], "supporting")
                    registration_source = payload["evidence_sources"][
                        "domain_registration"
                    ]
                    self.assertTrue(registration_source["decision_impact"])
                    self.assertTrue(any(
                        item["signal"] == "recent_registration_corroborates_ml"
                        for item in registration_source["findings"]
                    ))
                    self.assertEqual(
                        payload["scores"]["final_risk_score"],
                        50,
                    )
                    self.assertEqual(
                        payload["scores"]["ml_raw_score"],
                        0.99,
                    )
                else:
                    self.assertEqual(
                        result.decision_basis,
                        "ml_requires_corroboration",
                    )

    @patch("src.risk.collector.analyze_tls")
    @patch("src.risk.risk_engine.analyze_tls")
    @patch("src.risk.collector.predict_url")
    @patch("src.risk.collector.analyze_homograph")
    @patch("src.risk.collector.analyze_typosquatting")
    @patch("src.risk.collector.analyze_brand")
    @patch("src.risk.collector.check_threat_intelligence")
    def test_confirmed_threat_remains_phishing_with_valid_tls(
        self,
        mock_ti,
        mock_brand,
        mock_typo,
        mock_homo,
        mock_ml,
        _mock_tls_collect,
        _mock_tls_engine,
    ):
        mock_ti.return_value = "known_phishing"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.1}
        valid_tls = {
            "status": "available",
            "certificate": {"hostname_match": True},
            "signals": [],
        }
        _mock_tls_collect.return_value = valid_tls
        _mock_tls_engine.return_value = valid_tls

        result = self.engine.evaluate_url("https://example.com")

        self.assertEqual(result.decision, DecisionState.PHISHING)
        self.assertEqual(result.domain_forensics["contradictions"], [])
        self.assertEqual(result.evidence_agreement, "moderate_agreement")

    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_01_official_domain_safe(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml):
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": "Google", "official_domain": True}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.05}

        result = self.engine.evaluate_url("https://google.com")
        self.assertEqual(result.decision, DecisionState.SAFE)
        self.assertEqual(result.decision_basis, "official_identity_verified")

    def test_established_legitimate_domain_has_zero_weighted_score_not_zero_probability(self):
        result = self._evaluate_scenario(
            "https://google.com",
            age_days=3000,
            probability=0.05,
            brand="Google",
            official=True,
            tls_result={
                "status": "available",
                "source": "tls_handshake",
                "collected_at": "2026-10-10T10:00:00+00:00",
                "certificate": {
                    "hostname_match": True,
                    "san_matched": True,
                    "validity_status": "valid",
                    "valid_at_observation": True,
                    "observed_at": "2026-10-10T10:00:00+00:00",
                    "valid_from": "Oct 10 00:00:00 2025 GMT",
                    "valid_until": "Oct 10 00:00:00 2027 GMT",
                },
                "signals": [],
            },
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.SAFE)
        self.assertEqual(result.risk_score, 0)
        self.assertIsNone(payload["scores"]["ml_phishing_probability"])
        self.assertEqual(payload["scores"]["final_risk_score"], 0)
        self.assertEqual(payload["analysis"]["decision"], "safe")
        legacy = result.to_pipeline_dict()
        self.assertEqual(legacy["final_decision"], "LEGITIMATE")
        self.assertIsNone(legacy["phishing_score"])
        self.assertEqual(payload["analysis"]["risk_level"], "low")
        self.assertEqual(payload["analysis"]["decision_basis"], "official_identity_verified")
        self.assertEqual(payload["analysis"]["recommended_action"], "allow")
        self.assertEqual(payload["analysis"]["confidence"], 80.0)
        self.assertTrue(payload["identity"]["official_domain"])
        self.assertNotIn(
            "tls_hostname_verified",
            {
                item["signal"]
                for item in payload["reasoning"]["positive_signals"]
            },
        )
        maturity = next(
            item for item in payload["domain_forensics"]["findings"]
            if item["name"] == "domain_maturity"
        )
        self.assertFalse(maturity["influenced_decision"])
        self.assertTrue(payload["tls"]["valid_at_observation"])
        self.assertIsNotNone(payload["tls"]["certificate_observed_at"])
        self.assertIn("non-positive", payload["scores"]["score_range"])

    def test_new_registration_is_context_only_and_does_not_establish_phishing(self):
        result = self._evaluate_scenario(
            "https://new-example.invalid",
            age_days=4,
            probability=0.5,
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        legacy = result.to_pipeline_dict()
        self.assertEqual(legacy["final_decision"], "UNKNOWN")
        self.assertEqual(legacy["phishing_score"], 0.5)
        self.assertEqual(result.evidence_agreement, "insufficient")
        self.assertFalse(next(
            item for item in payload["domain_forensics"]["findings"]
            if item["name"] == "domain_maturity"
        )["influenced_decision"])
        age_evidence = next(
            item for item in result.evidence
            if item.source == "domain_intelligence"
        )
        self.assertEqual(age_evidence.direction.value, "neutral")

    def test_phishing_looking_hostname_on_hosting_platform_keeps_conflict(self):
        result = self._evaluate_scenario(
            "https://google.github.io",
            age_days=2000,
            probability=0.05,
            brand="Google",
            tls_result={
                "status": "available",
                "certificate": {"hostname_match": True, "san_matched": True},
                "signals": [],
            },
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertEqual(result.evidence_agreement, "strong_contradiction")
        self.assertTrue(payload["identity"]["brand_mismatch"])
        self.assertTrue(payload["reasoning"]["contradictions"])
        self.assertFalse(next(
            item for item in payload["domain_forensics"]["findings"]
            if item["name"] == "domain_maturity"
        )["influenced_decision"])

    def test_brand_impersonation_overrides_benign_ml(self):
        result = self._evaluate_scenario(
            "https://g00gle.com",
            age_days=2,
            probability=0.05,
            typosquat=True,
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertTrue(payload["identity"]["typosquatting"])
        self.assertEqual(result.evidence_agreement, "strong_contradiction")
        self.assertEqual(
            payload["analysis"]["decision_basis"],
            "unconfirmed_impersonation_signal",
        )

    def test_unavailable_threat_providers_are_unknown_not_clean(self):
        result = self._evaluate_scenario(
            "https://unknown-example.invalid",
            age_days=None,
            probability=0.5,
            threat_status="error",
        )
        payload = result.to_combined_dict()

        self.assertEqual(payload["threat_intelligence"]["status"], "error")
        self.assertEqual(
            set(payload["threat_intelligence"]["sources"].values()),
            {"error"},
        )
        self.assertFalse(payload["threat_intelligence"]["known_phishing"])
        self.assertFalse(payload["threat_intelligence"]["known_malware"])
        self.assertEqual(result.evidence_agreement, "insufficient")
        self.assertEqual(
            payload["evidence_sources"]["threat_intelligence"]["status"],
            "error",
        )
        self.assertEqual(
            {
                payload["evidence_sources"][provider]["status"]
                for provider in ("phishtank", "openphish", "urlhaus")
            },
            {"error"},
        )

    def test_missing_or_invalid_ml_probability_is_null_and_creates_no_ml_vote(self):
        for probability in (None, float("nan"), 1.01):
            with self.subTest(probability=probability):
                result = self._evaluate_scenario(
                    "https://unknown-example.invalid",
                    age_days=None,
                    probability=probability,
                )
                payload = result.to_combined_dict()

                self.assertIsNone(payload["scores"]["ml_phishing_probability"])
                self.assertFalse(any(
                    item.source == "ml_xgboost"
                    for item in result.evidence
                ))
                self.assertEqual(result.evidence_agreement, "insufficient")

    def test_invalid_tls_is_warning_not_brand_identity_or_phishing_proof(self):
        result = self._evaluate_scenario(
            "https://unknown-example.invalid",
            age_days=None,
            probability=0.5,
            tls_result={
                "status": "error",
                "source": "tls_handshake",
                "collected_at": "2026-10-10T10:00:00+00:00",
                "certificate": {
                    "hostname_match": None,
                    "validity_status": "invalid",
                    "validation_status": "invalid",
                    "valid_at_observation": None,
                },
                "signals": [{
                    "signal": "tls_certificate_invalid",
                    "severity": "medium",
                }],
            },
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(payload["tls"]["validity_status"], "invalid")
        self.assertEqual(payload["tls"]["validation_status"], "invalid")
        self.assertIsNone(payload["tls"]["valid_at_observation"])
        self.assertIsNone(payload["identity"]["detected_brand"])
        self.assertNotEqual(payload["analysis"]["decision"], "safe")

    def test_invalid_tls_only_supports_review_when_ml_is_also_high(self):
        result = self._evaluate_scenario(
            "https://unknown-example.invalid",
            age_days=1000,
            probability=0.99,
            tls_result={
                "status": "error",
                "certificate": {
                    "hostname_match": None,
                    "validity_status": "invalid",
                    "validation_status": "invalid",
                    "valid_at_observation": False,
                },
                "signals": [{
                    "signal": "tls_certificate_invalid",
                    "severity": "medium",
                }],
            },
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertEqual(
            result.decision_basis,
            "corroborated_ml_suspicion",
        )
        self.assertEqual(payload["analysis"]["recommended_action"], "quarantine")
        self.assertEqual(payload["analysis"]["confidence"], 55.0)
        self.assertEqual(payload["analysis"]["decision"], "suspicious")

    def test_verified_official_identity_outweighs_ml_only_high_score(self):
        result = self._evaluate_scenario(
            "https://google.com",
            age_days=3000,
            probability=0.99,
            brand="Google",
            official=True,
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.SAFE)
        self.assertEqual(result.risk_level, RiskLevel.LOW)
        self.assertEqual(result.decision_basis, "official_identity_verified")
        self.assertEqual(result.evidence_agreement, "moderate_agreement")
        self.assertEqual(
            payload["reasoning"]["evidence_agreement"],
            "moderate_agreement",
        )
        self.assertFalse(payload["reasoning"]["contradictions"])
        self.assertIsNone(payload["scores"]["ml_phishing_probability"])
        self.assertEqual(payload["analysis"]["confidence"], 80.0)
        self.assertEqual(payload["analysis"]["recommended_action"], "allow")
        self.assertEqual(payload["scores"]["final_risk_score"], 0)
        self.assertIn("official Google domain", payload["analysis"]["summary"])
        self.assertEqual(payload["analysis"]["risk_level"], "low")
        self.assertEqual(payload["analysis"]["decision"], "safe")
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"][
                "risk_increasing_evidence_points"
            ],
            0,
        )
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"][
                "risk_mitigating_evidence_points"
            ],
            50,
        )
        self.assertFalse(payload["analysis"]["ml_used"])

    def test_sbi_redirect_path_does_not_change_submitted_url_analysis(self):
        result = self._evaluate_scenario(
            "https://sbi.co.in/redirect/",
            age_days=8745,
            probability=0.9986900687217712,
            brand="Sbi",
            official=True,
            ml_contributions=[{
                "feature": "path_length",
                "value": 10,
                "contribution": 6.3663,
            }],
            tls_result={
                "status": "available",
                "certificate": {
                    "hostname_match": True,
                    "valid_at_observation": True,
                },
                "signals": [],
            },
        )
        payload = result.to_combined_dict()

        self.assertEqual(payload["analysis"]["decision"], "safe")
        self.assertEqual(payload["analysis"]["risk_level"], "low")
        self.assertEqual(payload["analysis"]["decision_basis"], "official_identity_verified")
        self.assertEqual(payload["analysis"]["recommended_action"], "allow")
        self.assertGreaterEqual(payload["analysis"]["confidence"], 0)
        self.assertLessEqual(payload["analysis"]["confidence"], 100)
        self.assertIsNone(payload["scores"]["ml_phishing_probability"])
        self.assertEqual(payload["scores"]["final_risk_score"], 0)
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"]["decision"],
            payload["analysis"]["decision"],
        )
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"]["decision_basis"],
            payload["analysis"]["decision_basis"],
        )
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"][
                "recommended_action"
            ],
            payload["analysis"]["recommended_action"],
        )
        self.assertIn("non-positive net", payload["scores"]["final_risk_score_explanation"]["meaning"])
        self.assertFalse(payload["reasoning"]["contradictions"])
        self.assertFalse(payload["analysis"]["ml_used"])
        self.assertEqual(payload["url"], "https://sbi.co.in/redirect/")
        self.assertNotIn("redirect_inspection", payload["evidence_sources"])
        self.assertNotIn("redirect_destination", payload["identity"])
        self.assertNotIn("redirect_destination", payload["threat_intelligence"])
        self.assertNotIn("redirect_inspection", result.collection_details)
        self.mock_submitted_ti.assert_called_once_with(
            "https://sbi.co.in/redirect/"
        )
        self.mock_submitted_brand.assert_called_once_with(
            "https://sbi.co.in/redirect/"
        )
        self.assertFalse(any(
            item.signal == "domain_intelligence"
            and item.direction != EvidenceDirection.NEUTRAL
            for item in result.evidence
        ))

    def test_path_and_query_are_preserved_without_analyzing_another_url(self):
        submitted_url = (
            "https://sbi.co.in/redirect/"
            "?next=https%3A%2F%2Fexternal.example%2Flogin"
        )
        result = self._evaluate_scenario(
            submitted_url,
            probability=0.2,
            brand="Sbi",
            official=True,
        )
        payload = result.to_combined_dict()

        self.assertEqual(payload["url"], submitted_url)
        self.assertEqual(normalize_url(submitted_url)["path"], "/redirect/")
        self.assertEqual(
            normalize_url(submitted_url)["query"],
            "next=https%3A%2F%2Fexternal.example%2Flogin",
        )
        self.mock_submitted_ti.assert_called_once_with(submitted_url)
        self.mock_submitted_brand.assert_called_once_with(submitted_url)
        self.assertNotIn("redirect_inspection", payload["evidence_sources"])
        self.assertNotIn("redirect_destination", payload["identity"])

    def test_confirmed_feed_conflict_with_official_identity_is_preserved(self):
        result = self._evaluate_scenario(
            "https://google.com",
            age_days=3000,
            probability=0.05,
            threat_status="known_phishing",
            brand="Google",
            official=True,
        )
        payload = result.to_combined_dict()

        self.assertEqual(result.decision, DecisionState.PHISHING)
        self.assertEqual(result.evidence_agreement, "strong_contradiction")
        self.assertTrue(any(
            "threat-intelligence" in item["description"]
            for item in payload["reasoning"]["contradictions"]
        ))
        self.assertTrue(payload["identity"]["official_domain"])
        self.assertTrue(payload["threat_intelligence"]["known_phishing"])
        self.assertEqual(payload["analysis"]["risk_level"], "critical")
        self.assertEqual(payload["analysis"]["decision_basis"], "known_threat_intelligence")
        self.assertEqual(payload["analysis"]["recommended_action"], "block")
        self.assertEqual(payload["scores"]["final_risk_score"], 50)

    def test_confirmed_feed_remains_decisive_with_high_ml_and_official_identity(self):
        result = self._evaluate_scenario(
            "https://google.com",
            age_days=3000,
            probability=0.99,
            threat_status="known_phishing",
            brand="Google",
            official=True,
        )
        payload = result.to_combined_dict()

        self.assertEqual(payload["analysis"]["decision"], "phishing")
        self.assertEqual(payload["analysis"]["risk_level"], "critical")
        self.assertEqual(
            payload["analysis"]["decision_basis"],
            "known_threat_intelligence",
        )
        self.assertEqual(payload["analysis"]["recommended_action"], "block")
        self.assertIsNone(payload["scores"]["ml_phishing_probability"])

    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_10_ml_false_positive_downgrade(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml):
        # Case 2 & 10: Accounts.google.com with high ML prob
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": "Google", "official_domain": True}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.99}  # ML False Positive

        result = self.engine.evaluate_url("https://accounts.google.com")
        
        self.assertEqual(result.decision, DecisionState.SAFE)
        self.assertEqual(result.decision_basis, "official_identity_verified")
        self.assertFalse(any(o.override_type == "ml_downgrade" for o in result.overrides))
        self.assertEqual(result.risk_level, RiskLevel.LOW)
        payload = result.to_combined_dict()
        self.assertIsNone(payload["scores"]["ml_raw_score"])
        self.assertFalse(payload["analysis"]["ml_used"])

    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_03_brand_impersonation(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml):
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": "Google", "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.88}

        result = self.engine.evaluate_url("https://google.com.evil.com/login")
        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertEqual(
            result.decision_basis,
            "unconfirmed_impersonation_signal",
        )

    @patch('src.risk.collector.analyze_tls')
    @patch('src.risk.risk_engine.analyze_tls')
    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_11_ml_false_negative_typosquat(
        self,
        mock_ti,
        mock_brand,
        mock_typo,
        mock_homo,
        mock_ml,
        mock_tls_engine,
        mock_tls_collector,
    ):
        # Case 4, 5 & 11: Typosquatting missed by ML
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": True, "target": "google"}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.10} # ML False Negative
        mock_tls_engine.return_value = {"status": "unavailable", "signals": []}
        mock_tls_collector.return_value = {
            "status": "unavailable",
            "certificate": {},
            "signals": [],
        }

        result = self.engine.evaluate_url("https://gooogle.com")
        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertTrue(any(o.override_type == "ml_override" for o in result.overrides))

    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_07_known_phishing(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml):
        mock_ti.return_value = "known_phishing"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.95}

        result = self.engine.evaluate_url("https://bad-phish.com")
        self.assertEqual(result.decision, DecisionState.PHISHING)
        self.assertEqual(result.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(result.decision_basis, "known_threat_intelligence")

    @patch('src.risk.collector.analyze_tls')
    @patch('src.risk.collector.analyze_dns')
    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_12_dns_tls_priority(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml, mock_dns, mock_tls):
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.15}
        mock_dns.return_value = {"status": "no_records", "signals": [{"signal": "no_mx_record"}]}
        mock_tls.return_value = {"signals": [{"signal": "tls_hostname_mismatch", "severity": "high"}]}
        self.forensic_result = _forensic_result(
            status="partial",
            dns_status="no_records",
        )
        self.forensic_result["dns_records"] = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "CNAME": [],
            "TXT": [],
        }
        self.mock_forensics.return_value = self.forensic_result

        result = self.engine.evaluate_url("https://misconfigured-example.test")
        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertEqual(result.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(
            result.decision_basis,
            "unconfirmed_impersonation_signal",
        )
        self.assertFalse(any(e.signal == "dns_anomaly" for e in result.malicious_signals))
        self.assertTrue(any(e.signal == "tls_hostname_mismatch" for e in result.malicious_signals))

    def test_dns_absence_does_not_create_malicious_evidence(self):
        result = self._evaluate_scenario(
            "https://no-mx.example",
            age_days=None,
            probability=0.5,
        )
        self.assertFalse(any(
            item.signal == "dns_anomaly"
            for item in result.malicious_signals
        ))
        self.assertEqual(result.decision, DecisionState.UNKNOWN)

    def test_module_brand_schema_maps_registered_identity_and_mismatch(self):
        with (
            patch(
                "src.risk.collector.analyze_brand",
                return_value={
                    "registered_domain": "attacker.example",
                    "detected_brands": ["Google"],
                    "official_brand_matches": [],
                    "brand": "Google",
                    "official_domain": False,
                    "brand_mismatch": True,
                    "brand_match_method": "exact_hostname_label",
                },
            ),
            patch(
                "src.risk.collector.analyze_typosquatting",
                return_value={"possible_typosquatting": False},
            ),
            patch(
                "src.risk.collector.analyze_homograph",
                return_value={"is_deceptive": False, "has_punycode": False},
            ),
            patch(
                "src.risk.collector.check_threat_intelligence",
                return_value="unknown",
            ),
            patch(
                "src.risk.collector.predict_url",
                return_value={"phishing_probability": 0.1},
            ),
            patch(
                "src.risk.collector.analyze_tls",
                return_value={"status": "unavailable", "signals": []},
            ),
            patch.object(
                self.engine,
                "_investigate_with_rag",
                return_value={"status": "unavailable"},
            ),
        ):
            result = self.engine.evaluate_url(
                "https://google.attacker.example"
            )

        self.assertTrue(result.to_combined_dict()["identity"]["brand_mismatch"])
        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)

    def test_high_ml_with_verified_vit_identity_is_legitimate(self):
        result = self._evaluate_scenario(
            "https://vtop.vit.ac.in/vtop/open/page",
            age_days=4000,
            probability=0.999,
            brand="VIT",
            official=True,
            tls_result={
                "status": "available",
                "certificate": {"hostname_match": True},
                "signals": [],
            },
        )
        payload = result.to_combined_dict()
        self.assertEqual(result.decision, DecisionState.SAFE)
        self.assertEqual(result.decision_basis, "official_identity_verified")
        self.assertTrue(payload["identity"]["official_domain"])
        self.assertIsNone(payload["scores"]["ml_phishing_probability"])
        self.assertFalse(payload["analysis"]["ml_used"])
        self.assertEqual(payload["analysis"]["recommended_action"], "allow")
        self.assertEqual(payload["analysis"]["risk_level"], "low")
        self.assertEqual(payload["scores"]["final_risk_score"], 0)
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"][
                "risk_increasing_evidence_points"
            ],
            0,
        )
        self.assertEqual(
            payload["scores"]["final_risk_score_explanation"][
                "risk_mitigating_evidence_points"
            ],
            50,
        )
        self.assertFalse(
            payload["evidence_sources"]["domain_forensics"]["decision_impact"]
        )
        self.assertFalse(
            payload["evidence_sources"]["dns"]["decision_impact"]
        )
        self.assertFalse(
            payload["evidence_sources"]["domain_registration"][
                "decision_impact"
            ]
        )
        for finding_name in (
            "domain_maturity",
            "dns_observation",
            "certificate_transparency_history",
            "passive_subdomain_discovery",
            "network_infrastructure",
        ):
            finding = next(
                item for item in payload["domain_forensics"]["findings"]
                if item["name"] == finding_name
            )
            self.assertFalse(finding["influenced_decision"])

    def test_punycode_is_review_context_not_mixed_script_fact(self):
        result = self._evaluate_scenario(
            "https://xn--e1afmkfd.example",
            age_days=None,
            probability=0.1,
            homograph_result={
                "is_deceptive": False,
                "has_punycode": True,
                "mixed_scripts": False,
                "has_confusable_characters": False,
            },
        )
        payload = result.to_combined_dict()
        self.assertEqual(result.decision, DecisionState.SUSPICIOUS)
        self.assertEqual(result.decision_basis, "punycode_domain_review")
        self.assertTrue(payload["identity"]["punycode"])
        self.assertFalse(payload["identity"]["mixed_script"])

    def test_correlated_identity_detectors_are_not_double_counted_in_score(self):
        correlated_identity_evidence = [
            Evidence(
                source=source,
                signal=signal,
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.9,
                direction=EvidenceDirection.MALICIOUS,
                reason="test evidence",
            )
            for source, signal in (
                ("brand_engine", "brand_mismatch"),
                ("typosquatting", "typosquat_detected"),
                ("homograph", "mixed_script_deception"),
            )
        ]

        score = self.engine._calculate_risk_score(
            correlated_identity_evidence,
            [],
        )

        self.assertEqual(score, 50)

    def test_ml_threshold_boundaries_are_explicit(self):
        for probability, expected_direction, expected_strength in (
            (0.85, EvidenceDirection.MALICIOUS, EvidenceStrength.MODERATE),
            (0.95, EvidenceDirection.MALICIOUS, EvidenceStrength.STRONG),
            (0.15, EvidenceDirection.NEUTRAL, EvidenceStrength.WEAK),
            (0.149, EvidenceDirection.BENIGN, EvidenceStrength.WEAK),
        ):
            with self.subTest(probability=probability):
                result = self._evaluate_scenario(
                    "https://boundary-example.invalid",
                    age_days=None,
                    probability=probability,
                )
                ml = next(
                    item for item in result.evidence
                    if item.source == "ml_xgboost"
                )
                self.assertEqual(ml.direction, expected_direction)
                self.assertEqual(ml.strength, expected_strength)

    def test_weighted_score_clamps_both_bounds(self):
        positive = [
            Evidence(
                source="threat_intelligence",
                signal=f"critical_{index}",
                value=True,
                strength=EvidenceStrength.CRITICAL,
                reliability=0.99,
                direction=EvidenceDirection.MALICIOUS,
                reason="confirmed threat",
            )
            for index in range(3)
        ]
        negative = [
            Evidence(
                source="brand_engine",
                signal="official_domain",
                value=True,
                strength=EvidenceStrength.STRONG,
                reliability=0.95,
                direction=EvidenceDirection.BENIGN,
                reason="verified identity",
            )
        ]
        self.assertEqual(
            self.engine._calculate_risk_score(positive, []),
            100,
        )
        self.assertEqual(
            self.engine._calculate_risk_score([], negative),
            0,
        )

    @patch('src.risk.collector.analyze_tls')
    @patch('src.risk.collector.analyze_dns')
    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_ml_alone_is_not_a_verdict_even_with_old_domain_and_valid_tls(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml, mock_dns, mock_tls):
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.99}
        mock_dns.return_value = {"status": "available", "signals": []}
        mock_tls.return_value = {
            "status": "available",
            "certificate": {"hostname_match": True},
            "signals": [],
        }
        self.forensic_result = _forensic_result(domain="vit.ac.in")
        self.forensic_result["subdomains"] = ["www.vit.ac.in"]
        self.forensic_result["dns_records"]["A"] = ["203.0.113.10"]
        self.forensic_result["registration"]["data"]["domain_age_days"] = 1000
        self.mock_forensics.return_value = self.forensic_result
        with patch(
            "src.risk.risk_engine.analyze_tls",
            return_value={
                "status": "available",
                "certificate": {"hostname_match": True},
                "signals": [],
            },
        ):
            result = self.engine.evaluate_url("https://www.vit.ac.in")

        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(
            result.decision_basis,
            "ml_requires_corroboration",
        )
        self.assertEqual(result.to_pipeline_dict()["final_decision"], "UNKNOWN")
        self.assertEqual(result.domain_forensics["contradictions"], [])

    def test_vit_domain_is_not_misidentified_as_vi_brand(self):
        brand_result = analyze_brand("https://www.vit.ac.in")
        self.assertNotIn("vi", brand_result["detected_brands"])
        self.assertFalse(brand_result["brand_mismatch"])
        self.assertTrue(brand_result["official_domain"])
        self.assertEqual(brand_result["brand"], "vit")

    def test_aws_hosted_brand_relationship_is_explicit_and_boundary_safe(self):
        aws_apex = analyze_brand("https://aws.amazon.com")
        aws_www = analyze_brand("https://www.aws.amazon.com")
        amazon_apex = analyze_brand("https://amazon.com")
        aws_attacker_suffix = analyze_brand(
            "https://aws.amazon.com.attacker.com"
        )
        aws_substring = analyze_brand("https://aws-example.com")
        vit_www = analyze_brand("https://www.vit.ac.in")
        vit_attacker_suffix = analyze_brand(
            "https://vit.ac.in.attacker.com"
        )

        for result in (aws_apex, aws_www):
            with self.subTest(hostname=result["hostname"]):
                self.assertEqual(result["registered_domain"], "amazon.com")
                self.assertNotIn("aws", result["registered_brand_matches"])
                self.assertEqual(
                    result["verified_hosted_brand_matches"],
                    ["aws"],
                )
                self.assertIn("aws", result["official_brand_matches"])
                self.assertEqual(
                    result["brand_match_method"],
                    "verified_hosted_hostname",
                )
                self.assertTrue(result["official_domain"])
                self.assertFalse(result["brand_mismatch"])
                self.assertEqual(result["brand"], "aws")

        self.assertIn("amazon", amazon_apex["registered_brand_matches"])
        self.assertNotIn(
            "aws",
            amazon_apex["verified_hosted_brand_matches"],
        )
        self.assertTrue(amazon_apex["official_domain"])
        self.assertFalse(aws_attacker_suffix["official_domain"])
        self.assertTrue(aws_attacker_suffix["brand_mismatch"])
        self.assertFalse(aws_substring["official_domain"])
        self.assertNotIn("aws", aws_substring["detected_brands"])
        self.assertTrue(vit_www["official_domain"])
        self.assertFalse(vit_www["brand_mismatch"])
        self.assertFalse(vit_attacker_suffix["official_domain"])
        self.assertTrue(vit_attacker_suffix["brand_mismatch"])

    def test_official_brand_subdomains_and_attacker_suffixes_use_boundaries(self):
        official = analyze_brand("https://accounts.google.com")
        deceptive = analyze_brand("https://google.com.attacker.example")
        official_parent_with_foreign_brand = analyze_brand(
            "https://google.vit.ac.in"
        )
        unlisted_vit_subdomain = analyze_brand("https://portal.vit.ac.in")
        official_vit_apex = analyze_brand("https://vit.ac.in")
        official_vit_vtop = analyze_brand("https://vtop.vit.ac.in")
        normalized_vit_vtop = analyze_brand("HTTPS://VTOP.VIT.AC.IN./vtop")
        official_sbi = analyze_brand("https://sbi.co.in")

        self.assertTrue(official["official_domain"])
        self.assertFalse(official["brand_mismatch"])
        self.assertFalse(deceptive["official_domain"])
        self.assertTrue(deceptive["brand_mismatch"])
        self.assertFalse(official_parent_with_foreign_brand["official_domain"])
        self.assertTrue(official_parent_with_foreign_brand["brand_mismatch"])
        self.assertFalse(unlisted_vit_subdomain["official_domain"])
        self.assertFalse(unlisted_vit_subdomain["brand_mismatch"])
        self.assertTrue(official_vit_apex["official_domain"])
        self.assertEqual(official_vit_apex["brand"], "vit")
        self.assertTrue(official_vit_vtop["official_domain"])
        self.assertTrue(normalized_vit_vtop["official_domain"])
        self.assertTrue(official_sbi["official_domain"])
        self.assertEqual(official_sbi["brand"], "sbi")

    def test_required_regression_urls_run_through_serializable_pipeline(self):
        urls = (
            "https://example.com",
            "https://vit.ac.in",
            "https://www.vit.ac.in",
            "https://vtop.vit.ac.in/vtop/open/page",
            "https://portal.vit.ac.in",
            "https://sbi.co.in",
            "https://sbi.co.in/redirect/",
            "https://www.google.com",
            "https://g00gle.com",
            "https://www.usa.gov/",
            "https://usa.gov.attacker.example/",
            "https://paypa1.com",
            "https://micros0ft.com",
            "https://google.com.attacker.example.com/login",
            "https://accounts.google.com@attacker.example.com/login",
            "https://google.vit.ac.in",
            "https://aws.amazon.com",
            "https://www.aws.amazon.com",
            "https://amazon.com",
            "https://aws.amazon.com.attacker.com",
            "https://aws-example.com",
            "https://vit.ac.in.attacker.com",
        )
        expected_decisions = {
            "https://example.com": DecisionState.UNKNOWN,
            "https://vit.ac.in": DecisionState.SAFE,
            "https://www.vit.ac.in": DecisionState.SAFE,
            "https://vtop.vit.ac.in/vtop/open/page": DecisionState.SAFE,
            "https://portal.vit.ac.in": DecisionState.UNKNOWN,
            "https://sbi.co.in": DecisionState.SAFE,
            "https://sbi.co.in/redirect/": DecisionState.SAFE,
            "https://www.google.com": DecisionState.SAFE,
            "https://www.usa.gov/": DecisionState.SAFE,
            "https://usa.gov.attacker.example/": DecisionState.UNKNOWN,
            "https://g00gle.com": DecisionState.SUSPICIOUS,
            "https://paypa1.com": DecisionState.SUSPICIOUS,
            "https://micros0ft.com": DecisionState.SUSPICIOUS,
            "https://google.com.attacker.example.com/login": DecisionState.SUSPICIOUS,
            "https://accounts.google.com@attacker.example.com/login": DecisionState.UNKNOWN,
            "https://google.vit.ac.in": DecisionState.SUSPICIOUS,
            "https://aws.amazon.com": DecisionState.SAFE,
            "https://www.aws.amazon.com": DecisionState.SAFE,
            "https://amazon.com": DecisionState.SAFE,
            "https://aws.amazon.com.attacker.com": DecisionState.SUSPICIOUS,
            "https://aws-example.com": DecisionState.UNKNOWN,
            "https://vit.ac.in.attacker.com": DecisionState.SUSPICIOUS,
        }
        with (
            patch(
                "src.risk.collector.check_threat_intelligence",
                return_value="unknown",
            ),
            patch(
                "src.risk.collector.predict_url",
                return_value={"phishing_probability": 0.1},
            ),
            patch(
                "src.risk.collector.analyze_tls",
                return_value={
                    "status": "unavailable",
                    "certificate": {"hostname_match": None},
                    "signals": [],
                },
            ),
            patch(
                "src.risk.risk_engine.analyze_tls",
                return_value={
                    "status": "unavailable",
                    "certificate": {"hostname_match": None},
                    "signals": [],
                },
            ),
        ):
            for url in urls:
                with self.subTest(url=url):
                    domain = normalize_url(url)["registered_domain"]
                    self.forensic_result = _forensic_result(
                        age_days=None,
                        domain=domain,
                    )
                    self.forensic_result["subdomains"] = []
                    self.mock_forensics.return_value = self.forensic_result
                    result = self.engine.evaluate_url(url)
                    payload = result.to_combined_dict(include_details=True)

                    self.assertEqual(payload["url"], url)
                    self.assertEqual(
                        payload["details"]["domain_forensics"]["domain"],
                        domain,
                    )
                    self.assertEqual(result.decision, expected_decisions[url])
                    if url == "https://www.vit.ac.in":
                        self.assertFalse(payload["identity"]["brand_mismatch"])
                        self.assertNotEqual(
                            payload["identity"]["detected_brand"],
                            "Vi",
                        )
                    if url == "https://www.google.com":
                        self.assertTrue(payload["identity"]["official_domain"])
                    if url in {
                        "https://aws.amazon.com",
                        "https://www.aws.amazon.com",
                    }:
                        self.assertTrue(payload["identity"]["official_domain"])
                        self.assertFalse(payload["identity"]["brand_mismatch"])
                        self.assertEqual(
                            payload["identity"]["detected_brand"],
                            "Aws",
                        )
                        self.assertEqual(result.decision_basis, "official_identity_verified")
                        self.assertEqual(result.risk_score, 0)
                        self.assertEqual(result.recommended_action, "allow")
                        self.assertFalse(
                            payload["analysis"]["ml_used"]
                        )
                        self.assertEqual(
                            payload["evidence_sources"]["machine_learning"]["status"],
                            "unknown",
                        )
                    if url == "https://google.vit.ac.in":
                        self.assertFalse(payload["identity"]["official_domain"])
                        self.assertTrue(payload["identity"]["brand_mismatch"])
                        self.assertEqual(
                            payload["identity"]["identity_status"],
                            "brand_impersonation",
                        )
                    if url == "https://portal.vit.ac.in":
                        self.assertFalse(payload["identity"]["official_domain"])
                        self.assertFalse(payload["identity"]["brand_mismatch"])
                        self.assertEqual(
                            payload["identity"]["identity_status"],
                            "unknown",
                        )
                    if url in {
                        "https://g00gle.com",
                        "https://paypa1.com",
                        "https://micros0ft.com",
                    }:
                        self.assertTrue(payload["identity"]["typosquatting"])
                    json.dumps(payload)

    @patch('src.risk.collector.predict_url')
    @patch('src.risk.collector.analyze_homograph')
    @patch('src.risk.collector.analyze_typosquatting')
    @patch('src.risk.collector.analyze_brand')
    @patch('src.risk.collector.check_threat_intelligence')
    def test_09_unknown_benign_looking(self, mock_ti, mock_brand, mock_typo, mock_homo, mock_ml):
        mock_ti.return_value = "unknown"
        mock_brand.return_value = {"brand": None, "official_domain": False}
        mock_typo.return_value = {"is_typosquat": False}
        mock_homo.return_value = {"is_deceptive": False}
        mock_ml.return_value = {"phishing_probability": 0.35} # Inconclusive ML

        result = self.engine.evaluate_url("https://newdomain123.com")
        self.assertEqual(result.decision, DecisionState.UNKNOWN)
        self.assertEqual(result.decision_basis, "insufficient_evidence")
        self.assertEqual(result.risk_level, RiskLevel.LOW)