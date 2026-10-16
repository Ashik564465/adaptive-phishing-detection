import json
import unittest
from unittest.mock import patch

from api.lambda_handler import lambda_handler
from src.risk.models import DecisionState, FinalDecision, RiskLevel


class TestLambdaHandlerResponseModes(unittest.TestCase):
    def setUp(self):
        self.analysis = FinalDecision(
            url="https://example.com",
            decision=DecisionState.UNKNOWN,
            risk_level=RiskLevel.LOW,
            risk_score=0,
            confidence=50,
            decision_basis="insufficient_evidence",
            domain_forensics={
                "status": "available",
                "raw": {
                    "domain": "example.com",
                    "certificate_history": [{"id": "ct-id"}],
                    "sources": {"certificate_transparency": {
                        "status": "available",
                        "attempts": [{"attempt": 1}],
                    }},
                },
                "normalized": {},
                "findings": [],
                "supporting_signals": [],
                "suspicious_signals": [],
                "contradictions": [],
                "unknown_evidence": [],
                "errors": [],
                "sources": {},
            },
        )

    def test_default_and_detailed_response_modes(self):
        with patch("api.lambda_handler.engine.evaluate_url", return_value=self.analysis) as evaluate:
            compact_response = lambda_handler(
                {"body": json.dumps({"url": "https://example.com"})},
                None,
            )
            detailed_response = lambda_handler(
                {"body": json.dumps({
                    "url": "https://example.com",
                    "include_details": True,
                })},
                None,
            )

        self.assertEqual(compact_response["statusCode"], 200)
        self.assertEqual(detailed_response["statusCode"], 200)
        compact = json.loads(compact_response["body"])
        detailed = json.loads(detailed_response["body"])
        self.assertNotIn("details", compact)
        self.assertEqual(
            detailed["details"]["domain_forensics"],
            self.analysis.domain_forensics["raw"],
        )
        self.assertEqual(compact["analysis"], detailed["analysis"])
        self.assertEqual(compact["scores"], detailed["scores"])
        self.assertEqual(compact["metadata"]["schema_version"], "2.1")
        self.assertIn("ml_raw_score", compact["scores"])
        self.assertIn(
            "final_risk_score_explanation",
            compact["scores"],
        )
        self.assertEqual(evaluate.call_count, 2)

    def test_non_boolean_include_details_is_rejected(self):
        with patch("api.lambda_handler.engine.evaluate_url") as evaluate:
            response = lambda_handler(
                {"body": json.dumps({
                    "url": "https://example.com",
                    "include_details": "true",
                })},
                None,
            )

        self.assertEqual(response["statusCode"], 400)
        self.assertIn("boolean", json.loads(response["body"])["error"])
        evaluate.assert_not_called()

    def test_malformed_and_unsupported_urls_are_rejected_before_analysis(self):
        for url in (
            "file:///etc/passwd",
            "https://bad host.example/path",
            "https://example.com:99999",
        ):
            with self.subTest(url=url):
                with patch("api.lambda_handler.engine.evaluate_url") as evaluate:
                    result = lambda_handler(
                        {"body": json.dumps({"url": url})},
                        None,
                    )

                self.assertEqual(result["statusCode"], 400)
                self.assertIn("error", json.loads(result["body"]))
                evaluate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
