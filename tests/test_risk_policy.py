import os
import unittest
from unittest.mock import patch

from src.risk.policy import RiskPolicy


class TestRiskPolicyConfiguration(unittest.TestCase):
    def test_thresholds_are_configurable_and_ordered(self):
        with patch.dict(
            os.environ,
            {
                "RISK_ML_REVIEW_THRESHOLD": "0.88",
                "RISK_ML_STRONG_THRESHOLD": "0.97",
                "RISK_ML_BENIGN_THRESHOLD": "0.12",
            },
            clear=False,
        ):
            policy = RiskPolicy.from_environment()

        self.assertEqual(policy.ml_review_threshold, 0.88)
        self.assertEqual(policy.ml_strong_threshold, 0.97)
        self.assertEqual(policy.ml_benign_threshold, 0.12)

    def test_invalid_threshold_configuration_fails_explicitly(self):
        invalid_configs = (
            {
                "RISK_ML_REVIEW_THRESHOLD": "1.1",
                "RISK_ML_STRONG_THRESHOLD": "0.95",
                "RISK_ML_BENIGN_THRESHOLD": "0.15",
            },
            {
                "RISK_ML_REVIEW_THRESHOLD": "0.1",
                "RISK_ML_STRONG_THRESHOLD": "0.95",
                "RISK_ML_BENIGN_THRESHOLD": "0.15",
            },
            {
                "RISK_ML_REVIEW_THRESHOLD": "invalid",
                "RISK_ML_STRONG_THRESHOLD": "0.95",
                "RISK_ML_BENIGN_THRESHOLD": "0.15",
            },
        )
        for values in invalid_configs:
            with self.subTest(values=values):
                with patch.dict(os.environ, values, clear=False):
                    with self.assertRaises(ValueError):
                        RiskPolicy.from_environment()


if __name__ == "__main__":
    unittest.main()
