import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from scripts.evaluate_model import (
    binary_metrics,
    evaluate_dataset,
    reliability_bins,
)


class TestModelEvaluation(unittest.TestCase):
    def test_binary_metrics_cover_operating_and_calibration_measures(self):
        result = binary_metrics(
            [0, 0, 1, 1],
            [0.1, 0.8, 0.7, 0.9],
            threshold=0.5,
        )

        self.assertEqual(result["confusion_matrix"], {
            "tn": 1,
            "fp": 1,
            "fn": 0,
            "tp": 2,
        })
        self.assertEqual(result["precision"], 2 / 3)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertIsNotNone(result["pr_auc_average_precision"])
        self.assertIsNotNone(result["roc_auc"])
        self.assertIsNotNone(result["brier_score"])
        self.assertIsNotNone(result["log_loss"])

    def test_reliability_bins_preserve_counts(self):
        bins = reliability_bins([0, 1, 1], [0.1, 0.8, 0.9], bin_count=5)
        self.assertEqual(sum(item["count"] for item in bins), 3)
        self.assertEqual(len(bins), 2)

    def test_evaluator_splits_domains_and_checks_training_overlap(self):
        records = []
        domains = (
            "alpha-example.com",
            "beta-example.net",
            "gamma-example.org",
            "delta-example.info",
        )
        scores = {}
        for domain in domains:
            for label in (0, 1):
                url = (
                    f"https://{domain}/"
                    + ("redirect/" if label else "about")
                )
                records.append({
                    "url": url,
                    "source_domain": domain,
                    "label": label,
                    "source": "test",
                })
                scores[url] = 0.9 if label else 0.1
        frame = pd.DataFrame(records)

        with patch(
            "scripts.evaluate_model._predict_urls",
            side_effect=lambda urls: np.asarray([scores[url] for url in urls]),
        ):
            result = evaluate_dataset(
                frame,
                training_groups={"trained-domain.com"},
                test_fraction=0.5,
                thresholds=(0.5, 0.85),
            )

        self.assertEqual(result["status"], "evaluated")
        self.assertTrue(result["split"]["groups_disjoint"])
        self.assertEqual(
            result["split"]["calibration_domains"]
            + result["split"]["test_domains"],
            4,
        )
        self.assertIn("redirect_path", result["test_by_category"])
        self.assertIn("raw", result["test_methods"])

        with patch("scripts.evaluate_model._predict_urls") as predict:
            with self.assertRaisesRegex(ValueError, "overlap"):
                evaluate_dataset(
                    frame,
                    training_groups={"alpha-example.com"},
                )
        predict.assert_not_called()


if __name__ == "__main__":
    unittest.main()
