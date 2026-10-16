import math
import unittest

import pandas as pd
from unittest.mock import patch

from src.features.url_features import extract_features
from src.ml.predict import FEATURE_COLUMNS, model, predict_url


class TestModelInferenceContract(unittest.TestCase):
    def test_exact_inference_urls_preserve_feature_order_and_scores(self):
        cases = {
            "https://sbi.co.in/redirect/": 0.9986901,
            "https://vtop.vit.ac.in/vtop/open/page": 0.9997821,
            "https://www.google.com": 0.9999094,
            "https://g00gle.com": 0.0003403,
        }
        booster = model.get_booster()
        self.assertEqual(booster.num_features(), len(FEATURE_COLUMNS))
        self.assertIn(booster.feature_names, (None, FEATURE_COLUMNS))

        for url, expected_score in cases.items():
            with self.subTest(url=url):
                features = extract_features(url)
                self.assertEqual(set(features), set(FEATURE_COLUMNS))
                self.assertTrue(all(
                    isinstance(value, (int, float))
                    and math.isfinite(float(value))
                    for value in features.values()
                ))
                matrix = pd.DataFrame([features]).reindex(
                    columns=FEATURE_COLUMNS,
                    fill_value=0,
                )
                direct_score = float(model.predict_proba(matrix)[0][1])
                result = predict_url(url)

                self.assertAlmostEqual(direct_score, expected_score, places=5)
                self.assertEqual(result["raw_model_score"], direct_score)
                self.assertEqual(result["phishing_probability"], direct_score)
                self.assertIn(
                    "not a calibrated probability",
                    result["score_semantics"],
                )
                self.assertTrue(result["top_feature_contributions"])

    def test_explanations_identify_path_and_subdomain_shortcuts(self):
        results = {
            url: predict_url(url)
            for url in (
                "https://sbi.co.in/redirect/",
                "https://vtop.vit.ac.in/vtop/open/page",
                "https://www.google.com",
            )
        }
        feature_names = {
            url: {
                item["feature"]
                for item in result["top_feature_contributions"]
            }
            for url, result in results.items()
        }

        self.assertIn(
            "path_length",
            feature_names["https://sbi.co.in/redirect/"],
        )
        self.assertIn(
            "subdomain_length",
            feature_names["https://www.google.com"],
        )
        self.assertIn(
            "subdomain_length",
            feature_names["https://vtop.vit.ac.in/vtop/open/page"],
        )

    def test_missing_extracted_feature_fails_instead_of_zero_filling(self):
        features = extract_features("https://example.com")
        features.pop(FEATURE_COLUMNS[0])
        with (
            patch("src.ml.predict.extract_features", return_value=features),
            patch.object(model, "predict_proba") as predict,
        ):
            with self.assertRaisesRegex(ValueError, "omitted model features"):
                predict_url("https://example.com")

        predict.assert_not_called()


if __name__ == "__main__":
    unittest.main()
