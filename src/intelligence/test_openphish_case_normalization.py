import unittest
from pathlib import Path

from src.intelligence.openphish import OpenPhishDatabase


class TestOpenPhishCaseNormalization(unittest.TestCase):
    def test_url_match_is_case_insensitive(self):
        db = OpenPhishDatabase(
            database_path=Path(__file__).resolve().parents[2]
            / "data"
            / "threat_intelligence"
            / "openphish.txt"
        )

        result = db.check("https://iuytrewert--oportunidad-ec.replit.app/")
        self.assertEqual(result["status"], "known_phishing")

        mixed_case = "https://IUyTreWErT--oportunidad-ec.replit.app/"
        self.assertEqual(db.check(mixed_case)["status"], "known_phishing")


if __name__ == "__main__":
    unittest.main()
