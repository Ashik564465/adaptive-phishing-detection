import csv
from pathlib import Path
from typing import Dict, Any, Optional


BASE_DIR = Path(__file__).resolve().parents[2]

PHISHTANK_DB_PATH = (
    BASE_DIR
    / "data"
    / "threat_intelligence"
    / "phishtank.csv"
)


class PhishTankDatabase:

    def __init__(self, database_path: Optional[Path] = None):

        self.database_path = (
            database_path
            if database_path
            else PHISHTANK_DB_PATH
        )

        self.url_index = {}
        self.loaded = False

        self.load_database()

    def normalize_url(self, url: str) -> str:
        return url.strip().rstrip("/").lower()

    def load_database(self):

        if not self.database_path.exists():

            print(
                f"[PhishTank] Database not found: "
                f"{self.database_path}"
            )

            self.loaded = False
            return

        print(
            f"[PhishTank] Loading database: "
            f"{self.database_path}"
        )

        count = 0

        with open(
            self.database_path,
            "r",
            encoding="utf-8",
            errors="replace",
            newline=""
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                url = row.get("url")

                if not url:
                    continue

                normalized_url = self.normalize_url(url)

                self.url_index[normalized_url] = row

                count += 1

        self.loaded = True

        print(
            f"[PhishTank] Loaded {count:,} phishing URLs"
        )

    def check(self, url: str) -> Dict[str, Any]:

        result = {
            "source": "phishtank",
            "url": url,
            "status": "unknown",
            "found": False,
            "phish_id": None,
            "verified": False,
            "online": False,
            "target": None,
            "verification_time": None,
            "detail_url": None,
            "error": None
        }

        if not self.loaded:

            result["status"] = "error"

            result["error"] = (
                "PhishTank database is not available"
            )

            return result

        normalized_url = self.normalize_url(url)

        record = self.url_index.get(normalized_url)

        if record is None:

            # Not found does NOT mean legitimate.
            return result

        result["found"] = True

        result["phish_id"] = record.get("phish_id")

        result["verified"] = (
            str(record.get("verified", "")).lower()
            == "yes"
        )

        result["online"] = (
            str(record.get("online", "")).lower()
            == "yes"
        )

        result["target"] = record.get("target")

        result["verification_time"] = (
            record.get("verification_time")
        )

        result["detail_url"] = (
            record.get("phish_detail_url")
        )

        if result["verified"]:
            result["status"] = "known_phishing"

        return result


_phishtank_db = PhishTankDatabase()


def check_phishtank(url: str) -> Dict[str, Any]:
    return _phishtank_db.check(url)


if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://example.com",
        "https://google.com.evil.com/login"
    ]

    for test_url in test_urls:

        print("\n" + "=" * 70)
        print(f"Checking: {test_url}")
        print("=" * 70)

        result = check_phishtank(test_url)

        for key, value in result.items():
            print(f"{key}: {value}")