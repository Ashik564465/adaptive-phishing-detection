from pathlib import Path
from typing import Dict, Any, Optional


BASE_DIR = Path(__file__).resolve().parents[2]

OPENPHISH_DB_PATH = (
    BASE_DIR
    / "data"
    / "threat_intelligence"
    / "openphish.txt"
)


class OpenPhishDatabase:

    def __init__(
        self,
        database_path: Optional[Path] = None
    ):

        self.database_path = (
            database_path
            if database_path
            else OPENPHISH_DB_PATH
        )

        self.url_index = set()

        self.loaded = False

        self.load_database()

    def normalize_url(self, url: str) -> str:

        return url.strip().rstrip("/").lower()

    def load_database(self):

        if not self.database_path.exists():

            print(
                f"[OpenPhish] Database not found: "
                f"{self.database_path}"
            )

            self.loaded = False

            return

        print(
            f"[OpenPhish] Loading database: "
            f"{self.database_path}"
        )

        count = 0

        with open(
            self.database_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:

                url = line.strip()

                if not url:
                    continue

                if url.startswith("#"):
                    continue

                normalized_url = self.normalize_url(url)

                self.url_index.add(normalized_url)

                count += 1

        self.loaded = True

        print(
            f"[OpenPhish] Loaded {count:,} phishing URLs"
        )

    def check(self, url: str) -> Dict[str, Any]:

        result = {
            "source": "openphish",
            "url": url,
            "status": "unknown",
            "found": False,
            "error": None
        }

        if not self.loaded:

            result["status"] = "error"

            result["error"] = (
                "OpenPhish database is not available"
            )

            return result

        normalized_url = self.normalize_url(url)

        if normalized_url in self.url_index:

            result["found"] = True

            result["status"] = "known_phishing"

        return result


_openphish_db = OpenPhishDatabase()


def check_openphish(url: str) -> Dict[str, Any]:

    return _openphish_db.check(url)


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

        result = check_openphish(test_url)

        for key, value in result.items():

            print(f"{key}: {value}")