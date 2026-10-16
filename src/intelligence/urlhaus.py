import csv
from pathlib import Path
from typing import Dict, Any, Optional


BASE_DIR = Path(__file__).resolve().parents[2]

URLHAUS_DB_PATH = (
    BASE_DIR
    / "data"
    / "threat_intelligence"
    / "urlhaus.csv"
)


class URLhausDatabase:

    def __init__(
        self,
        database_path: Optional[Path] = None
    ):

        self.database_path = (
            database_path
            if database_path
            else URLHAUS_DB_PATH
        )

        self.url_index = {}
        self.loaded = False

        self.load_database()

    def normalize_url(self, url: str) -> str:
        """
        Conservative normalization.

        Removes surrounding whitespace, one trailing slash,
        and canonicalizes case so feeds match reliably.
        """

        return url.strip().rstrip("/").lower()

    def load_database(self):

        if not self.database_path.exists():

            print(
                f"[URLhaus] Database not found: "
                f"{self.database_path}"
            )

            self.loaded = False
            return

        print(
            f"[URLhaus] Loading database: "
            f"{self.database_path}"
        )

        try:

            with open(
                self.database_path,
                "r",
                encoding="utf-8",
                errors="replace",
                newline=""
            ) as file:

                lines = file.readlines()

            # -------------------------------------------------
            # URLhaus format:
            #
            # # comments
            # # comments
            # # id,dateadded,url,...
            # "3919001",...
            # -------------------------------------------------

            header = None
            data_lines = []

            for line in lines:

                stripped = line.strip()

                if not stripped:
                    continue

                # Find the commented CSV header.
                if stripped.startswith("# id,"):

                    header = stripped[2:]

                    continue

                # Ignore all other comments.
                if stripped.startswith("#"):

                    continue

                data_lines.append(stripped)

            if header is None:

                print(
                    "[URLhaus] CSV header not found"
                )

                self.loaded = False
                return

            # Reconstruct a normal CSV stream.
            csv_lines = [
                header
            ] + data_lines

            reader = csv.DictReader(csv_lines)

            count = 0

            for row in reader:

                url = row.get("url")

                if not url:
                    continue

                normalized_url = self.normalize_url(url)

                self.url_index[normalized_url] = row

                count += 1

            self.loaded = True

            print(
                f"[URLhaus] Loaded {count:,} malware URLs"
            )

        except Exception as e:

            print(
                f"[URLhaus] Failed to load database: {e}"
            )

            self.loaded = False

    def check(self, url: str) -> Dict[str, Any]:

        result = {
            "source": "urlhaus",
            "url": url,
            "status": "unknown",
            "found": False,
            "threat_type": "malware",
            "url_status": None,
            "date_added": None,
            "last_online": None,
            "threat": None,
            "tags": [],
            "urlhaus_id": None,
            "urlhaus_link": None,
            "reporter": None,
            "error": None
        }

        if not self.loaded:

            result["status"] = "error"

            result["error"] = (
                "URLhaus database is not available"
            )

            return result

        normalized_url = self.normalize_url(url)

        record = self.url_index.get(normalized_url)

        if record is None:

            # Not found does NOT mean legitimate.
            return result

        result["found"] = True

        result["status"] = "known_malware"

        result["url_status"] = record.get(
            "url_status"
        )

        result["date_added"] = record.get(
            "dateadded"
        )

        result["last_online"] = record.get(
            "last_online"
        )

        result["threat"] = record.get(
            "threat"
        )

        tags = record.get("tags", "")

        if tags and tags.lower() != "none":

            result["tags"] = [
                tag.strip()
                for tag in tags.split(",")
                if tag.strip()
            ]

        result["urlhaus_id"] = record.get(
            "id"
        )

        result["urlhaus_link"] = record.get(
            "urlhaus_link"
        )

        result["reporter"] = record.get(
            "reporter"
        )

        return result


_urlhaus_db = URLhausDatabase()


def check_urlhaus(url: str) -> Dict[str, Any]:

    return _urlhaus_db.check(url)


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

        result = check_urlhaus(test_url)

        for key, value in result.items():

            print(f"{key}: {value}")