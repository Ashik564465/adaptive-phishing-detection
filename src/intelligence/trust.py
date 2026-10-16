import csv
from functools import lru_cache
from pathlib import Path
from typing import Set

from src.intelligence.url_normalizer import normalize_url


BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_PATH = BASE_DIR / "data" / "adaptive_phishing_dataset.csv"


@lru_cache(maxsize=1)
def trusted_domains() -> Set[str]:
    domains: Set[str] = {
        "vit.ac.in",
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
    }
    if not DATASET_PATH.exists():
        return domains
    try:
        with DATASET_PATH.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                is_legitimate = (
                    row.get("label_name", "").strip().lower() == "legitimate"
                    or row.get("label", "").strip() == "0"
                )
                domain = row.get("source_domain")
                if is_legitimate and domain:
                    domains.add(domain.strip().lower().rstrip("."))
    except (OSError, csv.Error):
        return domains
    return domains


def is_allowlisted(url: str) -> bool:
    return normalize_url(url)["registered_domain"] in trusted_domains()
