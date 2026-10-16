import json
from pathlib import Path
from typing import Any, Dict, Optional

from src.intelligence.url_normalizer import normalize_url


class ValidatedCaseStore:
    def __init__(self, path: Optional[Path] = None):
        root = Path(__file__).resolve().parents[2]
        self.path = path or root / "data" / "rag" / "cases" / "validated_cases.json"
        self._cases: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        values = json.loads(self.path.read_text(encoding="utf-8"))
        for case in values:
            domain = str(case.get("domain", "")).lower().strip(".")
            decision = case.get("decision")
            if domain and decision in {
                "confirmed_legitimate",
                "confirmed_phishing",
            }:
                self._cases[domain] = case

    def find_for_url(self, url: str) -> Optional[Dict[str, Any]]:
        domain = normalize_url(url)["registered_domain"]
        case = self._cases.get(domain)
        if case is None:
            return None
        return dict(case)
