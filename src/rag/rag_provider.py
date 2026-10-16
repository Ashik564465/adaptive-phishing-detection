from pathlib import Path
from typing import Any, Dict

from src.rag.investigator import RAGInvestigator
from src.rag.retriever import RAGRetriever
from src.rag.cases import ValidatedCaseStore


class RAGEvidenceProvider:
    """Facade for local knowledge retrieval and validated case retrieval."""

    def __init__(self, store_path: Path | None = None):
        root = Path(__file__).resolve().parents[2]
        self.store_path = store_path or root / "data" / "rag" / "vector_store"
        self.case_store = ValidatedCaseStore()
        self._investigator = None

    def investigate(self, url: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        case = self.case_store.find_for_url(url)
        context = dict(context or {})
        if case and case["decision"] == "confirmed_legitimate":
            context["validated_case"] = {
                "domain": case["domain"],
                "decision": case["decision"],
            }
        try:
            if self._investigator is None:
                self._investigator = RAGInvestigator(
                    RAGRetriever(self.store_path)
                )
            result = self._investigator.investigate(url, context)
            if case:
                result["closest_case"] = {
                    "domain": case["domain"],
                    "decision": case["decision"],
                    "similarity": 1.0,
                    "reason": case["reason"],
                }
                result["status"] = "available"
                result["investigation"] = (
                    "Evidence supports that this is a legitimate domain."
                    if case["decision"] == "confirmed_legitimate"
                    else "A validated historical case supports a phishing classification."
                )
            return result
        except (FileNotFoundError, ImportError, RuntimeError, ValueError) as exc:
            fallback = {
                "status": "unavailable",
                "closest_case": None,
                "supporting_knowledge": [],
                "investigation": "No sufficiently relevant RAG evidence was found.",
            }
            if case:
                fallback.update({
                    "status": "available",
                    "closest_case": {
                        "domain": case["domain"],
                        "decision": case["decision"],
                        "similarity": 1.0,
                        "reason": case["reason"],
                    },
                    "investigation": (
                        "Evidence supports that this is a legitimate domain."
                        if case["decision"] == "confirmed_legitimate"
                        else "A validated historical case supports a phishing classification."
                    ),
                })
            return fallback
