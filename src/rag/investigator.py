from typing import Any, Dict, List, Tuple

from src.rag.retriever import RAGRetriever


class RAGInvestigator:
    DEFAULT_RELEVANCE_THRESHOLD = 0.55
    MAX_SUPPORTING_KNOWLEDGE = 2

    def __init__(self, retriever: RAGRetriever):
        self.retriever = retriever

    def investigate(
        self,
        url: str,
        context: Dict[str, Any] | None = None,
        top_k: int = 5,
        relevance_threshold: float = DEFAULT_RELEVANCE_THRESHOLD,
    ) -> Dict[str, Any]:
        context = context or {}
        query, profile = self._build_query(url, context)
        results = self.retriever.search(query, max(top_k, 20))
        ranked_results = self._rank_results(results, profile)
        relevant_results = [
            result
            for result in ranked_results
            if result["relevance"] >= relevance_threshold
        ][: self.MAX_SUPPORTING_KNOWLEDGE]
        evidence = [
            {
                "topic": result["topic"],
                "relevance": round(result["relevance"], 2),
                "summary": result["document"]["content"],
            }
            for result in relevant_results
        ]
        return {
            "status": "available" if evidence else "no_relevant_evidence",
            "supporting_knowledge": evidence,
            "confidence": (
                round(relevant_results[0]["relevance"], 4)
                if relevant_results
                else 0.0
            ),
            "investigation": (
                self._investigation_summary(profile)
                if evidence
                else "No sufficiently relevant RAG evidence was found."
            ),
            "_debug_results": results,
            "_query": query,
        }

    @staticmethod
    def _build_query(
        url: str,
        context: Dict[str, Any],
    ) -> Tuple[str, Dict[str, Any]]:
        identity = context.get("brand_analysis", {})
        typo = context.get("typosquatting", {})
        homograph = context.get("homograph_analysis", {})
        domain = context.get("domain_intelligence", {})
        terms: List[str] = []
        preferred_categories: List[str] = []

        if typo.get("detected") or identity.get("typosquat_detected"):
            terms.extend([
                "typosquatting",
                "visual similarity",
                "character substitution",
                "brand impersonation",
                "deceptive domain",
                "registered domain",
            ])
            preferred_categories.extend([
                "typosquatting",
                "character_substitution",
                "brand_impersonation",
                "domain_verification",
            ])
        if identity.get("brand_mismatch"):
            terms.extend(["brand impersonation", "deceptive domain"])
            preferred_categories.extend([
                "brand_impersonation",
                "subdomain_deception",
            ])
        if homograph.get("detected"):
            terms.extend(["homograph", "mixed script", "confusable domain"])
            preferred_categories.extend(["unicode_homograph", "mixed_script"])
        if homograph.get("punycode"):
            terms.extend(["punycode", "internationalized domain"])
            preferred_categories.append("punycode")
        if identity.get("official_domain"):
            terms.extend(["official domain verification", "registered domain"])
            preferred_categories.extend(["official_identity", "domain_verification"])
        if not terms:
            terms.extend(["registered domain", "domain ownership", "URL identity"])
            preferred_categories.extend(["domain_verification", "official_identity"])

        registered_domain = domain.get("registered_domain")
        query = " ".join(
            [f"URL {url}", f"registered domain {registered_domain or ''}", *terms]
        )
        return query, {
            "terms": {term.lower() for term in terms},
            "categories": set(preferred_categories),
            "typosquat": bool(typo.get("detected")),
            "brand_mismatch": bool(identity.get("brand_mismatch")),
            "homograph": bool(homograph.get("detected") or homograph.get("punycode")),
        }

    @classmethod
    def _rank_results(
        cls,
        results: List[Dict[str, Any]],
        profile: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        ranked = []
        for result in results:
            document = result["document"]
            category = str(document.get("category", "")).lower()
            searchable = " ".join(
                [
                    str(document.get("title", "")),
                    category,
                    str(document.get("content", "")),
                    " ".join(document.get("tags", [])),
                ]
            ).lower()
            overlap = sum(
                1 for term in profile["terms"] if term in searchable
            )
            lexical = min(overlap / max(len(profile["terms"]), 1), 1.0)
            category_boosts = {
                "typosquatting": 0.35,
                "brand_impersonation": 0.32,
                "character_substitution": 0.28,
                "unicode_homograph": 0.32,
                "mixed_script": 0.30,
                "punycode": 0.30,
                "subdomain_deception": 0.28,
                "domain_verification": 0.22,
                "official_identity": 0.22,
            }
            category_boost = (
                category_boosts.get(category, 0.0)
                if category in profile["categories"]
                else 0.0
            )
            relevance = min(
                1.0,
                (result["score"] * 0.55)
                + (lexical * 0.35)
                + category_boost,
            )
            ranked.append({
                **result,
                "relevance": relevance,
                "topic": cls._topic(document, category),
            })
        return sorted(ranked, key=lambda item: item["relevance"], reverse=True)

    @staticmethod
    def _topic(document: Dict[str, Any], category: str) -> str:
        topic_names = {
            "typosquatting": "Typosquatting",
            "character_substitution": "Character substitution",
            "brand_impersonation": "Brand impersonation",
            "domain_verification": "Registered-domain verification",
            "unicode_homograph": "Unicode homograph",
            "mixed_script": "Mixed-script deception",
            "punycode": "Punycode domains",
            "official_identity": "Official-domain verification",
            "subdomain_deception": "Domain deception",
        }
        return topic_names.get(category, document.get("title", category))

    @staticmethod
    def _investigation_summary(profile: Dict[str, Any]) -> str:
        if profile["typosquat"] and profile["brand_mismatch"]:
            return (
                "The retrieved security knowledge supports the detected "
                "typosquatting and domain impersonation pattern."
            )
        if profile["typosquat"]:
            return (
                "The retrieved security knowledge supports the detected "
                "typosquatting and visual-similarity pattern."
            )
        if profile["brand_mismatch"]:
            return (
                "The retrieved security knowledge supports the detected "
                "brand impersonation and deceptive-domain pattern."
            )
        if profile["homograph"]:
            return (
                "The retrieved security knowledge supports the detected "
                "homograph or internationalized-domain pattern."
            )
        return "The retrieved security knowledge supports the detected domain identity pattern."
