from __future__ import annotations

import json
import os
import re

from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.rag.gemini_adapter import GeminiReasoningResult
from src.rag.context_builder import ThreatContext


load_dotenv()


class GeminiProvider:
    """
    Gemini-based contextual reasoning provider.

    Gemini is used only to interpret retrieved historical
    threat-memory evidence. It does not replace the primary
    Transformer classifier.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-3.6-flash",
    ):
        api_key = api_key or os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY is not configured."
            )
            
        self.api_key = api_key
        self.client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=30,
                retry_options=types.HttpRetryOptions(
                    attempts=1,
                ),
            ),
        )
        self.model_name = model_name

    @staticmethod
    def _extract_json(text: str) -> dict:
        """
        Extract a JSON object from Gemini's response.

        Handles:
        - plain JSON
        - ```json ... ```
        - explanatory text surrounding JSON
        """

        text = text.strip()

        # Case 1: direct JSON
        try:
            parsed = json.loads(text)

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            pass

        # Case 2: Markdown code block
        code_block = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        if code_block:
            try:
                parsed = json.loads(code_block.group(1))

                if isinstance(parsed, dict):
                    return parsed

            except json.JSONDecodeError:
                pass

        # Case 3: JSON object embedded in surrounding text
        start = text.find("{")
        end = text.rfind("}")

        if start != -1 and end > start:
            candidate = text[start : end + 1]

            try:
                parsed = json.loads(candidate)

                if isinstance(parsed, dict):
                    return parsed

            except json.JSONDecodeError:
                pass

        raise ValueError(
            "Gemini returned invalid JSON."
        )

    @staticmethod
    def _build_prompt(
        context: ThreatContext,
    ) -> str:

        evidence = []

        for item in context.evidence:
            evidence.append(
                {
                    "document_id": item.document_id,
                    "channel": item.channel,
                    "label": item.label,
                    "similarity": round(item.similarity, 4),
                    "text": item.text,
                }
            )

        evidence_json = json.dumps(
            evidence,
            ensure_ascii=False,
        )

        return f"""
You are a cybersecurity threat-context reasoning component.

Your role is ONLY to interpret retrieved historical threat-memory
evidence.

The primary Transformer classifier is responsible for classifying
the current message. Do not replace or override that classifier.

Do not use URLs or URL reputation.

Current channel:
{context.query_channel}

Retrieved historical evidence:
{evidence_json}

Retrieved evidence count:
{context.retrieved_count}

Historical phishing evidence count:
{context.similar_phishing_count}

Historical legitimate evidence count:
{context.similar_legitimate_count}

Average retrieval similarity:
{context.average_similarity:.4f}

Return ONLY a valid JSON object.

Required JSON structure:

{{
  "context_relevance": 0.0,
  "historical_phishing_evidence": 0,
  "historical_legitimate_evidence": 0,
  "reasoning": "brief explanation",
  "confidence": 0.0
}}

Rules:

1. context_relevance must be between 0 and 1.
2. confidence must be between 0 and 1.
3. historical_phishing_evidence must not exceed the retrieved evidence count.
4. historical_legitimate_evidence must not exceed the retrieved evidence count.
5. Do not invent evidence.
6. Do not classify the current message independently.
7. Use only the supplied retrieved evidence.
8. Return JSON only.
"""

    def analyze(
        self,
        context: ThreatContext,
    ) -> GeminiReasoningResult:

        prompt = self._build_prompt(context)

        interaction = self.client.interactions.create(
            model=self.model_name,
            input=prompt,
        )

        response_text = getattr(
            interaction,
            "output_text",
            None,
        )

        if not response_text:
            raise ValueError(
                "Gemini returned an empty response."
            )

        data = self._extract_json(response_text)

        retrieved_count = context.retrieved_count

        context_relevance = float(
            data.get("context_relevance", 0.0)
        )

        phishing_evidence = int(
            data.get(
                "historical_phishing_evidence",
                0,
            )
        )

        legitimate_evidence = int(
            data.get(
                "historical_legitimate_evidence",
                0,
            )
        )

        reasoning = str(
            data.get(
                "reasoning",
                "",
            )
        )

        confidence = float(
            data.get(
                "confidence",
                0.0,
            )
        )

        context_relevance = max(
            0.0,
            min(1.0, context_relevance),
        )

        confidence = max(
            0.0,
            min(1.0, confidence),
        )

        phishing_evidence = max(
            0,
            min(
                retrieved_count,
                phishing_evidence,
            ),
        )

        legitimate_evidence = max(
            0,
            min(
                retrieved_count,
                legitimate_evidence,
            ),
        )

        return GeminiReasoningResult(
            context_relevance=context_relevance,
            historical_phishing_evidence=phishing_evidence,
            historical_legitimate_evidence=legitimate_evidence,
            reasoning=reasoning,
            confidence=confidence,
        )