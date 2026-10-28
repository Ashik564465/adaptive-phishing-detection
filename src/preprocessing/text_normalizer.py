import html
import math
import re
import unicodedata


TAG_PATTERN = re.compile(r"<[^>]+>")
WHITESPACE_PATTERN = re.compile(r"\s+")


def normalize_text(value: object, *, html_cleanup: bool = False) -> str | None:
    if value is None or value is not None and _is_missing_scalar(value):
        return None
    text = str(value)
    if not text.strip():
        return None
    text = unicodedata.normalize("NFKC", text)
    if html_cleanup:
        text = html.unescape(TAG_PATTERN.sub(" ", text))
    text = WHITESPACE_PATTERN.sub(" ", text).strip()
    return text or None


def _is_missing_scalar(value: object) -> bool:
    return isinstance(value, float) and math.isnan(value)