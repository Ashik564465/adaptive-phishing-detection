import unicodedata
from urllib.parse import urlparse

import tldextract


# ============================================================
# Common Unicode confusable characters
#
# These are examples of characters that can visually resemble
# Latin characters commonly used in brand/domain impersonation.
# ============================================================

CONFUSABLES = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",

    # Greek
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Χ": "X",

    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "χ": "x",
}


# ============================================================
# Extract hostname
# ============================================================

def get_hostname(url: str) -> str:

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    return (
        parsed.hostname or ""
    ).lower()


# ============================================================
# Detect Unicode characters
# ============================================================

def get_unicode_characters(hostname: str):

    return [
        char
        for char in hostname
        if ord(char) > 127
    ]


# ============================================================
# Detect scripts
#
# This is intentionally lightweight. It gives us evidence
# rather than declaring every non-Latin domain malicious.
# ============================================================

def detect_script(char: str) -> str:

    name = unicodedata.name(
        char,
        ""
    ).upper()

    if "CYRILLIC" in name:
        return "Cyrillic"

    if "GREEK" in name:
        return "Greek"

    if "LATIN" in name:
        return "Latin"

    if "ARABIC" in name:
        return "Arabic"

    if "HEBREW" in name:
        return "Hebrew"

    if "DEVANAGARI" in name:
        return "Devanagari"

    if "HANGUL" in name:
        return "Hangul"

    if "HIRAGANA" in name:
        return "Hiragana"

    if "KATAKANA" in name:
        return "Katakana"

    if "CJK" in name:
        return "CJK"

    return "Other"


# ============================================================
# Detect scripts present in hostname
# ============================================================

def get_scripts(hostname: str):

    scripts = set()

    for char in hostname:

        if ord(char) <= 127:
            continue

        scripts.add(
            detect_script(char)
        )

    return sorted(scripts)


# ============================================================
# Detect mixed scripts
# ============================================================

def has_mixed_scripts(hostname: str):

    scripts = get_scripts(hostname)

    return len(scripts) > 1


# ============================================================
# Normalize Unicode confusables
#
# Example:
#
# Cyrillic "о" -> Latin "o"
#
# This allows comparison against known brand names.
# ============================================================

def normalize_confusables(text: str):

    normalized = []

    for char in text:

        replacement = CONFUSABLES.get(
            char,
            char
        )

        normalized.append(
            replacement
        )

    return "".join(normalized)


# ============================================================
# Detect whether normalization changes hostname
# ============================================================

def has_confusable_characters(hostname: str):

    normalized = normalize_confusables(
        hostname
    )

    return normalized != hostname


# ============================================================
# Punycode / IDN detection
# ============================================================

def has_punycode(hostname: str):

    return any(
        label.startswith("xn--")
        for label in hostname.split(".")
    )


# ============================================================
# Convert IDN hostname to ASCII representation
# ============================================================

def get_punycode_labels(hostname: str):

    labels = []

    for label in hostname.split("."):

        try:

            ascii_label = label.encode(
                "idna"
            ).decode("ascii")

            labels.append(
                ascii_label
            )

        except UnicodeError:

            labels.append(label)

    return labels


# ============================================================
# Unicode character details
# ============================================================

def get_unicode_details(hostname: str):

    details = []

    for char in hostname:

        if ord(char) <= 127:
            continue

        details.append({
            "character": char,
            "codepoint": f"U+{ord(char):04X}",
            "name": unicodedata.name(
                char,
                "UNKNOWN"
            ),
            "script": detect_script(char),
            "confusable_as": CONFUSABLES.get(
                char
            ),
        })

    return details


# ============================================================
# Main homograph analysis
# ============================================================

def analyze_homograph(url: str):

    hostname = get_hostname(url)

    if not hostname:

        return {
            "hostname": "",
            "has_unicode": False,
            "has_punycode": False,
            "unicode_count": 0,
            "scripts": [],
            "mixed_scripts": False,
            "has_confusable_characters": False,
            "normalized_hostname": "",
            "punycode_labels": [],
            "unicode_details": [],
            "homograph_risk": False,
        }

    unicode_chars = get_unicode_characters(
        hostname
    )

    unicode_count = len(
        unicode_chars
    )

    scripts = get_scripts(
        hostname
    )

    mixed_scripts = has_mixed_scripts(
        hostname
    )

    confusable = has_confusable_characters(
        hostname
    )

    punycode = has_punycode(
        hostname
    )

    normalized_hostname = (
        normalize_confusables(
            hostname
        )
    )

    punycode_labels = (
        get_punycode_labels(
            hostname
        )
    )

    unicode_details = (
        get_unicode_details(
            hostname
        )
    )

    # --------------------------------------------------------
    # Risk is evidence-based.
    #
    # Unicode alone does NOT automatically mean phishing.
    # --------------------------------------------------------

    homograph_risk = (
        confusable
        or punycode
        or mixed_scripts
    )

    return {
        "hostname": hostname,

        "has_unicode": (
            unicode_count > 0
        ),

        "has_punycode": punycode,

        "unicode_count": unicode_count,

        "scripts": scripts,

        "mixed_scripts": mixed_scripts,

        "has_confusable_characters": (
            confusable
        ),

        "normalized_hostname": (
            normalized_hostname
        ),

        "punycode_labels": (
            punycode_labels
        ),

        "unicode_details": (
            unicode_details
        ),

        "homograph_risk": (
            homograph_risk
        ),
    }


# ============================================================
# Local tests
# ============================================================

if __name__ == "__main__":

    test_urls = [

        # Normal domain
        "https://google.com",

        # Normal subdomain
        "https://accounts.google.com",

        # ASCII typosquatting
        "https://gooogle.com",

        # Digit substitution
        "https://g00gle.com",

        # Punycode example
        "https://xn--80ak6aa92e.com",

        # Unicode examples
        "https://gοοgle.com",

        "https://раypal.com",
    ]

    for url in test_urls:

        result = analyze_homograph(url)

        print("\n" + "=" * 70)

        print(
            "URL:",
            url
        )

        print(
            "hostname:",
            result["hostname"]
        )

        print(
            "has_unicode:",
            result["has_unicode"]
        )

        print(
            "has_punycode:",
            result["has_punycode"]
        )

        print(
            "unicode_count:",
            result["unicode_count"]
        )

        print(
            "scripts:",
            result["scripts"]
        )

        print(
            "mixed_scripts:",
            result["mixed_scripts"]
        )

        print(
            "has_confusable_characters:",
            result[
                "has_confusable_characters"
            ]
        )

        print(
            "normalized_hostname:",
            result[
                "normalized_hostname"
            ]
        )

        print(
            "punycode_labels:",
            result[
                "punycode_labels"
            ]
        )

        print(
            "unicode_details:",
            result[
                "unicode_details"
            ]
        )

        print(
            "homograph_risk:",
            result[
                "homograph_risk"
            ]
        )