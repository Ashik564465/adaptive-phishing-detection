import re
import math
from collections import Counter
from urllib.parse import urlparse, unquote

import tldextract


SUSPICIOUS_WORDS = {
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "password",
    "authenticate", "authentication", "auth", "bank", "banking",
    "payment", "wallet", "confirm", "confirmation", "invoice",
    "refund", "support", "recover", "unlock", "validate",
    "credential", "session", "billing"
}


BRANDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "github",
    "outlook",
    "office365",
    "whatsapp",
    "telegram",
    "coinbase",
    "binance"
]


def shannon_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    n = len(text)

    return -sum(
        (count / n) * math.log2(count / n)
        for count in counts.values()
    )


def vowel_ratio(text):
    letters = [c.lower() for c in text if c.isalpha()]

    if not letters:
        return 0.0

    return sum(
        c in "aeiou"
        for c in letters
    ) / len(letters)


def digit_ratio(text):
    if not text:
        return 0.0

    return sum(
        c.isdigit()
        for c in text
    ) / len(text)


def special_ratio(text):
    if not text:
        return 0.0

    return sum(
        not c.isalnum()
        for c in text
    ) / len(text)


def extract_features(url):

    url = str(url).strip()

    if "://" not in url:
        parse_url = "http://" + url
    else:
        parse_url = url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    fragment = parsed.fragment or ""

    extracted = tldextract.extract(parse_url)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    f = {}

    # -------------------------
    # URL length
    # -------------------------

    f["url_length"] = len(url)
    f["hostname_length"] = len(hostname)
    f["domain_length"] = len(domain)
    f["subdomain_length"] = len(subdomain)
    f["path_length"] = len(path)
    f["query_length"] = len(query)
    f["fragment_length"] = len(fragment)

    # -------------------------
    # Character counts
    # -------------------------

    f["dot_count"] = url.count(".")
    f["hyphen_count"] = url.count("-")
    f["underscore_count"] = url.count("_")
    f["slash_count"] = url.count("/")
    f["question_count"] = url.count("?")
    f["equal_count"] = url.count("=")
    f["ampersand_count"] = url.count("&")
    f["at_count"] = url.count("@")
    f["percent_count"] = url.count("%")
    f["colon_count"] = url.count(":")
    f["semicolon_count"] = url.count(";")

    # -------------------------
    # Character ratios
    # -------------------------

    f["digit_count"] = sum(
        c.isdigit()
        for c in url
    )

    f["letter_count"] = sum(
        c.isalpha()
        for c in url
    )

    f["digit_ratio"] = digit_ratio(url)
    f["special_ratio"] = special_ratio(url)

    # -------------------------
    # Structure
    # -------------------------

    f["subdomain_count"] = (
        len(subdomain.split("."))
        if subdomain
        else 0
    )

    f["path_segment_count"] = len(
        [x for x in path.split("/") if x]
    )

    f["query_parameter_count"] = (
        len(query.split("&"))
        if query
        else 0
    )

    # -------------------------
    # Protocol
    # -------------------------

    f["is_https"] = int(
        parsed.scheme.lower() == "https"
    )

    f["is_http"] = int(
        parsed.scheme.lower() == "http"
    )

    # -------------------------
    # IP address
    # -------------------------

    f["has_ip"] = int(
        bool(
            re.match(
                r"^(?:\d{1,3}\.){3}\d{1,3}$",
                hostname
            )
        )
    )

    # -------------------------
    # Suspicious syntax
    # -------------------------

    f["has_at_symbol"] = int(
        "@" in url
    )

    f["has_double_slash"] = int(
        "//" in path
    )

    f["has_encoded_chars"] = int(
        "%" in url
    )

    f["has_port"] = int(
        parsed.port is not None
        if parsed.hostname
        else False
    )

    # -------------------------
    # Entropy
    # -------------------------

    f["url_entropy"] = shannon_entropy(url)
    f["hostname_entropy"] = shannon_entropy(hostname)
    f["domain_entropy"] = shannon_entropy(domain)
    f["path_entropy"] = shannon_entropy(path)

    # -------------------------
    # Statistical characteristics
    # -------------------------

    f["hostname_digit_ratio"] = digit_ratio(hostname)
    f["domain_digit_ratio"] = digit_ratio(domain)
    f["path_digit_ratio"] = digit_ratio(path)

    f["hostname_special_ratio"] = special_ratio(hostname)
    f["path_special_ratio"] = special_ratio(path)

    f["domain_vowel_ratio"] = vowel_ratio(domain)

    # -------------------------
    # Suspicious words
    # -------------------------

    url_lower = url.lower()

    suspicious_count = 0

    for word in SUSPICIOUS_WORDS:

        present = int(
            word in url_lower
        )

        f[f"keyword_{word}"] = present

        suspicious_count += present

    f["suspicious_keyword_count"] = suspicious_count

    # -------------------------
    # Brand-like patterns
    # -------------------------

    brand_count = 0

    for brand in BRANDS:

        present = int(
            brand in url_lower
        )

        f[f"brand_{brand}"] = present

        brand_count += present

    f["brand_count"] = brand_count

    # -------------------------
    # Unicode / Punycode
    # -------------------------

    f["unicode_count"] = sum(
        ord(c) > 127
        for c in url
    )

    f["has_unicode"] = int(
        f["unicode_count"] > 0
    )

    f["has_punycode"] = int(
        "xn--" in hostname.lower()
    )

    # -------------------------
    # Long token detection
    # -------------------------

    tokens = re.split(
        r"[^a-zA-Z0-9]+",
        hostname
    )

    tokens = [
        x for x in tokens
        if x
    ]

    f["max_hostname_token_length"] = (
        max(map(len, tokens))
        if tokens
        else 0
    )

    f["hostname_token_count"] = len(tokens)

    return f