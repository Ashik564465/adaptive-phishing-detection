
from typing import Dict, Any, List

from src.intelligence.phishtank import check_phishtank
from src.intelligence.openphish import check_openphish
from src.intelligence.urlhaus import check_urlhaus


def check_threat_intelligence(url: str) -> Dict[str, Any]:
    """
    Check a URL against all configured threat-intelligence sources.

    Sources:
        - PhishTank  -> phishing intelligence
        - OpenPhish  -> phishing intelligence
        - URLhaus    -> malware intelligence

    Important:
        UNKNOWN does NOT mean legitimate.
    """

    results: List[Dict[str, Any]] = []

    # ---------------------------------------------------------
    # PhishTank
    # ---------------------------------------------------------

    phishtank_result = check_phishtank(url)

    results.append(phishtank_result)

    # ---------------------------------------------------------
    # OpenPhish
    # ---------------------------------------------------------

    openphish_result = check_openphish(url)

    results.append(openphish_result)

    # ---------------------------------------------------------
    # URLhaus
    # ---------------------------------------------------------

    urlhaus_result = check_urlhaus(url)

    results.append(urlhaus_result)

    # ---------------------------------------------------------
    # Aggregate results
    # ---------------------------------------------------------

    phishing_sources = []
    malware_sources = []
    errors = []

    for result in results:

        source = result.get("source")
        status = result.get("status")

        if status == "known_phishing":

            phishing_sources.append(source)

        elif status == "known_malware":

            malware_sources.append(source)

        elif status == "error":

            errors.append({
                "source": source,
                "error": result.get("error")
            })

    # ---------------------------------------------------------
    # Overall status
    # ---------------------------------------------------------

    if phishing_sources:

        overall_status = "known_phishing"

    elif malware_sources:

        overall_status = "known_malware"

    elif errors and len(errors) == len(results):

        overall_status = "error"

    else:

        overall_status = "unknown"

    # ---------------------------------------------------------
    # Return unified result
    # ---------------------------------------------------------

    return {
        "url": url,

        "status": overall_status,

        "known_phishing": bool(phishing_sources),

        "known_malware": bool(malware_sources),

        "phishing_sources": phishing_sources,

        "malware_sources": malware_sources,

        "errors": errors,

        "sources": results
    }


if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://example.com",
        "https://google.com.evil.com/login"
    ]

    for test_url in test_urls:

        print("\n")
        print("=" * 80)
        print(f"URL: {test_url}")
        print("=" * 80)

        result = check_threat_intelligence(test_url)

        print(
            f"\nOverall Status: "
            f"{result['status']}"
        )

        print(
            f"Known Phishing: "
            f"{result['known_phishing']}"
        )

        print(
            f"Known Malware: "
            f"{result['known_malware']}"
        )

        print(
            f"Phishing Sources: "
            f"{result['phishing_sources']}"
        )

        print(
            f"Malware Sources: "
            f"{result['malware_sources']}"
        )

        print(
            f"Errors: "
            f"{result['errors']}"
        )

        print("\nIndividual Sources:")

        for source in result["sources"]:

            print(
                f"  {source['source']}: "
                f"{source['status']}"
            )

