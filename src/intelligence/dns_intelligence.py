from functools import lru_cache
from typing import Any, Dict, List


@lru_cache(maxsize=2048)
def analyze_dns(hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
    records: Dict[str, List[str]] = {
        record_type: []
        for record_type in ("A", "AAAA", "MX", "NS", "CNAME", "TXT")
    }
    errors: List[Dict[str, str]] = []
    try:
        import dns.resolver
    except ImportError:
        return {
            "status": "unavailable",
            "hostname": hostname,
            "records": records,
            "errors": [{"type": "dependency", "message": "dnspython is not installed"}],
            "signals": [],
        }

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    for record_type in records:
        try:
            answers = resolver.resolve(hostname, record_type)
            records[record_type] = [
                answer.to_text().strip('"') for answer in answers
            ]
        except dns.resolver.NXDOMAIN:
            errors.append({"type": record_type, "message": "nxdomain"})
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            errors.append({"type": record_type, "message": "no_answer"})
        except dns.exception.Timeout:
            errors.append({"type": record_type, "message": "timeout"})
        except Exception as exc:
            errors.append({"type": record_type, "message": str(exc)})

    populated = sum(bool(values) for values in records.values())
    status = "available" if populated == len(records) else (
        "partial" if populated else "no_records"
    )
    signals = []
    if not records["MX"]:
        signals.append({"signal": "no_mx_record", "interpretation": "supporting"})
    return {
        "status": status,
        "hostname": hostname,
        "records": records,
        "errors": errors,
        "signals": signals,
    }
