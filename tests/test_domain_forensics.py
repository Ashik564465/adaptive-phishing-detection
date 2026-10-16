import unittest
import json
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver
import requests

from src.intelligence.domain_forensics import (
    MAX_CERTIFICATES,
    _normalize_registered_domain,
    investigate_domain,
)
from src.risk.models import DecisionState, FinalDecision, RiskLevel


COLLECTED_AT = "2026-10-10T10:42:00+00:00"

# Reduced from the observed production-shaped output: partial DNS data,
# crt.sh timeout, valid RIPEstat prefix, but an empty ASN list.
OBSERVED_OUTPUT_FIXTURE = {
    "dns_records": {
        "A": ["172.66.147.243", "104.20.23.154"],
        "AAAA": ["2606:4700:9b05:72db:f2a7:0:ef6b:ff98"],
        "MX": ["0 ."],
    },
    "ct_error": requests.Timeout("crt.sh read timeout"),
    "ripe_data": {
        "data": {
            "prefix": "172.66.144.0/20",
            "asns": [],
        }
    },
}


def _answer(*values):
    return [Mock(to_text=Mock(return_value=value)) for value in values]


def _domain_info(**overrides):
    result = {
        "status": "available",
        "reason": "rdap_metadata",
        "creation_date": "2020-01-01T00:00:00Z",
        "expiry_date": "2027-01-01T00:00:00Z",
        "registrar": "Example Registrar",
        "nameservers": ["ns1.example.com"],
        "domain_age_days": 0,
        "domain_age_known": True,
    }
    result.update(overrides)
    return result


class TestDomainForensics(unittest.TestCase):
    def test_normalizes_url_subdomain_to_registered_domain(self):
        self.assertEqual(
            _normalize_registered_domain(
                "https://login.accounts.example.co.uk/path?q=value"
            ),
            "example.co.uk",
        )

    def test_rejects_credentials_and_ip_addresses(self):
        for value in (
            "https://user:secret@example.com",
            "https://127.0.0.1",
            "file:///etc/passwd",
            "bad..example.com",
        ):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    _normalize_registered_domain(value)

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics.time.sleep")
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_observed_fixture_preserves_partial_dns_and_prefix_without_asn(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        mock_sleep,
        _mock_now,
    ):
        resolver = mock_resolver_class.return_value

        def resolve(_domain, record_type, **_kwargs):
            if record_type == "A":
                return _answer(*OBSERVED_OUTPUT_FIXTURE["dns_records"]["A"])
            if record_type == "AAAA":
                return _answer(*OBSERVED_OUTPUT_FIXTURE["dns_records"]["AAAA"])
            if record_type == "MX":
                return _answer("0 .")
            if record_type == "NS":
                raise dns.resolver.NoAnswer()
            if record_type == "CNAME":
                raise dns.resolver.NXDOMAIN()
            raise dns.exception.Timeout()

        resolver.resolve.side_effect = resolve
        mock_domain.return_value = _domain_info()

        def public_source(url, **_kwargs):
            if "crt.sh" in url:
                raise OBSERVED_OUTPUT_FIXTURE["ct_error"]
            return OBSERVED_OUTPUT_FIXTURE["ripe_data"]

        mock_get_json.side_effect = public_source

        result = investigate_domain(
            "https://example.com",
            ct_retries=1,
            use_certspotter_fallback=False,
        )

        self.assertEqual(result["dns_records"]["A"], OBSERVED_OUTPUT_FIXTURE["dns_records"]["A"])
        self.assertEqual(result["dns_records"]["MX"], ["0 ."])
        self.assertEqual(result["dns_interpretations"]["null_mx"], True)
        self.assertEqual(result["dns_interpretations"]["record_status"]["NS"], "no_answer")
        self.assertEqual(result["dns_interpretations"]["record_status"]["CNAME"], "nxdomain")
        self.assertEqual(result["dns_interpretations"]["record_status"]["TXT"], "timeout")
        self.assertEqual(result["certificate_history_status"], "unavailable")
        self.assertEqual(result["subdomain_discovery_status"], "unavailable")
        self.assertEqual(
            result["sources"]["subdomain_discovery"]["status"],
            "unavailable",
        )
        self.assertEqual(result["infrastructure"][0]["prefix"], "172.66.144.0/20")
        self.assertEqual(result["infrastructure"][0]["asns"], [])
        self.assertEqual(result["infrastructure"][0]["asn_status"], "unavailable")
        self.assertIn("asn", result["unavailable_evidence"])
        self.assertEqual(mock_get_json.call_count, 5)
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_successful_certificate_history_and_subdomain_discovery(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        resolver = mock_resolver_class.return_value
        resolver.resolve.side_effect = lambda _domain, kind, **_kwargs: (
            _answer("203.0.113.10")
            if kind == "A"
            else (_ for _ in ()).throw(dns.resolver.NoAnswer())
        )
        mock_domain.return_value = _domain_info(
            creation_date="2020-01-01T00:00:00Z",
            expiry_date="2027-01-01T00:00:00Z",
        )
        certificates = [{
                "id": str(index),
                "common_name": f"www-{index}.example.com",
                "name_value": "example.com\nwww.example.com\n*.api.example.com",
                "issuer_name": "Example CA",
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2026-01-01T00:00:00Z",
                "entry_timestamp": "2025-01-01T01:00:00Z",
            }
            for index in range(MAX_CERTIFICATES + 5)
        ]
        mock_get_json.side_effect = [
            certificates,
            {"data": {"prefix": "203.0.113.0/24", "asns": [64500]}},
        ]

        result = investigate_domain(
            "example.com",
            use_certspotter_fallback=False,
        )

        self.assertEqual(result["certificate_history_status"], "available")
        self.assertEqual(result["subdomain_discovery_status"], "available")
        self.assertEqual(len(result["certificate_history"]), MAX_CERTIFICATES)
        self.assertEqual(result["subdomains"], ["api.example.com", "www.example.com"])
        self.assertEqual(result["infrastructure"][0]["asn_status"], "available")
        self.assertEqual(result["infrastructure"][0]["asns"], [64500])

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_example_com_certspotter_response_and_expected_cname_absence(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        def resolve(_domain, record_type, **_kwargs):
            if record_type == "A":
                return _answer("203.0.113.10")
            raise dns.resolver.NoAnswer()

        mock_resolver_class.return_value.resolve.side_effect = resolve
        mock_domain.return_value = _domain_info()
        certificates = [
            {
                "id": str(index),
                "cert_sha256": f"{index:064x}",
                "dns_names": ["example.com", "www.example.com"],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            }
            for index in range(1, 14)
        ]
        mock_get_json.side_effect = [
            requests.HTTPError("crt.sh unavailable"),
            certificates,
            {"data": {"prefix": "203.0.113.0/24", "asns": [64500]}},
        ]

        result = investigate_domain(
            "example.com",
            ct_retries=0,
            use_certspotter_fallback=True,
        )

        self.assertEqual(len(result["certificate_history"]), 13)
        self.assertEqual(result["subdomains"], ["www.example.com"])
        self.assertEqual(result["certificate_history_status"], "available")
        self.assertEqual(result["subdomain_discovery_status"], "available")
        self.assertEqual(
            result["dns_interpretations"]["record_status"]["CNAME"],
            "no_answer",
        )
        self.assertEqual(result["sources"]["dns"]["status"], "available")
        self.assertEqual(result["status"], "available")
        first_certificate = result["certificate_history"][0]
        self.assertIsNone(first_certificate["common_name"])
        self.assertIsNone(first_certificate["issuer"])
        self.assertIsNone(first_certificate["logged_at"])
        attempts = result["sources"]["certificate_transparency"]["attempts"]
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(attempt["collected_at"] for attempt in attempts))

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics.time.sleep")
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_ct_empty_response_is_distinct_from_ct_timeout(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        mock_sleep,
        _mock_now,
    ):
        resolver = mock_resolver_class.return_value
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = [[], {"data": {"prefix": None, "asns": []}}]

        result = investigate_domain("example.com")

        self.assertEqual(result["certificate_history_status"], "no_records")
        self.assertEqual(result["subdomain_discovery_status"], "no_records")
        self.assertEqual(result["sources"]["certificate_transparency"]["status"], "no_records")
        mock_sleep.assert_not_called()

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics.time.sleep")
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_ct_retry_respects_configured_attempts_and_deadline_budget(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        mock_sleep,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = [
            requests.Timeout("read timeout"),
            requests.Timeout("read timeout"),
            {"data": {"prefix": None, "asns": []}},
        ]

        result = investigate_domain(
            "example.com",
            ct_timeout=0.25,
            ct_retries=1,
            retry_backoff=0.01,
            deadline_seconds=15,
            use_certspotter_fallback=False,
        )

        self.assertEqual(result["certificate_history_status"], "unavailable")
        self.assertEqual(result["subdomain_discovery_status"], "unavailable")
        self.assertEqual(mock_get_json.call_count, 2)  # two CT attempts; no DNS IPs
        self.assertEqual(mock_sleep.call_count, 1)
        for call in mock_get_json.call_args_list[:2]:
            self.assertEqual(call.kwargs["timeout"], (0.25, 0.25))

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics.time.sleep")
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_http_502_is_retried_then_reported_unavailable(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        mock_sleep,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        error = requests.HTTPError("502 Bad Gateway")
        error.response = Mock(status_code=502)
        mock_get_json.side_effect = [error, error]

        result = investigate_domain(
            "example.com",
            ct_retries=1,
            retry_backoff=0.01,
            use_certspotter_fallback=False,
        )

        self.assertEqual(result["certificate_history_status"], "unavailable")
        self.assertEqual(result["subdomain_discovery_status"], "unavailable")
        attempts = result["sources"]["certificate_transparency"]["attempts"]
        self.assertEqual([item["status"] for item in attempts], ["http_502", "http_502"])
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_malformed_ct_json_is_unavailable_not_empty(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = json.JSONDecodeError("invalid JSON", "{", 1)

        result = investigate_domain(
            "example.com",
            ct_retries=0,
            use_certspotter_fallback=False,
        )

        self.assertEqual(result["certificate_history_status"], "unavailable")
        self.assertEqual(result["subdomain_discovery_status"], "unavailable")
        self.assertEqual(
            result["sources"]["certificate_transparency"]["attempts"][0]["status"],
            "malformed_response",
        )

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics.time.sleep")
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_certspotter_fallback_failure_preserves_both_source_errors(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_sleep,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        bad_gateway = requests.HTTPError("502 Bad Gateway")
        bad_gateway.response = Mock(status_code=502)
        mock_get_json.side_effect = [
            bad_gateway,
            bad_gateway,
            bad_gateway,
            bad_gateway,
            requests.Timeout("CertSpotter timeout"),
        ]

        result = investigate_domain(
            "example.com",
            ct_retries=3,
            use_certspotter_fallback=True,
        )

        self.assertEqual(result["certificate_history_status"], "unavailable")
        self.assertEqual(result["subdomain_discovery_status"], "unavailable")
        self.assertEqual(
            result["sources"]["certificate_transparency"]["status"],
            "unavailable",
        )
        error_sources = {item["source"] for item in result["errors"]}
        self.assertNotIn("crt_sh", error_sources)
        self.assertNotIn("certspotter", error_sources)
        self.assertEqual(mock_get_json.call_count, 5)
        self.assertIn("certificate_history", result["unavailable_evidence"])
        self.assertIn("subdomain_discovery", result["unavailable_evidence"])
        self.assertEqual(
            [item["source"] for item in result["sources"]["certificate_transparency"]["attempts"]],
            ["crt_sh", "crt_sh", "crt_sh", "crt_sh", "certspotter"],
        )
        self.assertNotIn("certificate_transparency_crtsh", result["sources"])
        self.assertNotIn("certificate_transparency_certspotter", result["sources"])

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_certspotter_successful_fallback_parses_documented_response(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        resolver = mock_resolver_class.return_value
        resolver.resolve.side_effect = lambda _domain, kind, **_kwargs: (
            _answer("203.0.113.10")
            if kind == "A"
            else (_ for _ in ()).throw(dns.resolver.NoAnswer())
        )
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = [
            requests.Timeout("crt.sh timeout"),
            [{
                "id": "ct-entry-1",
                "dns_names": ["example.com", "www.example.com"],
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2026-01-01T00:00:00Z",
            }],
            {"data": {"prefix": "203.0.113.0/24", "asns": [64500]}},
        ]

        result = investigate_domain(
            "example.com",
            ct_retries=0,
            use_certspotter_fallback=True,
        )

        self.assertEqual(result["certificate_history_status"], "available")
        self.assertEqual(result["subdomain_discovery_status"], "available")
        self.assertEqual(result["subdomains"], ["www.example.com"])
        self.assertEqual(
            result["sources"]["certificate_transparency"]["source"],
            "certspotter",
        )
        self.assertEqual(
            result["sources"]["certificate_transparency"]["selected_source"],
            "certspotter",
        )
        attempts = result["sources"]["certificate_transparency"]["attempts"]
        self.assertEqual(attempts[0]["source"], "crt_sh")
        self.assertEqual(attempts[0]["status"], "timeout")
        self.assertEqual(len(attempts), 2)

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_certspotter_malformed_response_fails_without_claiming_empty(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = [
            requests.HTTPError("502 Bad Gateway"),
            {"unexpected": "object"},
        ]

        result = investigate_domain(
            "example.com",
            ct_retries=0,
            use_certspotter_fallback=True,
        )

        self.assertEqual(result["certificate_history_status"], "unavailable")
        self.assertEqual(result["subdomain_discovery_status"], "unavailable")
        attempts = result["sources"]["certificate_transparency"]["attempts"]
        self.assertEqual(attempts[-1]["source"], "certspotter")
        self.assertEqual(attempts[-1]["status"], "malformed_response")

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_duplicate_certificates_and_out_of_scope_names_are_filtered(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        cert = {
            "id": "duplicate",
            "common_name": "WWW.Example.com.",
            "dns_names": [
                "EXAMPLE.COM.",
                "WWW.Example.com.",
                "api.example.com",
                "example.com.attacker.test",
                "notexample.com",
                "unrelated.test",
                "*.api.example.com",
                "bad..example.com",
                "www.example.com..",
                "bad_label.example.com",
            ],
            "cert_sha256": "A" * 64,
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
        }
        distinct_certificate = {
            **cert,
            "id": "distinct",
            "cert_sha256": "B" * 64,
        }
        mock_get_json.side_effect = [
            requests.HTTPError("502 Bad Gateway"),
            [cert, dict(cert), distinct_certificate],
        ]

        result = investigate_domain(
            "example.com",
            ct_retries=0,
            use_certspotter_fallback=True,
        )

        self.assertEqual(len(result["certificate_history"]), 2)
        self.assertEqual(
            {certificate["id"] for certificate in result["certificate_history"]},
            {"duplicate", "distinct"},
        )
        self.assertEqual(
            result["certificate_history"][0]["name_values"],
            ["example.com", "www.example.com", "api.example.com"],
        )
        self.assertEqual(
            result["subdomains"],
            ["api.example.com", "www.example.com"],
        )

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_empty_certspotter_results_report_no_records_independently(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = [
            requests.HTTPError("502 Bad Gateway"),
            [{"id": "outside", "dns_names": ["attacker.test"]}],
        ]

        result = investigate_domain(
            "example.com",
            ct_retries=0,
            use_certspotter_fallback=True,
        )

        self.assertEqual(result["certificate_history_status"], "no_records")
        self.assertEqual(result["subdomain_discovery_status"], "no_records")
        self.assertEqual(result["sources"]["certificate_transparency"]["status"], "no_records")

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_rdap_malformed_and_future_dates_are_not_used_for_age(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info(
            creation_date="not-a-date",
            expiry_date="2099-99-99",
        )
        mock_get_json.return_value = []

        result = investigate_domain(
            "example.com",
            use_certspotter_fallback=False,
        )

        self.assertEqual(result["registration"]["retrieval_status"], "available")
        self.assertEqual(result["registration"]["registration_status"], "registered")
        self.assertIsNone(result["registration"]["data"]["domain_age_days"])
        self.assertFalse(result["registration"]["data"]["domain_age_known"])
        self.assertEqual(
            result["registration"]["data"]["malformed_fields"],
            ["creation_date", "expiry_date"],
        )

    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_malformed_rdap_payload_is_reported_nonfatally(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = ["not", "an", "RDAP object"]
        mock_get_json.return_value = []

        result = investigate_domain("example.com")

        self.assertEqual(result["registration"]["retrieval_status"], "unavailable")
        self.assertEqual(result["registration"]["registration_status"], "unknown")
        self.assertTrue(any(error["source"] == "registration" for error in result["errors"]))

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_registration_age_uses_creation_date_and_collection_timestamp(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()
        mock_domain.return_value = _domain_info(
            creation_date="2020-10-10T10:42:00Z",
            expiry_date=None,
        )
        mock_get_json.return_value = []

        result = investigate_domain("example.com")

        self.assertEqual(
            result["registration"]["data"]["domain_age_days"],
            2191,
        )
        self.assertEqual(result["registration"]["data"]["expiry_date"], None)

    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_expired_deadline_skips_rdap_and_public_http_requests(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
    ):
        mock_resolver_class.return_value.resolve.side_effect = dns.resolver.NoAnswer()

        result = investigate_domain("example.com", deadline_seconds=0.000001)

        self.assertEqual(result["registration"]["retrieval_status"], "unavailable")
        self.assertEqual(result["certificate_history_status"], "unavailable")
        mock_domain.assert_not_called()
        mock_get_json.assert_not_called()

    @patch("src.intelligence.domain_forensics._utc_now", return_value=COLLECTED_AT)
    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_asn_empty_preserves_prefix_and_reports_asn_unavailable(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
        _mock_now,
    ):
        resolver = mock_resolver_class.return_value
        resolver.resolve.side_effect = lambda _domain, kind, **_kwargs: (
            _answer("203.0.113.10")
            if kind == "A"
            else (_ for _ in ()).throw(dns.resolver.NoAnswer())
        )
        mock_domain.return_value = _domain_info()
        mock_get_json.side_effect = [
            [],
            {"data": {"prefix": "203.0.113.0/24", "asns": []}},
        ]

        result = investigate_domain("example.com")

        item = result["infrastructure"][0]
        self.assertEqual(item["prefix"], "203.0.113.0/24")
        self.assertEqual(item["prefix_status"], "available")
        self.assertEqual(item["asns"], [])
        self.assertEqual(item["asn_status"], "unavailable")
        self.assertEqual(result["sources"]["ip_prefix"]["status"], "available")
        self.assertEqual(result["sources"]["asn"]["status"], "unavailable")

    @patch("src.intelligence.domain_forensics._get_json")
    @patch("src.intelligence.domain_forensics.analyze_domain")
    @patch("src.intelligence.domain_forensics.dns.resolver.Resolver")
    def test_invalid_input_makes_no_collection_calls(
        self,
        mock_resolver_class,
        mock_domain,
        mock_get_json,
    ):
        result = investigate_domain("https://user:password@example.com")

        self.assertEqual(result["status"], "invalid_input")
        self.assertIsNone(result["domain"])
        mock_resolver_class.assert_not_called()
        mock_domain.assert_not_called()
        mock_get_json.assert_not_called()

    def test_existing_api_response_schema_is_unchanged(self):
        decision = FinalDecision(
            url="https://example.com",
            decision=DecisionState.UNKNOWN,
            risk_level=RiskLevel.MEDIUM,
            risk_score=50,
            confidence=50,
            decision_basis="insufficient_evidence",
        )

        payload = decision.to_combined_dict()

        self.assertIn("analysis", payload)
        self.assertIn("scores", payload)
        self.assertIn("identity", payload)
        self.assertIn("dns", payload)
        self.assertIn("tls", payload)
        self.assertIn("domain_forensics", payload)
        self.assertEqual(payload["domain_forensics"]["status"], "unavailable")
        self.assertNotIn("pipeline", payload)


if __name__ == "__main__":
    unittest.main()
