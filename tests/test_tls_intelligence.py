import ssl
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.intelligence.tls_intelligence import (
    _certificate_valid_at,
    analyze_tls,
)


def _cert_date(value):
    return value.strftime("%b %d %H:%M:%S %Y GMT")


class TestTlsIntelligenceTimestamps(unittest.TestCase):
    def tearDown(self):
        analyze_tls.cache_clear()

    def test_certificate_validity_is_checked_at_observation_time(self):
        observed_at = datetime(2026, 10, 10, 10, tzinfo=timezone.utc)

        self.assertTrue(_certificate_valid_at(
            "Oct 09 00:00:00 2026 GMT",
            "Oct 11 00:00:00 2026 GMT",
            observed_at,
        ))
        self.assertFalse(_certificate_valid_at(
            "Oct 01 00:00:00 2026 GMT",
            "Oct 09 00:00:00 2026 GMT",
            observed_at,
        ))
        self.assertIsNone(_certificate_valid_at(None, None, observed_at))

    def test_successful_scan_records_scan_and_certificate_timestamps(self):
        now = datetime.now(timezone.utc)
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.getpeercert.return_value = {
            "issuer": ((("organizationName", "Example CA"),),),
            "subject": ((("commonName", "example.test"),),),
            "notBefore": _cert_date(now - timedelta(days=1)),
            "notAfter": _cert_date(now + timedelta(days=1)),
            "subjectAltName": (("DNS", "example.test"),),
        }
        context = MagicMock()
        context.wrap_socket.return_value = connection

        with (
            patch("src.intelligence.tls_intelligence.ssl.create_default_context",
                 return_value=context),
            patch("src.intelligence.tls_intelligence.socket.create_connection",
                 return_value=raw_socket),
        ):
            result = analyze_tls("example.test")

        certificate = result["certificate"]
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["source"], "tls_handshake")
        self.assertEqual(certificate["validity_status"], "valid")
        self.assertEqual(certificate["validation_status"], "valid")
        self.assertTrue(certificate["valid_at_observation"])
        self.assertTrue(certificate["hostname_match"])
        self.assertTrue(certificate["san_matched"])
        self.assertIsNotNone(certificate["observed_at"])
        self.assertIsNotNone(result["collected_at"])
        self.assertLessEqual(
            datetime.fromisoformat(certificate["observed_at"]),
            datetime.fromisoformat(result["collected_at"]),
        )

    def test_expired_certificate_is_not_reported_as_hostname_mismatch(self):
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        context = MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            10,
            "certificate has expired",
        )

        with (
            patch("src.intelligence.tls_intelligence.ssl.create_default_context",
                 return_value=context),
            patch("src.intelligence.tls_intelligence.socket.create_connection",
                 return_value=raw_socket),
        ):
            result = analyze_tls("expired.example.test")

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["certificate"]["validity_status"], "invalid")
        self.assertEqual(result["certificate"]["validation_status"], "invalid")
        self.assertFalse(result["certificate"]["valid_at_observation"])
        self.assertIsNotNone(result["certificate"]["observed_at"])
        self.assertIsNone(result["certificate"]["hostname_match"])
        self.assertIn(
            "tls_certificate_invalid",
            [item["signal"] for item in result["signals"]],
        )
        self.assertNotIn(
            "tls_hostname_mismatch",
            [item["signal"] for item in result["signals"]],
        )

    def test_hostname_verification_error_is_not_mislabeled_as_expiry(self):
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        context = MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            62,
            "hostname mismatch",
        )

        with (
            patch("src.intelligence.tls_intelligence.ssl.create_default_context",
                 return_value=context),
            patch("src.intelligence.tls_intelligence.socket.create_connection",
                 return_value=raw_socket),
        ):
            result = analyze_tls("wrong.example.test")

        self.assertEqual(result["certificate"]["hostname_match"], False)
        self.assertEqual(result["certificate"]["validity_status"], "unknown")
        self.assertEqual(result["certificate"]["validation_status"], "invalid")
        self.assertEqual(
            [item["signal"] for item in result["signals"]],
            ["tls_hostname_mismatch"],
        )


if __name__ == "__main__":
    unittest.main()
