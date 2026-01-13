"""Tests for Host Header Injection Scanner module."""

import unittest
import asyncio
import hashlib
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.host_header_scanner import HostHeaderScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestHostHeaderScanner(unittest.TestCase):
    """Test cases for HostHeaderScanner class."""

    def setUp(self):
        self.config = Config()
        self.config.timeout = 5
        self.scanner = HostHeaderScanner(self.config)

    def _create_mock_response(self, status=200, headers=None, body=""):
        """Helper to create a mock aiohttp response."""
        mock_response = AsyncMock()
        mock_response.status = status
        mock_response.headers = headers or {}
        mock_response.text = AsyncMock(return_value=body)
        return mock_response

    def _create_mock_session(self, responses):
        """Helper to create a mock session with response list."""
        mock_session = MagicMock()
        response_iter = iter(responses)

        def get_next(*args, **kwargs):
            try:
                resp = next(response_iter)
            except StopIteration:
                resp = self._create_mock_response()

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=resp)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            return mock_cm

        mock_session.get = MagicMock(side_effect=get_next)
        return mock_session

    def _patch_session(self, mock_session):
        """Create patched ClientSession context manager."""
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=None)
        return mock_session_cm

    # -------------------------------------------------------------------------
    # Configuration Tests
    # -------------------------------------------------------------------------

    def test_default_configuration(self):
        """Test default configuration values."""
        self.assertEqual(self.scanner.name, "Host Header Injection")
        self.assertGreater(len(self.scanner.host_payloads), 5)
        self.assertGreater(len(self.scanner.override_headers), 3)

    def test_canary_domain_set(self):
        """Test canary domain is configured."""
        self.assertIsNotNone(self.scanner.canary_domain)
        self.assertIn(".", self.scanner.canary_domain)

    # -------------------------------------------------------------------------
    # URL Helper Tests
    # -------------------------------------------------------------------------

    def test_get_url_with_url_target(self):
        """Test _get_url with URL target."""
        target = Target(
            original_input="https://example.com",
            host="example.com",
            url="https://example.com"
        )
        self.assertEqual(self.scanner._get_url(target), "https://example.com")

    def test_get_url_with_host_target(self):
        """Test _get_url with host-only target."""
        target = Target(original_input="example.com", host="example.com")
        self.assertEqual(self.scanner._get_url(target), "http://example.com")

    def test_get_url_empty_target(self):
        """Test _get_url with empty target."""
        target = Target(original_input="", host="")
        self.assertIsNone(self.scanner._get_url(target))

    # -------------------------------------------------------------------------
    # Empty Target Tests
    # -------------------------------------------------------------------------

    def test_empty_target_returns_empty(self):
        """Test that empty target returns empty dict."""
        target = Target(original_input="", host="")
        results = asyncio.run(self.scanner.run(target))
        self.assertEqual(results, {})

    # -------------------------------------------------------------------------
    # Severity Classification Tests
    # -------------------------------------------------------------------------

    def test_get_severity_high_for_redirect(self):
        """Test high severity for redirect reflection."""
        severity = self.scanner._get_severity("reflected_in_redirect", "Host")
        self.assertEqual(severity, "high")

    def test_get_severity_high_for_cache_poisoning(self):
        """Test high severity for cache poisoning."""
        severity = self.scanner._get_severity("cache_poisoning_potential", "Host")
        self.assertEqual(severity, "high")

    def test_get_severity_medium_for_body_reflection(self):
        """Test medium severity for body reflection."""
        severity = self.scanner._get_severity("reflected_in_body", "Host")
        self.assertEqual(severity, "medium")

    def test_get_severity_low_for_unknown(self):
        """Test low severity for unknown types."""
        severity = self.scanner._get_severity("unknown_type", "Host")
        self.assertEqual(severity, "low")

    # -------------------------------------------------------------------------
    # Description and Impact Tests
    # -------------------------------------------------------------------------

    def test_get_description_returns_string(self):
        """Test description is returned for known types."""
        desc = self.scanner._get_description("reflected_in_body")
        self.assertIsInstance(desc, str)
        self.assertGreater(len(desc), 10)

    def test_get_impact_returns_string(self):
        """Test impact is returned for known types."""
        impact = self.scanner._get_impact("reflected_in_redirect")
        self.assertIsInstance(impact, str)
        self.assertIn("reset", impact.lower())  # Password reset mentioned

    # -------------------------------------------------------------------------
    # Injection Detection Tests
    # -------------------------------------------------------------------------

    def test_analyze_injection_body_reflection(self):
        """Test detection of canary in response body."""
        canary = self.scanner.canary_domain
        baseline = {"status": 200, "length": 100, "hash": "abc123"}

        result = self.scanner._analyze_injection(
            canary,
            f"<html><a href='https://{canary}/path'>Link</a></html>",
            {},
            200,
            baseline
        )
        self.assertEqual(result, "reflected_in_body")

    def test_analyze_injection_header_reflection(self):
        """Test detection of canary in response headers."""
        canary = self.scanner.canary_domain
        baseline = {"status": 200, "length": 100, "hash": "abc123"}

        result = self.scanner._analyze_injection(
            canary,
            "<html>Normal page</html>",
            {"Link": f"<https://{canary}/api>; rel=api"},
            200,
            baseline
        )
        self.assertEqual(result, "reflected_in_header")

    def test_analyze_injection_redirect_reflection(self):
        """Test detection of canary in Location header."""
        canary = self.scanner.canary_domain
        baseline = {"status": 200, "length": 100, "hash": "abc123"}

        result = self.scanner._analyze_injection(
            canary,
            "",
            {"Location": f"https://{canary}/redirect"},
            200,
            baseline
        )
        self.assertEqual(result, "reflected_in_redirect")

    def test_analyze_injection_causes_redirect(self):
        """Test detection of injection causing redirect."""
        baseline = {"status": 200, "length": 100, "hash": "abc123"}

        result = self.scanner._analyze_injection(
            "payload",
            "",
            {},
            302,
            baseline
        )
        self.assertEqual(result, "causes_redirect")

    def test_analyze_injection_causes_error(self):
        """Test detection of injection causing server error."""
        baseline = {"status": 200, "length": 100, "hash": "abc123"}

        result = self.scanner._analyze_injection(
            "payload",
            "",
            {},
            500,
            baseline
        )
        self.assertEqual(result, "causes_error")

    def test_analyze_injection_no_vuln(self):
        """Test no vulnerability detected on normal response."""
        baseline = {"status": 200, "length": 100, "hash": hashlib.md5(b"test").hexdigest()}

        result = self.scanner._analyze_injection(
            "payload",
            "test",
            {},
            200,
            baseline
        )
        self.assertIsNone(result)

    # -------------------------------------------------------------------------
    # Check Injection Success Tests
    # -------------------------------------------------------------------------

    def test_check_injection_success_in_body(self):
        """Test successful injection detection in body."""
        result = self.scanner._check_injection_success(
            "Visit evil.com for more",
            {},
            "evil.com"
        )
        self.assertTrue(result)

    def test_check_injection_success_in_headers(self):
        """Test successful injection detection in headers."""
        result = self.scanner._check_injection_success(
            "Normal body",
            {"Location": "https://evil.com/path"},
            "evil.com"
        )
        self.assertTrue(result)

    def test_check_injection_success_not_found(self):
        """Test no injection found."""
        result = self.scanner._check_injection_success(
            "Normal body",
            {"Server": "nginx"},
            "evil.com"
        )
        self.assertFalse(result)

    # -------------------------------------------------------------------------
    # Integration Tests with Mocking
    # -------------------------------------------------------------------------

    def test_vulnerable_host_reflection(self):
        """Test detection of Host header reflection in body."""
        canary = self.scanner.canary_domain
        baseline_body = "<html>Normal page</html>"
        vuln_body = f"<html>Link: https://{canary}/page</html>"

        responses = [
            # Baseline
            self._create_mock_response(status=200, body=baseline_body),
            # Vulnerable response
            self._create_mock_response(status=200, body=vuln_body),
            # Many more normal responses
            *[self._create_mock_response(status=200, body=baseline_body) for _ in range(50)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results.get("vulnerable"))
            self.assertGreater(len(results.get("vulnerabilities", [])), 0)

    def test_safe_server_no_vulnerabilities(self):
        """Test that a safe server produces no vulnerabilities."""
        baseline_body = "<html>Normal page</html>"

        responses = [
            # All responses are identical and safe
            *[self._create_mock_response(status=200, body=baseline_body) for _ in range(50)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertFalse(results.get("vulnerable"))
            self.assertEqual(len(results.get("vulnerabilities", [])), 0)

    def test_connection_error_handling(self):
        """Test graceful handling of connection errors."""
        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=Exception("Connection failed"))
        mock_session.get = MagicMock(return_value=mock_cm)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            # Should handle error gracefully
            self.assertIn("error", results)

    # -------------------------------------------------------------------------
    # Override Headers Tests
    # -------------------------------------------------------------------------

    def test_override_headers_list(self):
        """Test that common override headers are included."""
        self.assertIn("X-Forwarded-Host", self.scanner.override_headers)
        self.assertIn("X-Host", self.scanner.override_headers)
        self.assertIn("X-Original-URL", self.scanner.override_headers)

    # -------------------------------------------------------------------------
    # Payload Tests
    # -------------------------------------------------------------------------

    def test_payloads_include_injection_types(self):
        """Test that payloads include various injection types."""
        payload_names = [p[0] for p in self.scanner.host_payloads]

        self.assertIn("direct_injection", payload_names)
        self.assertIn("localhost", payload_names)
        self.assertIn("metadata_ip", payload_names)


if __name__ == "__main__":
    unittest.main()
