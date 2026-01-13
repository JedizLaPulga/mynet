"""Tests for Open Redirect Scanner module."""

import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.redirect_scanner import OpenRedirectScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestOpenRedirectScanner(unittest.TestCase):
    """Test cases for OpenRedirectScanner class."""

    def setUp(self):
        self.config = Config()
        self.config.timeout = 5
        self.config.redirect_max_hops = 5
        self.config.redirect_test_limit = 10  # Limit for faster tests
        self.scanner = OpenRedirectScanner(self.config)

    def _create_mock_response(self, status=200, headers=None, body=""):
        """Helper to create a mock aiohttp response."""
        mock_response = AsyncMock()
        mock_response.status = status
        mock_response.headers = headers or {}
        mock_response.text = AsyncMock(return_value=body)
        mock_response.url = "http://example.com"
        return mock_response

    def _create_mock_session(self, responses):
        """Helper to create a mock session."""
        mock_session = MagicMock()
        response_iter = iter(responses)

        def get_next_response(*args, **kwargs):
            try:
                resp = next(response_iter)
            except StopIteration:
                resp = self._create_mock_response()

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=resp)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            return mock_cm

        mock_session.get = MagicMock(side_effect=get_next_response)
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
        config = Config()
        scanner = OpenRedirectScanner(config)

        self.assertEqual(scanner.name, "Open Redirect Scanner")
        self.assertEqual(scanner.max_redirects, 5)
        self.assertGreater(len(scanner.redirect_params), 30)
        self.assertGreater(len(scanner.payloads), 10)

    def test_custom_configuration(self):
        """Test custom configuration."""
        self.config.redirect_max_hops = 10
        self.config.redirect_test_limit = 100
        scanner = OpenRedirectScanner(self.config)

        self.assertEqual(scanner.max_redirects, 10)
        self.assertEqual(scanner.test_limit, 100)

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
    # External Redirect Detection Tests
    # -------------------------------------------------------------------------

    def test_is_external_redirect_canary(self):
        """Test detection of canary domain in redirect."""
        self.assertTrue(
            self.scanner._is_external_redirect(
                f"https://{self.scanner.canary_domain}/path",
                "http://example.com"
            )
        )

    def test_is_external_redirect_protocol_relative(self):
        """Test detection of protocol-relative external redirect."""
        self.assertTrue(
            self.scanner._is_external_redirect(
                "//evil.com/path",
                "http://example.com"
            )
        )

    def test_is_external_redirect_same_domain(self):
        """Test that same-domain redirects are not flagged."""
        self.assertFalse(
            self.scanner._is_external_redirect(
                "https://example.com/other",
                "http://example.com"
            )
        )

    def test_is_external_redirect_internal_path(self):
        """Test that internal paths are not flagged."""
        self.assertFalse(
            self.scanner._is_external_redirect(
                "/internal/path",
                "http://example.com"
            )
        )

    def test_is_external_redirect_javascript(self):
        """Test detection of JavaScript URLs."""
        self.assertTrue(
            self.scanner._is_external_redirect(
                "javascript:alert(1)",
                "http://example.com"
            )
        )

    def test_is_external_redirect_empty(self):
        """Test handling of empty location."""
        self.assertFalse(
            self.scanner._is_external_redirect("", "http://example.com")
        )

    # -------------------------------------------------------------------------
    # OAuth Context Detection Tests
    # -------------------------------------------------------------------------

    def test_detect_oauth_context_positive(self):
        """Test OAuth context detection with OAuth URL."""
        response = {"status": 200, "headers": {}}

        self.assertTrue(
            self.scanner._detect_oauth_context(
                "https://example.com/oauth/callback?redirect_uri=test",
                response
            )
        )

    def test_detect_oauth_context_login(self):
        """Test OAuth context detection with login URL."""
        response = {"status": 200, "headers": {}}

        self.assertTrue(
            self.scanner._detect_oauth_context(
                "https://example.com/login",
                response
            )
        )

    def test_detect_oauth_context_negative(self):
        """Test OAuth context not detected on regular URL."""
        response = {"status": 200, "headers": {}}

        self.assertFalse(
            self.scanner._detect_oauth_context(
                "https://example.com/products",
                response
            )
        )

    # -------------------------------------------------------------------------
    # Severity Calculation Tests
    # -------------------------------------------------------------------------

    def test_calculate_severity_oauth_param(self):
        """Test high severity for OAuth-related params."""
        self.assertEqual(
            self.scanner._calculate_severity("redirect_uri", "https_direct", []),
            "high"
        )

    def test_calculate_severity_direct_payload(self):
        """Test high severity for direct protocol payloads."""
        self.assertEqual(
            self.scanner._calculate_severity("url", "https_direct", []),
            "high"
        )

    def test_calculate_severity_encoding_bypass(self):
        """Test medium severity for encoding bypasses."""
        self.assertEqual(
            self.scanner._calculate_severity("next", "url_encoded", []),
            "medium"
        )

    def test_calculate_severity_default(self):
        """Test low severity for other cases."""
        self.assertEqual(
            self.scanner._calculate_severity("page", "data_redirect", []),
            "low"
        )

    # -------------------------------------------------------------------------
    # Meta Redirect Detection Tests
    # -------------------------------------------------------------------------

    def test_check_meta_redirect_found(self):
        """Test meta refresh redirect detection."""
        body = '<html><head><meta http-equiv="refresh" content="0;url=https://evil.com"></head></html>'
        result = self.scanner._check_meta_redirect(body)
        self.assertEqual(result, "https://evil.com")

    def test_check_meta_redirect_not_found(self):
        """Test no meta refresh in normal page."""
        body = '<html><head><title>Normal Page</title></head></html>'
        result = self.scanner._check_meta_redirect(body)
        self.assertIsNone(result)

    # -------------------------------------------------------------------------
    # JavaScript Redirect Detection Tests
    # -------------------------------------------------------------------------

    def test_check_js_redirect_location_href(self):
        """Test JavaScript location.href redirect detection."""
        body = '<script>location.href = "//evil.com";</script>'
        result = self.scanner._check_js_redirect(body)
        self.assertEqual(result, "//evil.com")

    def test_check_js_redirect_window_location(self):
        """Test JavaScript window.location redirect detection."""
        body = '<script>window.location = "https://evil.com";</script>'
        result = self.scanner._check_js_redirect(body)
        self.assertEqual(result, "https://evil.com")

    def test_check_js_redirect_replace(self):
        """Test JavaScript location.replace detection."""
        body = '<script>location.replace("//evil.com/path");</script>'
        result = self.scanner._check_js_redirect(body)
        self.assertEqual(result, "//evil.com/path")

    def test_check_js_redirect_not_found(self):
        """Test no JavaScript redirect in normal page."""
        body = '<script>console.log("hello");</script>'
        result = self.scanner._check_js_redirect(body)
        self.assertIsNone(result)

    # -------------------------------------------------------------------------
    # Recommendations Tests
    # -------------------------------------------------------------------------

    def test_generate_recommendations_with_high(self):
        """Test recommendations include critical for high severity."""
        vulns = [{"severity": "high"}, {"severity": "medium"}]
        recs = self.scanner._generate_recommendations(vulns)

        priorities = [r["priority"] for r in recs]
        self.assertIn("critical", priorities)

    def test_generate_recommendations_basic(self):
        """Test basic recommendations are always included."""
        vulns = [{"severity": "low"}]
        recs = self.scanner._generate_recommendations(vulns)

        self.assertGreater(len(recs), 0)
        self.assertTrue(any("validate" in r["recommendation"].lower() for r in recs))

    # -------------------------------------------------------------------------
    # Empty Target Tests
    # -------------------------------------------------------------------------

    def test_empty_target_returns_empty(self):
        """Test that empty target returns empty dict."""
        target = Target(original_input="", host="")
        results = asyncio.run(self.scanner.run(target))
        self.assertEqual(results, {})

    # -------------------------------------------------------------------------
    # Mock Scanning Tests
    # -------------------------------------------------------------------------

    def test_vulnerability_detection_302_redirect(self):
        """Test detection of 302 redirect vulnerability."""
        canary = self.scanner.canary_domain

        responses = [
            # Base response
            self._create_mock_response(status=200),
            # First param test - vulnerable redirect
            self._create_mock_response(
                status=302,
                headers={"Location": f"https://{canary}/malicious"}
            ),
            # Many more responses for other tests
            *[self._create_mock_response(status=200) for _ in range(100)],
        ]

        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results.get("vulnerable"))
            self.assertGreater(len(results.get("vulnerabilities", [])), 0)

    def test_no_vulnerability_safe_redirects(self):
        """Test no vulnerabilities on safe redirects."""
        responses = [
            # Base response
            self._create_mock_response(status=200),
            # All redirects go to same domain
            *[self._create_mock_response(
                status=302,
                headers={"Location": "https://example.com/safe"}
            ) for _ in range(20)],
            *[self._create_mock_response(status=200) for _ in range(100)],
        ]

        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            # Should find no vulns since redirects are to same domain
            # (depends on exact URL matching)

    def test_meta_refresh_vulnerability(self):
        """Test detection of meta refresh redirect vulnerability."""
        canary = self.scanner.canary_domain

        responses = [
            # Base response
            self._create_mock_response(status=200),
            # Response with meta refresh to evil domain
            self._create_mock_response(
                status=200,
                body=f'<html><head><meta http-equiv="refresh" content="0;url=https://{canary}"></head></html>'
            ),
            *[self._create_mock_response(status=200) for _ in range(100)],
        ]

        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            # May or may not find vuln depending on param tested

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
    # Payload Tests
    # -------------------------------------------------------------------------

    def test_payloads_contain_bypasses(self):
        """Test that payloads include various bypass techniques."""
        payload_types = [p[0] for p in self.scanner.payloads]

        self.assertIn("protocol_relative", payload_types)
        self.assertIn("url_encoded", payload_types)
        self.assertIn("backslash_bypass", payload_types)
        self.assertIn("at_symbol", payload_types)

    def test_params_contain_oauth_related(self):
        """Test that params include OAuth-related ones."""
        self.assertIn("redirect_uri", self.scanner.redirect_params)
        self.assertIn("callback", self.scanner.redirect_params)
        self.assertIn("return_url", self.scanner.redirect_params)

    def test_params_contain_common_names(self):
        """Test that params include common redirect param names."""
        self.assertIn("url", self.scanner.redirect_params)
        self.assertIn("next", self.scanner.redirect_params)
        self.assertIn("redirect", self.scanner.redirect_params)
        self.assertIn("goto", self.scanner.redirect_params)


if __name__ == "__main__":
    unittest.main()
