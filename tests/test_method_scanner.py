"""Tests for HTTP Method Scanner module."""

import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.method_scanner import HTTPMethodScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestHTTPMethodScanner(unittest.TestCase):
    """Test cases for HTTPMethodScanner class."""

    def setUp(self):
        self.config = Config()
        self.config.timeout = 5
        self.scanner = HTTPMethodScanner(self.config)

    def _create_mock_response(self, status=200, headers=None, body=""):
        """Helper to create a mock aiohttp response."""
        mock_response = AsyncMock()
        mock_response.status = status
        mock_response.headers = headers or {}
        mock_response.text = AsyncMock(return_value=body)
        return mock_response

    def _create_mock_session(self, responses_map):
        """
        Helper to create a mock session.
        responses_map: dict mapping method names to responses
        """
        mock_session = MagicMock()

        def create_response_cm(method, *args, **kwargs):
            if method.upper() in responses_map:
                resp = responses_map[method.upper()]
            else:
                resp = self._create_mock_response(status=405)

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=resp)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            return mock_cm

        mock_session.request = MagicMock(side_effect=lambda m, *a, **k: create_response_cm(m, *a, **k))
        mock_session.options = MagicMock(side_effect=lambda *a, **k: create_response_cm("OPTIONS", *a, **k))

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
        self.assertEqual(self.scanner.name, "HTTP Method Scanner")
        self.assertIn("GET", self.scanner.standard_methods)
        self.assertIn("PUT", self.scanner.standard_methods)
        self.assertIn("TRACE", self.scanner.standard_methods)
        self.assertIn("PROPFIND", self.scanner.webdav_methods)

    def test_risk_classifications(self):
        """Test that risk methods are classified correctly."""
        self.assertIn("PUT", self.scanner.high_risk_methods)
        self.assertIn("DELETE", self.scanner.high_risk_methods)
        self.assertIn("TRACE", self.scanner.high_risk_methods)
        self.assertIn("PROPFIND", self.scanner.medium_risk_methods)

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
    # OPTIONS Request Tests
    # -------------------------------------------------------------------------

    def test_options_parses_allow_header(self):
        """Test that OPTIONS response Allow header is parsed."""
        responses = {
            "OPTIONS": self._create_mock_response(
                status=200,
                headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"}
            ),
            "GET": self._create_mock_response(status=200),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("PUT", results["allowed_methods"])
            self.assertIn("DELETE", results["allowed_methods"])

    def test_options_parses_cors_methods(self):
        """Test that CORS Access-Control-Allow-Methods is parsed."""
        responses = {
            "OPTIONS": self._create_mock_response(
                status=200,
                headers={"Access-Control-Allow-Methods": "GET, POST, PUT"}
            ),
            "GET": self._create_mock_response(status=200),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("PUT", results["allowed_methods"])

    # -------------------------------------------------------------------------
    # Vulnerability Detection Tests
    # -------------------------------------------------------------------------

    def test_trace_xst_vulnerability(self):
        """Test TRACE XST vulnerability detection."""
        responses = {
            "OPTIONS": self._create_mock_response(status=200),
            "GET": self._create_mock_response(status=200),
            "TRACE": self._create_mock_response(
                status=200,
                body="TRACE / HTTP/1.1\nX-Custom-Header: TraceTest"
            ),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            vulns = results.get("vulnerabilities", [])
            xst_vulns = [v for v in vulns if v.get("type") == "XST"]
            self.assertGreater(len(xst_vulns), 0)
            self.assertEqual(xst_vulns[0]["severity"], "high")

    def test_put_enabled_vulnerability(self):
        """Test PUT method vulnerability detection."""
        responses = {
            "OPTIONS": self._create_mock_response(status=200),
            "GET": self._create_mock_response(status=200),
            "PUT": self._create_mock_response(status=201),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            vulns = results.get("vulnerabilities", [])
            put_vulns = [v for v in vulns if v.get("type") == "PUT_ENABLED"]
            self.assertGreater(len(put_vulns), 0)

    def test_delete_enabled_vulnerability(self):
        """Test DELETE method vulnerability detection."""
        responses = {
            "OPTIONS": self._create_mock_response(status=200),
            "GET": self._create_mock_response(status=200),
            "DELETE": self._create_mock_response(status=200),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            vulns = results.get("vulnerabilities", [])
            del_vulns = [v for v in vulns if v.get("type") == "DELETE_ENABLED"]
            self.assertGreater(len(del_vulns), 0)

    def test_webdav_detection(self):
        """Test WebDAV detection via PROPFIND."""
        responses = {
            "OPTIONS": self._create_mock_response(status=200),
            "GET": self._create_mock_response(status=200),
            "PROPFIND": self._create_mock_response(
                status=207,
                body="<d:multistatus><d:response></d:response></d:multistatus>"
            ),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results.get("webdav_enabled"))
            vulns = results.get("vulnerabilities", [])
            webdav_vulns = [v for v in vulns if v.get("type") == "WEBDAV_ENABLED"]
            self.assertGreater(len(webdav_vulns), 0)

    # -------------------------------------------------------------------------
    # Safe Server Tests
    # -------------------------------------------------------------------------

    def test_safe_server_no_vulnerabilities(self):
        """Test that a properly configured server has no vulnerabilities."""
        # All dangerous methods return 405
        responses = {
            "OPTIONS": self._create_mock_response(
                status=200,
                headers={"Allow": "GET, HEAD, POST, OPTIONS"}
            ),
            "GET": self._create_mock_response(status=200),
            "HEAD": self._create_mock_response(status=200),
            "POST": self._create_mock_response(status=200),
            # Dangerous methods blocked
            "PUT": self._create_mock_response(status=405),
            "DELETE": self._create_mock_response(status=405),
            "TRACE": self._create_mock_response(status=405),
            "PROPFIND": self._create_mock_response(status=405),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            vulns = results.get("vulnerabilities", [])
            self.assertEqual(len(vulns), 0)

    # -------------------------------------------------------------------------
    # Dangerous Methods Detection Tests
    # -------------------------------------------------------------------------

    def test_dangerous_methods_detected(self):
        """Test that dangerous methods are flagged."""
        responses = {
            "OPTIONS": self._create_mock_response(status=200),
            "GET": self._create_mock_response(status=200),
            "PUT": self._create_mock_response(status=200),
            "DELETE": self._create_mock_response(status=200),
            "TRACE": self._create_mock_response(status=200),
        }
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            dangerous = results.get("dangerous_methods", [])
            self.assertIn("PUT", dangerous)
            self.assertIn("DELETE", dangerous)
            self.assertIn("TRACE", dangerous)

    # -------------------------------------------------------------------------
    # Error Handling Tests
    # -------------------------------------------------------------------------

    def test_connection_error_handling(self):
        """Test graceful handling of connection errors."""
        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=Exception("Connection failed"))
        mock_session.options = MagicMock(return_value=mock_cm)
        mock_session.request = MagicMock(return_value=mock_cm)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            # Should handle errors gracefully
            # May have error in results or just empty data

    def test_timeout_handling(self):
        """Test handling of timeout errors."""
        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_session.options = MagicMock(return_value=mock_cm)
        mock_session.request = MagicMock(return_value=mock_cm)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="http://example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            # Should not crash


if __name__ == "__main__":
    unittest.main()
