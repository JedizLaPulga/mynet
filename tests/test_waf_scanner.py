"""Tests for WAF Scanner module."""

import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.waf_scanner import WAFScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestWAFScanner(unittest.TestCase):
    """Test cases for WAFScanner class."""

    def setUp(self):
        self.config = Config()
        self.scanner = WAFScanner(self.config)

    def _create_mock_response(self, headers=None, cookies=None, status=200, body=""):
        """Helper to create a mock aiohttp response."""
        mock_response = AsyncMock()
        mock_response.headers = headers or {}
        mock_response.cookies = cookies or []
        mock_response.status = status
        mock_response.text = AsyncMock(return_value=body)
        return mock_response

    def _create_mock_session(self, responses):
        """
        Helper to create a mock session that returns different responses.
        responses: list of mock responses to return in order.
        """
        mock_session = MagicMock()
        
        # Create context managers for each response
        response_iter = iter(responses)
        
        def get_next_response(*args, **kwargs):
            try:
                resp = next(response_iter)
            except StopIteration:
                # Return a basic response if we run out
                resp = self._create_mock_response()
            
            mock_cm = MagicMock()
            mock_cm.__aenter__.return_value = resp
            mock_cm.__aexit__.return_value = None
            return mock_cm
        
        mock_session.get.side_effect = get_next_response
        mock_session.request.side_effect = get_next_response
        
        return mock_session

    def _patch_session(self, mock_session):
        """Create patched ClientSession context manager."""
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        return mock_session_cm

    # -------------------------------------------------------------------------
    # Passive Detection Tests
    # -------------------------------------------------------------------------
    
    def test_passive_detection_cloudflare_headers(self):
        """Test Cloudflare detection via headers."""
        responses = [
            # Passive detection response
            self._create_mock_response(
                headers={"Server": "cloudflare", "CF-RAY": "1234567890"},
                cookies=[],
            ),
            # Baseline for active probe
            self._create_mock_response(status=200),
            # Active probe responses (5 probes)
            *[self._create_mock_response(status=200) for _ in range(5)],
            # Multi-method responses (4 methods)
            *[self._create_mock_response(status=200) for _ in range(4)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("Cloudflare", results["wafs"])
            self.assertGreater(results["confidence"], 0)

    def test_passive_detection_aws_waf(self):
        """Test AWS WAF detection via headers."""
        responses = [
            self._create_mock_response(
                headers={"X-Amz-Cf-Id": "abc123", "X-Amz-Cf-Pop": "IAD50"},
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("AWS WAF", results["wafs"])

    def test_passive_detection_f5_cookie(self):
        """Test F5 BIG-IP detection via cookies."""
        responses = [
            self._create_mock_response(
                headers={},
                cookies=["TS01234567", "BigIP"],
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("F5 BIG-IP", results["wafs"])

    def test_passive_detection_body_signature(self):
        """Test WAF detection via response body."""
        responses = [
            self._create_mock_response(
                headers={},
                body="Protected by Cloudflare. Ray ID: 123456",
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("Cloudflare", results["wafs"])

    # -------------------------------------------------------------------------
    # Active Probing Tests
    # -------------------------------------------------------------------------

    def test_active_probe_detects_block(self):
        """Test that active probing detects WAF via block response."""
        responses = [
            # Passive detection (clean)
            self._create_mock_response(headers={"Server": "Apache"}),
            # Baseline
            self._create_mock_response(status=200),
            # Active probe triggers WAF (403 with block message)
            self._create_mock_response(
                status=403,
                body="Access Denied - Cloudflare Security",
            ),
            *[self._create_mock_response(status=200) for _ in range(8)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("Cloudflare", results["wafs"])
            self.assertIsNotNone(results["block_behavior"])
            self.assertEqual(results["block_behavior"]["status_code"], 403)

    def test_active_probe_block_type_detection(self):
        """Test detection of different block types."""
        responses = [
            self._create_mock_response(headers={}),
            self._create_mock_response(status=200),
            self._create_mock_response(
                status=429,
                body="Rate limit exceeded. Too many requests.",
            ),
            *[self._create_mock_response(status=200) for _ in range(8)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            if results.get("block_behavior"):
                self.assertEqual(results["block_behavior"]["block_type"], "Rate Limited")

    # -------------------------------------------------------------------------
    # Multi-Method Tests
    # -------------------------------------------------------------------------

    def test_multi_method_detects_waf(self):
        """Test that different HTTP methods can detect WAF."""
        responses = [
            # Passive (clean)
            self._create_mock_response(headers={}),
            # Baseline
            self._create_mock_response(status=200),
            # Active probes (clean)
            *[self._create_mock_response(status=200) for _ in range(5)],
            # Multi-method: POST returns 403 with Akamai header
            self._create_mock_response(
                status=403,
                headers={"Server": "AkamaiGHost"},
            ),
            *[self._create_mock_response(status=200) for _ in range(3)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("Akamai", results["wafs"])
            self.assertIn("method_testing", results["detection_methods"])

    # -------------------------------------------------------------------------
    # Confidence Score Tests
    # -------------------------------------------------------------------------

    def test_confidence_score_high(self):
        """Test high confidence when multiple signatures match."""
        responses = [
            self._create_mock_response(
                headers={
                    "Server": "cloudflare",
                    "CF-RAY": "123",
                    "cf-cache-status": "HIT",
                },
                cookies=["__cfduid"],
                body="cloudflare",
            ),
            self._create_mock_response(status=200),
            # Active probe triggers block
            self._create_mock_response(status=403, body="cloudflare blocked"),
            *[self._create_mock_response(status=200) for _ in range(8)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertGreaterEqual(results["confidence"], 50)

    def test_confidence_score_low(self):
        """Test low confidence with single signature match."""
        responses = [
            self._create_mock_response(headers={"X-Varnish": "123"}),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("Varnish", results["wafs"])
            self.assertLess(results["confidence"], 50)

    # -------------------------------------------------------------------------
    # Bypass Hints Tests
    # -------------------------------------------------------------------------

    def test_bypass_hints_provided(self):
        """Test that bypass hints are provided for known WAFs."""
        responses = [
            self._create_mock_response(
                headers={"Server": "cloudflare", "CF-RAY": "123"},
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertGreater(len(results["bypass_hints"]), 0)
            self.assertTrue(any("origin IP" in hint for hint in results["bypass_hints"]))

    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------

    def test_no_waf_detected(self):
        """Test clean site with no WAF."""
        responses = [
            self._create_mock_response(headers={"Server": "Apache/2.4.41"}),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            self.assertFalse(results["detected"])
            self.assertEqual(results["wafs"], [])
            self.assertEqual(results["confidence"], 0)
            self.assertEqual(results["bypass_hints"], [])

    def test_url_target(self):
        """Test with URL target instead of host."""
        responses = [
            self._create_mock_response(headers={"Server": "cloudflare"}),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(9)],
        ]
        mock_session = self._create_mock_session(responses)
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(
                original_input="https://example.com/path",
                host="example.com",
                url="https://example.com/path",
            )
            results = asyncio.run(self.scanner.run(target))
            
            self.assertTrue(results["detected"])

    def test_empty_target(self):
        """Test with target that has no URL or host that resolves to no URL."""
        target = Target(original_input="", host="")
        results = asyncio.run(self.scanner.run(target))
        
        self.assertEqual(results, {})

    def test_connection_error_handling(self):
        """Test graceful handling of connection errors."""
        import aiohttp
        
        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__.side_effect = aiohttp.ClientError("Connection failed")
        mock_session.get.return_value = mock_cm
        mock_session.request.return_value = mock_cm
        
        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))
            
            # When all requests fail, the results should still be valid
            # The error is caught internally, wafs will be empty
            self.assertFalse(results["detected"])
            self.assertEqual(results["wafs"], [])

    # -------------------------------------------------------------------------
    # Unit Tests for Helper Methods
    # -------------------------------------------------------------------------

    def test_check_signature_headers(self):
        """Test _check_signature for header location."""
        result = self.scanner._check_signature(
            location="headers",
            pattern=r"CF-RAY",
            headers={"CF-RAY": "123", "Content-Type": "text/html"},
            cookies=[],
            server="",
            body="",
        )
        self.assertTrue(result)

    def test_check_signature_server(self):
        """Test _check_signature for server location."""
        result = self.scanner._check_signature(
            location="server",
            pattern=r"cloudflare",
            headers={},
            cookies=[],
            server="cloudflare",
            body="",
        )
        self.assertTrue(result)

    def test_check_signature_cookie(self):
        """Test _check_signature for cookie location."""
        result = self.scanner._check_signature(
            location="cookie",
            pattern=r"incap_ses",
            headers={},
            cookies=["incap_ses_123", "other_cookie"],
            server="",
            body="",
        )
        self.assertTrue(result)

    def test_check_signature_body(self):
        """Test _check_signature for body location."""
        result = self.scanner._check_signature(
            location="body",
            pattern=r"wordfence",
            headers={},
            cookies=[],
            server="",
            body="Protected by Wordfence Security",
        )
        self.assertTrue(result)

    def test_detect_block_type(self):
        """Test _detect_block_type method."""
        self.assertEqual(
            self.scanner._detect_block_type("Access Denied - You are blocked"),
            "Access Denied"
        )
        self.assertEqual(
            self.scanner._detect_block_type("Too many requests, please slow down"),
            "Rate Limited"
        )
        self.assertEqual(
            self.scanner._detect_block_type("Please complete the captcha"),
            "Captcha Challenge"
        )
        self.assertIsNone(self.scanner._detect_block_type("Normal page content"))

    def test_calculate_confidence(self):
        """Test confidence score calculation."""
        # Low: 1 passive match only
        self.assertEqual(self.scanner._calculate_confidence(1, False, False), 20)
        
        # Medium: 2 passive matches + active
        self.assertEqual(self.scanner._calculate_confidence(2, True, False), 65)
        
        # High: 3+ passive + active + method
        self.assertEqual(self.scanner._calculate_confidence(3, True, True), 100)

    def test_get_url_with_host(self):
        """Test _get_url with host target."""
        target = Target(original_input="example.com", host="example.com")
        self.assertEqual(self.scanner._get_url(target), "http://example.com")

    def test_get_url_with_url(self):
        """Test _get_url with URL target."""
        target = Target(original_input="https://example.com", host="example.com", url="https://example.com")
        self.assertEqual(self.scanner._get_url(target), "https://example.com")


if __name__ == "__main__":
    unittest.main()
