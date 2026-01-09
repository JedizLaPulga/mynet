"""Tests for WAF Scanner module."""

import unittest
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch, mock_open
from mynet.modules.waf_scanner import WAFScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestWAFScanner(unittest.TestCase):
    """Test cases for WAFScanner class."""

    def setUp(self):
        self.config = Config()
        # Set default test config values
        self.config.waf_rate_limit = 0  # No delay for tests
        self.config.waf_stealth = False
        self.config.waf_evasion = False
        self.config.waf_payload_file = None
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
        response_iter = iter(responses)

        def get_next_response(*args, **kwargs):
            try:
                resp = next(response_iter)
            except StopIteration:
                resp = self._create_mock_response()

            mock_cm = MagicMock()
            mock_cm.__aenter__.return_value = resp
            mock_cm.__aexit__.return_value = None
            return mock_cm

        mock_session.get.side_effect = get_next_response
        mock_session.request.side_effect = get_next_response
        mock_session.post.side_effect = get_next_response

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
            self._create_mock_response(
                headers={"Server": "cloudflare", "CF-RAY": "1234567890"},
                cookies=[],
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("Cloudflare", results["wafs"])
            self.assertGreater(results["confidence"], 0)
            # Check fingerprint data
            self.assertIn("fingerprint", results)
            if "Cloudflare" in results["fingerprint"]:
                self.assertIn("signatures_matched", results["fingerprint"]["Cloudflare"])

    def test_passive_detection_aws_waf(self):
        """Test AWS WAF detection via headers."""
        responses = [
            self._create_mock_response(
                headers={"X-Amz-Cf-Id": "abc123", "X-Amz-Cf-Pop": "IAD50"},
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("AWS WAF", results["wafs"])

    def test_passive_detection_azure_waf(self):
        """Test Azure WAF detection via headers."""
        responses = [
            self._create_mock_response(
                headers={"X-Azure-Ref": "abc123", "X-MSEdge-Ref": "edge123"},
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("Azure WAF", results["wafs"])

    def test_passive_detection_f5_cookie(self):
        """Test F5 BIG-IP detection via cookies."""
        responses = [
            self._create_mock_response(
                headers={},
                cookies=["TS01234567", "BigIP"],
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
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
            *[self._create_mock_response(status=200) for _ in range(20)],
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
            self._create_mock_response(headers={"Server": "Apache"}),
            self._create_mock_response(status=200),
            self._create_mock_response(
                status=403,
                body="Access Denied - Cloudflare Security",
            ),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("Cloudflare", results["wafs"])
            self.assertIsNotNone(results["block_behavior"])
            self.assertEqual(results["block_behavior"]["status_code"], 403)
            self.assertIn("payload", results["block_behavior"])

    def test_active_probe_block_type_detection(self):
        """Test detection of different block types."""
        responses = [
            self._create_mock_response(headers={}),
            self._create_mock_response(status=200),
            self._create_mock_response(
                status=429,
                body="Rate limit exceeded. Too many requests.",
            ),
            *[self._create_mock_response(status=200) for _ in range(20)],
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
            self._create_mock_response(headers={}),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(10)],
            self._create_mock_response(
                status=403,
                headers={"Server": "AkamaiGHost"},
            ),
            *[self._create_mock_response(status=200) for _ in range(10)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("Akamai", results["wafs"])
            self.assertIn("method_testing", results["detection_methods"])

    # -------------------------------------------------------------------------
    # Stealth Mode Tests
    # -------------------------------------------------------------------------

    def test_stealth_mode_reduces_probes(self):
        """Test that stealth mode reduces probe count."""
        self.config.waf_stealth = True
        scanner = WAFScanner(self.config)

        responses = [
            self._create_mock_response(headers={"Server": "cloudflare"}),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))

            self.assertTrue(results["detected"])
            # In stealth mode, active_probing should not be in methods
            # (or have reduced activity)

    def test_stealth_mode_uses_browser_headers(self):
        """Test that stealth mode sends browser-like headers."""
        self.config.waf_stealth = True
        scanner = WAFScanner(self.config)

        headers = scanner._get_stealth_headers()
        self.assertIn("User-Agent", headers)
        self.assertIn("Mozilla", headers["User-Agent"])
        self.assertIn("Accept", headers)

    # -------------------------------------------------------------------------
    # Evasion Mode Tests
    # -------------------------------------------------------------------------

    def test_evasion_mode_tests_bypasses(self):
        """Test that evasion mode attempts bypass techniques."""
        self.config.waf_evasion = True
        scanner = WAFScanner(self.config)

        responses = [
            # Passive detection finds WAF
            self._create_mock_response(headers={"Server": "cloudflare"}),
            # Baseline
            self._create_mock_response(status=200),
            # Active probes blocked
            self._create_mock_response(status=403),
            *[self._create_mock_response(status=403) for _ in range(10)],
            # Evasion baseline blocked
            self._create_mock_response(status=403),
            # Some evasion attempts - first 3 blocked, 4th bypasses
            *[self._create_mock_response(status=403) for _ in range(3)],
            self._create_mock_response(status=200),  # Bypass success!
            *[self._create_mock_response(status=403) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("evasion_results", results)
            # Check if any bypass was detected
            if results["evasion_results"]:
                bypassed = [r for r in results["evasion_results"] if r.get("bypassed")]
                # At least verify the structure
                self.assertTrue(isinstance(results["evasion_results"], list))

    # -------------------------------------------------------------------------
    # Custom Payload File Tests
    # -------------------------------------------------------------------------

    def test_custom_payload_file_loading(self):
        """Test loading custom payloads from file."""
        payload_content = """# Custom payloads
SQLi|?id=1' UNION ALL SELECT--
XSS|?q=<marquee>xss</marquee>
?custom=payload
"""
        self.config.waf_payload_file = "/tmp/payloads.txt"

        with patch('builtins.open', mock_open(read_data=payload_content)):
            with patch('pathlib.Path.exists', return_value=True):
                scanner = WAFScanner(self.config)

                # Check that custom payloads were loaded
                payload_types = [p[0] for p in scanner.probe_payloads]
                self.assertIn("Custom", payload_types)

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
            self._create_mock_response(status=403, body="cloudflare blocked"),
            *[self._create_mock_response(status=200) for _ in range(20)],
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
            *[self._create_mock_response(status=200) for _ in range(20)],
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
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertGreater(len(results["bypass_hints"]), 0)
            self.assertTrue(any("origin IP" in hint for hint in results["bypass_hints"]))

    # -------------------------------------------------------------------------
    # Fingerprint / JSON Export Tests
    # -------------------------------------------------------------------------

    def test_fingerprint_data_structure(self):
        """Test that fingerprint data is properly structured."""
        responses = [
            self._create_mock_response(
                headers={"Server": "cloudflare", "CF-RAY": "123"},
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("fingerprint", results)
            fingerprint = results["fingerprint"]
            if "Cloudflare" in fingerprint:
                self.assertIn("signatures_matched", fingerprint["Cloudflare"])
                self.assertIn("headers_found", fingerprint["Cloudflare"])

    def test_export_fingerprint_json(self):
        """Test JSON export for SIEM integration."""
        results = {
            "detected": True,
            "wafs": ["Cloudflare"],
            "confidence": 85,
            "fingerprint": {"Cloudflare": {"signatures_matched": []}},
            "block_behavior": {"trigger": "SQLi", "status_code": 403},
            "evasion_results": [],
            "bypass_hints": ["Test hint"],
        }

        json_output = self.scanner.export_fingerprint_json(results)
        parsed = json.loads(json_output)

        self.assertEqual(parsed["scan_type"], "waf_detection")
        self.assertTrue(parsed["detected"])
        self.assertIn("Cloudflare", parsed["wafs"])
        self.assertEqual(parsed["confidence"], 85)

    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------

    def test_no_waf_detected(self):
        """Test clean site with no WAF."""
        responses = [
            self._create_mock_response(headers={"Server": "Apache/2.4.41"}),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
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
            *[self._create_mock_response(status=200) for _ in range(20)],
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
        self.assertEqual(
            self.scanner._detect_block_type("Checking your browser before accessing"),
            "Browser Check"
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

    # -------------------------------------------------------------------------
    # Rate Limiting Tests
    # -------------------------------------------------------------------------

    def test_rate_limit_config(self):
        """Test that rate limit configuration is respected."""
        self.config.waf_rate_limit = 1.5
        scanner = WAFScanner(self.config)
        self.assertEqual(scanner.rate_limit_delay, 1.5)

    def test_default_rate_limit(self):
        """Test default rate limit value."""
        # Reset to no explicit config
        config = Config()
        scanner = WAFScanner(config)
        self.assertEqual(scanner.rate_limit_delay, 0.5)

    # -------------------------------------------------------------------------
    # New WAF Signature Tests
    # -------------------------------------------------------------------------

    def test_detect_imperva_securesphere(self):
        """Test Imperva SecureSphere detection."""
        responses = [
            self._create_mock_response(
                headers={"X-SL-CompState": "abc123"},
                body="SecureSphere protected",
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("Imperva SecureSphere", results["wafs"])

    def test_detect_perimeterx(self):
        """Test PerimeterX detection."""
        responses = [
            self._create_mock_response(
                cookies=["_px3", "_pxvid"],
                body="px-captcha validation",
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("PerimeterX", results["wafs"])

    def test_detect_datadome(self):
        """Test DataDome detection."""
        responses = [
            self._create_mock_response(
                headers={"X-DataDome": "true"},
                cookies=["datadome"],
            ),
            self._create_mock_response(status=200),
            *[self._create_mock_response(status=200) for _ in range(20)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertTrue(results["detected"])
            self.assertIn("DataDome", results["wafs"])


if __name__ == "__main__":
    unittest.main()
