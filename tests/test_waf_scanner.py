import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.waf_scanner import WAFScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestWAFScanner(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_waf_detection_headers(self):
        """Test detection via headers (Cloudflare)."""
        scanner = WAFScanner(self.config)
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.headers = {
            "Server": "cloudflare",
            "CF-RAY": "1234567890"
        }
        mock_response.cookies = []
        
        # Mock Session
        mock_session = MagicMock()
        # session.get() returns a context manager, whose __aenter__ returns the response
        mock_get_cm = MagicMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = None
        mock_session.get.return_value = mock_get_cm
        
        # Mock ClientSession() returning the session context manager
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("Cloudflare", results["wafs"])

    def test_waf_detection_cookie(self):
        """Test detection via cookies (F5)."""
        scanner = WAFScanner(self.config)
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = ["TS01234567"] # F5 pattern
        
        # Mock Session
        mock_session = MagicMock()
        mock_get_cm = MagicMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = None
        mock_session.get.return_value = mock_get_cm
        
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            self.assertTrue(results["detected"])
            self.assertIn("F5 BIG-IP", results["wafs"])

    def test_no_waf(self):
        """Test clean site."""
        scanner = WAFScanner(self.config)
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.headers = {"Server": "Apache"}
        mock_response.cookies = []
        
        # Mock Session
        mock_session = MagicMock()
        mock_get_cm = MagicMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = None
        mock_session.get.return_value = mock_get_cm
        
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            self.assertFalse(results["detected"])
            self.assertEqual(results["wafs"], [])

if __name__ == "__main__":
    unittest.main()
