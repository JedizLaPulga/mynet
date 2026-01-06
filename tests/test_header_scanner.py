import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.header_scanner import HeaderScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestHeaderScanner(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_perfect_score(self):
        """Test with all security headers present."""
        scanner = HeaderScanner(self.config)
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()"
        }
        
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = headers
        
        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_cm

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            self.assertEqual(results["score"], 100)
            self.assertEqual(len(results["missing"]), 0)
            self.assertEqual(len(results["present"]), 6)

    def test_poor_score(self):
        """Test with no security headers."""
        scanner = HeaderScanner(self.config)
        
        headers = {
            "Server": "Apache"
        }
        
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = headers
        
        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_session.get.return_value = mock_cm

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            # 2 High (40) + 1 Medium (10) + 3 Low (15) = 65 penalty
            # Score = 100 - 65 = 35
            self.assertEqual(results["score"], 35) 
            self.assertEqual(len(results["missing"]), 6)

if __name__ == "__main__":
    unittest.main()
