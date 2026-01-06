import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.wayback_scanner import WaybackScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestWaybackScanner(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.scanner = WaybackScanner(self.config)

    def test_run_success(self):
        """Test finding URLs and params."""
        mock_resp = AsyncMock()
        mock_resp.status = 200
        # CDX API returns list of lists. First row is header.
        mock_resp.json = AsyncMock(return_value=[
            ["original", "mimetype", "statuscode"],
            ["http://example.com/index.php?id=1", "text/html", "200"],
            ["http://example.com/admin/login", "text/html", "200"],
            ["http://example.com/style.css", "text/css", "200"], # Should be filtered
            ["http://example.com/api/v1/user?token=abc", "application/json", "200"]
        ])
        
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
            results = asyncio.run(self.scanner.run(target))
            
            self.assertIn("urls", results)
            self.assertEqual(len(results["urls"]), 3) # index.php, admin/login, api (css filtered)
            self.assertEqual(results["total_found"], 3)
            
            # Check filtering
            self.assertFalse(any("style.css" in u for u in results["urls"]))
            
            # Check params
            self.assertIn("interesting_params", results)
            self.assertIn("id", results["interesting_params"])
            self.assertIn("token", results["interesting_params"])

    def test_run_error(self):
        """Test handling API error."""
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("API Down")

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
             target = Target(original_input="example.com", host="example.com")
             results = asyncio.run(self.scanner.run(target))
             
             self.assertIn("error", results)
             self.assertEqual(results["urls"], [])

if __name__ == "__main__":
    unittest.main()
