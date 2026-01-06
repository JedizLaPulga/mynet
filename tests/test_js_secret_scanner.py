import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.js_secret_scanner import JSSecretScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestJSSecretScanner(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_find_google_key(self):
        """Test finding a Google API Key in a JS file."""
        scanner = JSSecretScanner(self.config)
        
        # 1. Mock Main Page Response (contains script tag)
        # 1. Mock Main Page Response (contains script tag)
        mock_main_resp = AsyncMock()
        mock_main_resp.status = 200
        async def main_text(): return '<html><script src="app.js"></script></html>'
        mock_main_resp.text = MagicMock(side_effect=main_text)
        
        # 2. Mock JS File Response (contains secret)
        mock_js_resp = AsyncMock()
        mock_js_resp.status = 200
        async def js_text(): return 'const apiKey = "AIzaSyD-1234567890abcdef1234567890abcde";'
        mock_js_resp.text = MagicMock(side_effect=js_text)

        # Chain logic for fetches:
        # First call -> Main Page
        # Second call -> JS file
        
        # Use a side_effect function for the session.get context manager return values
        # This must be sync because session.get(...) returns a CM immediately, not awaitable
        def get_side_effect(*args, **kwargs):
            url = args[0]
            cm = MagicMock()
            if "app.js" in url:
                cm.__aenter__ = AsyncMock(return_value=mock_js_resp)
            else:
                cm.__aenter__ = AsyncMock(return_value=mock_main_resp)
            cm.__aexit__ = AsyncMock(return_value=None)
            return cm

        # Mock Session
        mock_session = MagicMock()
        mock_session.get.side_effect = get_side_effect
        
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            # Should have found 1 file and 1 secret
            # Note: The scanner implementation fetches the main page separately in _find_js_files using a NEW session
            # and then fetch secrets using another NEW session.
            # My mock patches 'aiohttp.ClientSession' class, so EVERY instance created will use my mock_session_cm.
            # Since I reuse the side_effect logic, it should work for both instances.
            
            self.assertIn("secrets", results)
            self.assertTrue(len(results["secrets"]) > 0)
            self.assertEqual(results["secrets"][0]["type"], "Google API Key")
            self.assertIn("AIza", results["secrets"][0]["value"])

    def test_no_secrets(self):
        """Test finding no secrets."""
        scanner = JSSecretScanner(self.config)
        
        mock_main_resp = AsyncMock()
        mock_main_resp.status = 200
        async def main_text(): return '<html><script src="clean.js"></script></html>'
        mock_main_resp.text = MagicMock(side_effect=main_text)
        
        mock_js_resp = AsyncMock()
        mock_js_resp.status = 200
        async def js_text(): return 'console.log("Hello World");'
        mock_js_resp.text = MagicMock(side_effect=js_text)
        
        # side_effect for session.get
        def get_side_effect(*args, **kwargs):
            # args[0] is url (session.get(url, ...))
            url = args[0]
            
            # Create a dedicated CM for this call
            cm = MagicMock()
            if "clean.js" in url:
                cm.__aenter__ = AsyncMock(return_value=mock_js_resp)
            else:
                cm.__aenter__ = AsyncMock(return_value=mock_main_resp)
            cm.__aexit__ = AsyncMock(return_value=None)
            return cm

        mock_session = MagicMock()
        mock_session.get.side_effect = get_side_effect
        
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            self.assertEqual(results["scanned_files"], 1)
            self.assertEqual(results["secrets"], [])

if __name__ == "__main__":
    unittest.main()
