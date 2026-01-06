import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.takeover_scanner import TakeoverScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestTakeoverScanner(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    @patch("dns.asyncresolver.Resolver.resolve")
    def test_takeover_vulnerable(self, mock_resolve):
        """Test a vulnerable subdomain (e.g. GitHub Pages)."""
        scanner = TakeoverScanner(self.config)

        # 1. Mock DNS
        mock_answer = MagicMock()
        mock_answer.target.__str__ = MagicMock(return_value="username.github.io.") 
        mock_resolve.return_value = [mock_answer]

        # 2. Mock HTTP
        mock_response = AsyncMock()
        mock_response.text.return_value = "There isn't a GitHub Pages site here"
        
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
            target = Target(original_input="sub.example.com", host="sub.example.com")
            results = asyncio.run(scanner.run(target))

            self.assertTrue(results.get("vulnerable", False))
            self.assertEqual(results.get("provider"), "github.io")

    @patch("dns.asyncresolver.Resolver.resolve")
    def test_takeover_safe_content(self, mock_resolve):
        """Test CNAME points to provider, but content is valid (claimed)."""
        scanner = TakeoverScanner(self.config)

        # 1. Mock DNS
        mock_answer = MagicMock()
        mock_answer.target.__str__ = MagicMock(return_value="username.github.io.")
        mock_resolve.return_value = [mock_answer]

        # 2. Mock HTTP (Valid site content)
        mock_response = AsyncMock()
        mock_response.text.return_value = "Welcome to my cool site!"
        
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
            target = Target(original_input="sub.example.com", host="sub.example.com")
            results = asyncio.run(scanner.run(target))

            # Should be empty or vulnerable=False
            self.assertFalse(results.get("vulnerable", False))

    @patch("dns.asyncresolver.Resolver.resolve")
    def test_takeover_no_match(self, mock_resolve):
        """Test CNAME does not match any provider."""
        scanner = TakeoverScanner(self.config)

        # 1. Mock DNS
        mock_answer = MagicMock()
        mock_answer.target.__str__ = MagicMock(return_value="another-domain.com.")
        mock_resolve.return_value = [mock_answer]

        target = Target(original_input="sub.example.com", host="sub.example.com")
        results = asyncio.run(scanner.run(target))

        self.assertEqual(results, {})

if __name__ == "__main__":
    unittest.main()
