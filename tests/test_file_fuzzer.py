import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.file_fuzzer import FileFuzzer
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestFileFuzzer(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_found_sensitive_file(self):
        """Test finding a valid sensitive file (.env)."""
        scanner = FileFuzzer(self.config)
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "DB_PASSWORD=secret"
        
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
            
            # Since we iterate multiple paths, we need side_effect if we want specific behavior per path
            # But for simple success test, if all return 200, we find all.
            results = asyncio.run(scanner.run(target))
            
            self.assertTrue(len(results["found"]) > 0)
            self.assertEqual(results["found"][0]["path"], ".env")

    def test_found_git_head_validation(self):
        """Test .git/HEAD content validation."""
        scanner = FileFuzzer(self.config)
        scanner.paths = [".git/HEAD"] # Limit to just this one for test
        
        # Mock Response (Invalid Content)
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "<html>Not Found</html>"
        
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
            
            # Should be empty because validation failed
            self.assertEqual(results, {})

    def test_found_git_head_success(self):
        """Test .git/HEAD success content."""
        scanner = FileFuzzer(self.config)
        scanner.paths = [".git/HEAD"] 
        
        # Mock Response (Valid Content)
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "ref: refs/heads/main"
        
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
            
            self.assertEqual(len(results["found"]), 1)
            self.assertEqual(results["found"][0]["path"], ".git/HEAD")

    def test_404_ignored(self):
        """Test 404 responses are ignored."""
        scanner = FileFuzzer(self.config)
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.status = 404
        
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
            
            self.assertEqual(results, {})

if __name__ == "__main__":
    unittest.main()
