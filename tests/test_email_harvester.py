import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.email_harvester import EmailHarvester
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestEmailHarvester(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_harvest_emails_simple(self):
        """Test finding emails on a single page."""
        scanner = EmailHarvester(self.config)
        
        html_content = """
        <html>
            <body>
                <p>Contact us at support@example.com</p>
                <a href="mailto:sales@example.com">Sales</a>
            </body>
        </html>
        """
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text.return_value = html_content
        
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
            # We must ensure the loop runs long enough or tasks complete
            # The code uses queue.join(), so it should wait.
            results = asyncio.run(scanner.run(target))
            
            self.assertEqual(results["count"], 2)
            self.assertIn("support@example.com", results["emails"])
            self.assertIn("sales@example.com", results["emails"])

    def test_harvest_no_emails(self):
        """Test page with no emails."""
        scanner = EmailHarvester(self.config)
        
        html_content = "<html><body><h1>Hello World</h1></body></html>"
        
        # Mock Response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text.return_value = html_content
        
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
            
            self.assertEqual(results["count"], 0)
            self.assertEqual(results["emails"], [])

if __name__ == "__main__":
    unittest.main()
