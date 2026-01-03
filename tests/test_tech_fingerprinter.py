import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.tech_fingerprinter import TechFingerprinter
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestTechFingerprinter(unittest.TestCase):
    def setUp(self):
        self.config = Config(timeout=1)
        self.module = TechFingerprinter(self.config)

    def test_analyze_headers(self):
        """Test that headers are correctly parsed for technology signatures."""
        
        # Mock response object
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
            "Set-Cookie": "JSESSIONID=12345; Path=/"
        }
        mock_response.text.return_value = "<html><body><h1>Hello</h1></body></html>"

        # We need to mock the session context manager structure
        # session.get() returns a context manager that yields the response
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response

        # Run the internal analyze method
        # We wrap it in asyncio.run since it is async
        results = asyncio.run(self.module._analyze_url(mock_session, "http://example.com"))

        # Verify results
        tech_names = [t['name'] for t in results]
        self.assertIn("Nginx", tech_names)
        self.assertIn("PHP", tech_names)
        self.assertIn("Java/Servlet", tech_names)

        # Check versions
        nginx = next(t for t in results if t['name'] == "Nginx")
        self.assertEqual(nginx['version'], "1.18.0")
        
        php = next(t for t in results if t['name'] == "PHP")
        self.assertEqual(php['version'], "7.4.3")

    def test_analyze_meta_and_scripts(self):
        """Test that HTML body (meta tags and scripts) are parsed correctly."""
        
        html_content = """
        <html>
        <head>
            <meta name="generator" content="WordPress 5.8" />
            <meta name="viewport" content="width=device-width" />
        </head>
        <body>
            <script src="/js/jquery-3.6.0.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
        </body>
        </html>
        """

        mock_response = AsyncMock()
        mock_response.status = 200
        # Empty headers of interest
        mock_response.headers = {"Server": "Unknown"}
        mock_response.text.return_value = html_content

        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response

        results = asyncio.run(self.module._analyze_url(mock_session, "http://example.com"))

        tech_names = [t['name'] for t in results]
        self.assertIn("WordPress", tech_names)
        self.assertIn("jQuery", tech_names)
        self.assertIn("Vue.js", tech_names)
        self.assertIn("Responsive Design", tech_names)

        # Check ver
        wp = next(t for t in results if t['name'] == "WordPress")
        self.assertEqual(wp['version'], "5.8")

        jq = next(t for t in results if t['name'] == "jQuery")
        self.assertEqual(jq['version'], "3.6.0")
    
    def test_run_full_flow(self):
        """Test the run() entry point."""
        target = Target(original_input="example.com", host="example.com", type="domain")
        
        # We need to patch aiohttp.ClientSession within the module
        with patch("aiohttp.ClientSession") as MockSession:
            # Setup the mock session instance
            mock_session_instance = MockSession.return_value
            mock_session_instance.__aenter__.return_value = mock_session_instance
            
            # Setup response for http://example.com
            mock_resp = AsyncMock()
            mock_resp.headers = {"Server": "Apache/2.4.50"}
            mock_resp.text.return_value = ""
            
            # Make get return this response
            mock_session_instance.get.return_value.__aenter__.return_value = mock_resp
            
            # Run
            results = asyncio.run(self.module.run(target))
            
            # Should have results for http and https keys (logic tries both)
            # Since our mock returns the same for all calls, we expect Apache on both
            self.assertIn("http://example.com", results)
            self.assertIn("https://example.com", results)
            
            techs = results["http://example.com"]
            self.assertEqual(techs[0]['name'], "Apache HTTP Server")

if __name__ == "__main__":
    unittest.main()
