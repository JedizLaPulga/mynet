import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.crtsh_scanner import CrtShScanner
from mynet.modules.robot_scanner import RobotScanner
from mynet.modules.cloud_enum import CloudEnumScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestNewModules(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_crtsh_success(self):
        scanner = CrtShScanner(self.config)
        # Mock crt.sh JSON response
        mock_data = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com\nsub3.example.com"}, # Multiline
            {"name_value": "*.wildcard.example.com"} # Should be ignored
        ]
        
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.json = AsyncMock(return_value=mock_data)
        
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
            
            subs = results.get("subdomains", [])
            self.assertIn("sub1.example.com", subs)
            self.assertIn("sub2.example.com", subs)
            self.assertIn("sub3.example.com", subs)
            self.assertFalse(any("*" in s for s in subs))

    def test_robot_scanner(self):
        scanner = RobotScanner(self.config)
        
        # We need to mock separate calls for robots.txt and sitemap.xml
        mock_robots = AsyncMock()
        mock_robots.status = 200
        mock_robots.text = AsyncMock(return_value="User-agent: *\nDisallow: /admin\nDisallow: /config")
        
        mock_sitemap = AsyncMock()
        mock_sitemap.status = 200
        mock_sitemap.text = AsyncMock(return_value="<url><loc>http://example.com/page1</loc></url>")
        
        def get_side_effect(*args, **kwargs):
            url = args[0]
            cm = MagicMock()
            if "robots.txt" in url:
                cm.__aenter__ = AsyncMock(return_value=mock_robots)
            elif "sitemap.xml" in url:
                cm.__aenter__ = AsyncMock(return_value=mock_sitemap)
            else:
                 cm.__aenter__ = AsyncMock(return_value=AsyncMock(status=404))
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
            
            self.assertTrue(results["robots_found"])
            self.assertIn("disallowed_paths", results)
            self.assertIn("/admin", results["disallowed_paths"])
            self.assertTrue(results["sitemap_found"])
            self.assertEqual(results["sitemap_count"], 1)

    def test_cloud_enum(self):
        scanner = CloudEnumScanner(self.config)
        # Mock HEAD requests
        # We expect calls to http://{host}-{perm}.s3...
        
        def head_side_effect(*args, **kwargs):
            url = args[0]
            cm = MagicMock()
            mock_head = AsyncMock()
            if "example-backup" in url:
                mock_head.status = 200 # Found public
            elif "example-dev" in url:
                mock_head.status = 403 # Found protected
            else:
                mock_head.status = 404 # Not found
            
            cm.__aenter__ = AsyncMock(return_value=mock_head)
            cm.__aexit__ = AsyncMock(return_value=None)
            return cm

        mock_session = MagicMock()
        mock_session.head.side_effect = head_side_effect
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        
        # We need to ensure Semaphore is mocked or real? 
        # Real semaphore works fine in asyncio.run
        
        with patch('aiohttp.ClientSession', return_value=mock_session_cm):
            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(scanner.run(target))
            
            buckets = results.get("aws_buckets", [])
            found_names = [b["name"] for b in buckets]
            
            self.assertIn("example-backup", found_names)
            self.assertIn("example-dev", found_names)
            
            # Verify status
            for b in buckets:
                if b["name"] == "example-backup":
                    self.assertIn("Public", b["status"])
                if b["name"] == "example-dev":
                    self.assertIn("Protected", b["status"])

if __name__ == "__main__":
    unittest.main()
