import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.traceroute_scanner import TracerouteScanner
from mynet.modules.zone_transfer_scanner import ZoneTransferScanner
from mynet.modules.vuln_scanner import VulnScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestNewFeatures(unittest.TestCase):
    def setUp(self):
        self.config = Config(timeout=1)

    # --- 1. Traceroute Tests ---
    def test_traceroute_parse_windows(self):
        """Test parsing of Windows tracert output."""
        scanner = TracerouteScanner(self.config)
        output = """
        Tracing route to example.com [93.184.216.34]
        over a maximum of 30 hops:

          1    <1 ms    <1 ms    <1 ms  192.168.1.1 
          2    10 ms    12 ms    11 ms  10.0.0.1 
          3     *        *        *     Request timed out.
        """
        hops = scanner._parse_output(output, is_windows=True)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0]['ip'], "192.168.1.1")
        self.assertEqual(hops[0]['rtt'], "<1 ms")
        self.assertEqual(hops[2]['ip'], "*")

    def test_traceroute_parse_linux(self):
        """Test parsing of Linux traceroute output."""
        scanner = TracerouteScanner(self.config)
        output = """
        traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
         1  192.168.1.1 (192.168.1.1)  0.123 ms  0.100 ms  0.090 ms
         2  10.0.0.1 (10.0.0.1)  10.5 ms  10.2 ms  10.1 ms
        """
        hops = scanner._parse_output(output, is_windows=False)
        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0]['ip'], "192.168.1.1")
        # Our regex logic extracts last ms value roughly
        self.assertIn("0.090 ms", hops[0]['rtt']) 

    # --- 2. Zone Transfer Tests ---
    @patch("dns.asyncresolver.Resolver.resolve")
    def test_zone_transfer_no_ns(self, mock_resolve):
        """Test graceful failure when no NS records found."""
        scanner = ZoneTransferScanner(self.config)
        
        # Mock resolve raising exception
        mock_resolve.side_effect = Exception("No NS")
        
        target = Target(original_input="example.com", host="example.com", type="domain")
        results = asyncio.run(scanner.run(target))
        
        self.assertIn("error", results)
        self.assertEqual(results["error"], "Could not detect nameservers")

    # --- 3. Vuln Scanner Tests ---
    def test_vuln_scanner_cve_lookup(self):
        """Test CVE API lookup logic."""
        scanner = VulnScanner(self.config)
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = [
            {"id": "CVE-2021-1234", "cvss": 9.8, "summary": "Critical RCE"},
            {"id": "CVE-2021-5678", "cvss": 5.0, "summary": "Medium XSS"}
        ]
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        cves = asyncio.run(scanner._lookup_cve_circl(mock_session, "apache", "2.4.49"))
        
        self.assertEqual(len(cves), 2)
        self.assertEqual(cves[0]['id'], "CVE-2021-1234")
        
if __name__ == "__main__":
    unittest.main()
