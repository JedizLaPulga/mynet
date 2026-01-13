"""Tests for PDF Report Generator."""

import unittest
import tempfile
import os
from mynet.core.config import Config

try:
    from mynet.output.pdf_report import PDFReportGenerator, generate_pdf_report, REPORTLAB_AVAILABLE
except ImportError:
    REPORTLAB_AVAILABLE = False


@unittest.skipIf(not REPORTLAB_AVAILABLE, "reportlab not installed")
class TestPDFReportGenerator(unittest.TestCase):
    """Test cases for PDFReportGenerator class."""

    def setUp(self):
        self.generator = PDFReportGenerator()
        self.sample_results = {
            "example.com": {
                "target": {
                    "host": "example.com",
                    "type": "domain",
                },
                "scans": {
                    "Port Scanner": {
                        "open_ports": [80, 443, 22],
                    },
                    "HTTP Scanner": {
                        "80": {"status": 200, "title": "Example"},
                    },
                    "CORS Scanner": {
                        "vulnerable": True,
                        "vulnerabilities": [
                            {"type": "origin_reflection", "severity": "high", "description": "Origin header is reflected"},
                        ],
                    },
                    "Security Headers": {
                        "score": 45,
                        "missing": ["Content-Security-Policy", "X-Frame-Options"],
                    },
                },
            },
        }

    def test_generator_initialization(self):
        """Test that generator initializes correctly."""
        self.assertIsNotNone(self.generator.styles)
        self.assertIn("primary", self.generator.colors)

    def test_calculate_stats(self):
        """Test statistics calculation."""
        stats = self.generator._calculate_stats(self.sample_results)

        self.assertEqual(stats["total_targets"], 1)
        self.assertGreater(stats["modules_run"], 0)

    def test_extract_all_findings(self):
        """Test finding extraction."""
        findings = self.generator._extract_all_findings(self.sample_results)

        self.assertIsInstance(findings, list)
        # Should have at least the CORS vulnerability
        high_findings = [f for f in findings if f["severity"] == "high"]
        self.assertGreater(len(high_findings), 0)

    def test_extract_module_findings_vulnerabilities(self):
        """Test extraction of vulnerabilities list."""
        module_data = {
            "vulnerabilities": [
                {"type": "test", "severity": "high", "description": "Test vuln"},
            ],
        }
        findings = self.generator._extract_module_findings("Test", module_data)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_extract_module_findings_vulnerable_flag(self):
        """Test extraction with vulnerable flag."""
        module_data = {"vulnerable": True}
        findings = self.generator._extract_module_findings("Test", module_data)

        self.assertGreater(len(findings), 0)

    def test_extract_module_findings_dangerous_methods(self):
        """Test extraction of dangerous methods."""
        module_data = {"dangerous_methods": ["PUT", "DELETE"]}
        findings = self.generator._extract_module_findings("HTTP Method Scanner", module_data)

        self.assertGreater(len(findings), 0)
        self.assertIn("PUT", findings[0]["description"])

    def test_extract_module_findings_low_score(self):
        """Test extraction of low security score."""
        module_data = {"score": 30}
        findings = self.generator._extract_module_findings("Security Headers", module_data)

        self.assertGreater(len(findings), 0)

    def test_generate_pdf_creates_file(self):
        """Test that PDF generation creates a file."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            temp_path = f.name

        try:
            self.generator.generate(self.sample_results, temp_path)
            self.assertTrue(os.path.exists(temp_path))
            self.assertGreater(os.path.getsize(temp_path), 1000)  # Should be non-trivial size
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_generate_pdf_convenience_function(self):
        """Test the convenience function."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            temp_path = f.name

        try:
            generate_pdf_report(self.sample_results, temp_path)
            self.assertTrue(os.path.exists(temp_path))
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_empty_results(self):
        """Test handling of empty results."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            temp_path = f.name

        try:
            self.generator.generate({}, temp_path)
            self.assertTrue(os.path.exists(temp_path))
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_results_with_no_findings(self):
        """Test results with no vulnerabilities."""
        clean_results = {
            "example.com": {
                "target": {"host": "example.com"},
                "scans": {
                    "Port Scanner": {"open_ports": [80]},
                },
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            temp_path = f.name

        try:
            self.generator.generate(clean_results, temp_path)
            self.assertTrue(os.path.exists(temp_path))
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
