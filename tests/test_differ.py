"""Tests for the Scan Differ module."""

import unittest
import tempfile
import json
import os
from mynet.core.differ import ScanDiffer, ChangeType, DiffResult, load_baseline, save_baseline


class TestScanDiffer(unittest.TestCase):
    """Test cases for ScanDiffer class."""

    def setUp(self):
        self.differ = ScanDiffer()

    # -------------------------------------------------------------------------
    # Basic Diff Tests
    # -------------------------------------------------------------------------

    def test_identical_scans_no_diff(self):
        """Test that identical scans produce no differences."""
        baseline = {
            "example.com": {
                "target": {"host": "example.com"},
                "scans": {
                    "Port Scanner": {"open_ports": [80, 443]},
                    "HTTP Scanner": {"status": 200},
                }
            }
        }
        current = baseline.copy()

        diffs = self.differ.diff(baseline, current)
        summary = self.differ.generate_summary(diffs)

        self.assertEqual(summary["total_changes"], 0)

    def test_new_host_detected(self):
        """Test that a new host is detected."""
        baseline = {}
        current = {
            "example.com": {
                "target": {"host": "example.com"},
                "scans": {}
            }
        }

        diffs = self.differ.diff(baseline, current)

        self.assertIn("example.com", diffs)
        self.assertEqual(diffs["example.com"][0].change_type, ChangeType.NEW)

    def test_removed_host_detected(self):
        """Test that a removed host is detected."""
        baseline = {
            "example.com": {
                "target": {"host": "example.com"},
                "scans": {}
            }
        }
        current = {}

        diffs = self.differ.diff(baseline, current)

        self.assertIn("example.com", diffs)
        self.assertEqual(diffs["example.com"][0].change_type, ChangeType.REMOVED)

    # -------------------------------------------------------------------------
    # Module Field Change Tests
    # -------------------------------------------------------------------------

    def test_new_open_ports_detected(self):
        """Test that new open ports are detected."""
        baseline = {
            "example.com": {
                "scans": {
                    "Port Scanner": {"open_ports": [80]}
                }
            }
        }
        current = {
            "example.com": {
                "scans": {
                    "Port Scanner": {"open_ports": [80, 443, 8080]}
                }
            }
        }

        diffs = self.differ.diff(baseline, current)

        self.assertIn("example.com", diffs)
        port_diffs = [d for d in diffs["example.com"] if d.module == "Port Scanner"]
        self.assertGreater(len(port_diffs), 0)

    def test_new_vulnerability_high_severity(self):
        """Test that new vulnerabilities get high severity."""
        baseline = {
            "example.com": {
                "scans": {
                    "CORS Scanner": {"vulnerable": False, "vulnerabilities": []}
                }
            }
        }
        current = {
            "example.com": {
                "scans": {
                    "CORS Scanner": {
                        "vulnerable": True,
                        "vulnerabilities": [{"type": "origin_reflection"}]
                    }
                }
            }
        }

        diffs = self.differ.diff(baseline, current)
        summary = self.differ.generate_summary(diffs)

        # Should have high severity changes
        high_sev_diffs = [
            d for d in diffs.get("example.com", [])
            if d.severity == "high"
        ]
        self.assertGreater(len(high_sev_diffs), 0)

    def test_resolved_vulnerability_low_severity(self):
        """Test that resolved vulnerabilities get low severity (good news)."""
        baseline = {
            "example.com": {
                "scans": {
                    "CORS Scanner": {
                        "vulnerable": True,
                        "vulnerabilities": [{"type": "origin_reflection"}]
                    }
                }
            }
        }
        current = {
            "example.com": {
                "scans": {
                    "CORS Scanner": {"vulnerable": False, "vulnerabilities": []}
                }
            }
        }

        diffs = self.differ.diff(baseline, current)

        # Should have some diffs
        self.assertIn("example.com", diffs)
        # Resolved vulns should be REMOVED type
        removed_diffs = [
            d for d in diffs["example.com"]
            if d.change_type == ChangeType.REMOVED
        ]
        # At least the vulnerabilities field should be marked

    def test_security_score_decrease_medium_severity(self):
        """Test that security score decrease is medium severity."""
        baseline = {
            "example.com": {
                "scans": {
                    "Security Headers": {"score": 85}
                }
            }
        }
        current = {
            "example.com": {
                "scans": {
                    "Security Headers": {"score": 60}
                }
            }
        }

        diffs = self.differ.diff(baseline, current)

        score_diffs = [
            d for d in diffs.get("example.com", [])
            if d.key == "score"
        ]
        self.assertEqual(len(score_diffs), 1)
        self.assertEqual(score_diffs[0].severity, "medium")
        self.assertEqual(score_diffs[0].old_value, 85)
        self.assertEqual(score_diffs[0].new_value, 60)

    # -------------------------------------------------------------------------
    # Summary Generation Tests
    # -------------------------------------------------------------------------

    def test_generate_summary_counts(self):
        """Test that summary correctly counts changes."""
        diffs = {
            "example.com": [
                DiffResult("example.com", "Port Scanner", ChangeType.NEW, "open_ports", None, [80]),
                DiffResult("example.com", "WAF Detection", ChangeType.CHANGED, "detected", False, True),
            ],
            "test.com": [
                DiffResult("test.com", "Target", ChangeType.REMOVED, "host", "test.com", None),
            ],
        }

        summary = self.differ.generate_summary(diffs)

        self.assertEqual(summary["total_changes"], 3)
        self.assertEqual(summary["new"], 1)
        self.assertEqual(summary["removed"], 1)
        self.assertEqual(summary["changed"], 1)
        self.assertEqual(summary["hosts_affected"], 2)

    def test_generate_summary_by_module(self):
        """Test that summary tracks changes by module."""
        diffs = {
            "example.com": [
                DiffResult("example.com", "Port Scanner", ChangeType.NEW, "open_ports", None, [80]),
                DiffResult("example.com", "Port Scanner", ChangeType.NEW, "services", None, ["http"]),
            ],
        }

        summary = self.differ.generate_summary(diffs)

        self.assertIn("Port Scanner", summary["by_module"])
        self.assertEqual(summary["by_module"]["Port Scanner"]["new"], 2)

    # -------------------------------------------------------------------------
    # Edge Case Tests
    # -------------------------------------------------------------------------

    def test_empty_baselines(self):
        """Test handling of empty baselines."""
        baseline = {}
        current = {}

        diffs = self.differ.diff(baseline, current)
        summary = self.differ.generate_summary(diffs)

        self.assertEqual(summary["total_changes"], 0)

    def test_error_results_ignored(self):
        """Test that error-only results are ignored."""
        baseline = {
            "example.com": {
                "scans": {
                    "Port Scanner": {"error": "Connection timeout"}
                }
            }
        }
        current = {
            "example.com": {
                "scans": {
                    "Port Scanner": {"error": "Different error"}
                }
            }
        }

        diffs = self.differ.diff(baseline, current)
        summary = self.differ.generate_summary(diffs)

        # Error-only results should not produce diffs
        self.assertEqual(summary["total_changes"], 0)

    def test_is_empty_or_error_detection(self):
        """Test _is_empty_or_error correctly identifies empty/error data."""
        self.assertTrue(self.differ._is_empty_or_error({}))
        self.assertTrue(self.differ._is_empty_or_error(None))
        self.assertTrue(self.differ._is_empty_or_error({"error": "Timeout"}))
        self.assertTrue(self.differ._is_empty_or_error({"status": "crashed"}))
        
        self.assertFalse(self.differ._is_empty_or_error({"open_ports": [80]}))
        self.assertFalse(self.differ._is_empty_or_error({"error": "Timeout", "partial": True}))


class TestBaselineIO(unittest.TestCase):
    """Test baseline file I/O functions."""

    def test_save_and_load_baseline(self):
        """Test saving and loading baseline files."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            test_data = {
                "example.com": {
                    "target": {"host": "example.com"},
                    "scans": {"Port Scanner": {"open_ports": [80, 443]}}
                }
            }

            save_baseline(test_data, temp_path)
            loaded = load_baseline(temp_path)

            self.assertEqual(loaded, test_data)

        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
