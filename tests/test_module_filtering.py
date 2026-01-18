"""Tests for Runner module filtering functionality."""

import unittest
from unittest.mock import MagicMock, patch
from mynet.core.runner import Runner
from mynet.core.config import Config


class TestRunnerModuleFiltering(unittest.TestCase):
    """Test cases for Runner module include/exclude functionality."""

    def setUp(self):
        self.config = Config()

    def test_list_available_modules(self):
        """Test that list_available_modules returns module info."""
        modules = Runner.list_available_modules()
        
        self.assertIsInstance(modules, list)
        self.assertGreater(len(modules), 0)
        
        # Check structure of each module info
        for mod in modules:
            self.assertIn("name", mod)
            self.assertIn("description", mod)
            self.assertIn("class", mod)

    def test_include_modules_filter(self):
        """Test that include_modules limits loaded modules."""
        runner = Runner(
            self.config,
            include_modules=["WAF Detection", "Port Scanner"],
        )
        
        loaded_names = runner.get_loaded_module_names()
        
        # Should only have the specified modules
        self.assertLessEqual(len(loaded_names), 2)
        # All loaded modules should be in our include list
        for name in loaded_names:
            self.assertIn(name.lower(), ["waf detection", "port scanner"])

    def test_exclude_modules_filter(self):
        """Test that exclude_modules removes specified modules."""
        runner = Runner(
            self.config,
            exclude_modules=["Screenshot Capture"],
        )
        
        loaded_names = runner.get_loaded_module_names()
        
        # Screenshot Capture should not be loaded
        self.assertNotIn("Screenshot Capture", loaded_names)
        # But other modules should still be there
        self.assertGreater(len(loaded_names), 0)

    def test_case_insensitive_filtering(self):
        """Test that module filtering is case insensitive."""
        runner = Runner(
            self.config,
            include_modules=["waf detection"],  # lowercase
        )
        
        loaded_names = runner.get_loaded_module_names()
        
        # Should match despite case difference
        self.assertEqual(len(loaded_names), 1)
        self.assertEqual(loaded_names[0], "WAF Detection")

    def test_no_filters_loads_all(self):
        """Test that no filters loads all modules."""
        runner = Runner(self.config)
        
        loaded_names = runner.get_loaded_module_names()
        
        # Should have many modules
        self.assertGreater(len(loaded_names), 20)

    def test_normalize_names(self):
        """Test the _normalize_names helper method."""
        runner = Runner(self.config)
        
        # Test with list
        result = runner._normalize_names(["WAF Detection", " Port Scanner "])
        self.assertEqual(result, {"waf detection", "port scanner"})
        
        # Test with None
        result = runner._normalize_names(None)
        self.assertEqual(result, set())
        
        # Test with empty list
        result = runner._normalize_names([])
        self.assertEqual(result, set())

    def test_get_loaded_module_names(self):
        """Test get_loaded_module_names returns correct names."""
        runner = Runner(
            self.config,
            include_modules=["DNS Scanner"],
        )
        
        names = runner.get_loaded_module_names()
        
        self.assertIsInstance(names, list)
        self.assertEqual(len(names), 1)
        self.assertEqual(names[0], "DNS Scanner")

    def test_include_and_exclude_mutual_exclusivity(self):
        """Test that include takes precedence over exclude."""
        # If include is specified, exclude is ignored
        runner = Runner(
            self.config,
            include_modules=["DNS Scanner", "Port Scanner"],
            exclude_modules=["DNS Scanner"],  # Should be ignored
        )
        
        loaded_names = runner.get_loaded_module_names()
        
        # Include should take precedence, so DNS Scanner should be loaded
        self.assertIn("DNS Scanner", loaded_names)


if __name__ == "__main__":
    unittest.main()
