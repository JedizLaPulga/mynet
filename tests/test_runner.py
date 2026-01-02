import unittest
import asyncio
from mynet.core.runner import Runner
from mynet.core.config import Config
from mynet.core.input_parser import Target

class TestRunner(unittest.TestCase):
    def setUp(self):
        self.config = Config(timeout=1, ports=[80])
        self.runner = Runner(self.config)

    def test_load_modules(self):
        """Test that modules are loaded dynamically."""
        modules = self.runner.modules
        print(f"Loaded modules: {[m.name for m in modules]}")
        self.assertTrue(len(modules) > 0, "Should load at least one module")
        
        # Check if expected modules are loaded (based on file listing)
        module_names = [m.name for m in modules]
        self.assertIn("DNS Scanner", module_names)
        self.assertIn("Port Scanner", module_names)
        self.assertIn("HTTP Scanner", module_names)
        self.assertIn("SSL Scanner", module_names)

    def test_run_scan_structure(self):
        """Test the run_scan method returns the correct structure."""
        target = Target(original_input="example.com", host="example.com", type="domain")
        
        # We need to run the async method
        # This is an integration test that actually runs the modules (mocking would be better for unit tests, 
        # but for 'cleaning up and verifying it works' this is okay)
        results = asyncio.run(self.runner.run_scan([target]))
        
        self.assertIn("example.com", results)
        self.assertIn("target", results["example.com"])
        self.assertIn("scans", results["example.com"])
        
        scans = results["example.com"]["scans"]
        self.assertIsInstance(scans, dict)
        
        # Since we are running against example.com, we might get actual results or errors,
        # but we just want to check the structure holds up.

if __name__ == "__main__":
    unittest.main()
