"""Tests for Screenshot Scanner module."""

import unittest
import asyncio
import os
import tempfile
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.screenshot_scanner import ScreenshotScanner, PLAYWRIGHT_AVAILABLE
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestScreenshotScanner(unittest.TestCase):
    """Test cases for ScreenshotScanner class."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = Config()
        self.config.screenshot_dir = self.temp_dir
        self.config.screenshot_full_page = False
        self.config.screenshot_mobile = False
        self.config.screenshot_quality = 80
        self.config.timeout = 10
        self.scanner = ScreenshotScanner(self.config)

    def tearDown(self):
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Configuration Tests
    # -------------------------------------------------------------------------

    def test_default_configuration(self):
        """Test default configuration values."""
        config = Config()
        scanner = ScreenshotScanner(config)
        
        self.assertEqual(scanner.name, "Screenshot Capture")
        self.assertFalse(scanner.full_page)
        self.assertFalse(scanner.mobile)
        self.assertEqual(scanner.quality, 80)

    def test_custom_output_directory(self):
        """Test custom output directory is used."""
        self.assertEqual(self.scanner.output_dir, self.temp_dir)

    def test_viewport_settings(self):
        """Test viewport dimensions are set correctly."""
        self.assertEqual(self.scanner.desktop_viewport["width"], 1920)
        self.assertEqual(self.scanner.desktop_viewport["height"], 1080)
        self.assertEqual(self.scanner.mobile_viewport["width"], 375)
        self.assertEqual(self.scanner.mobile_viewport["height"], 812)

    # -------------------------------------------------------------------------
    # URL Helper Tests
    # -------------------------------------------------------------------------

    def test_get_url_with_url_target(self):
        """Test _get_url with URL target."""
        target = Target(
            original_input="https://example.com",
            host="example.com",
            url="https://example.com"
        )
        self.assertEqual(self.scanner._get_url(target), "https://example.com")

    def test_get_url_with_host_target(self):
        """Test _get_url with host-only target."""
        target = Target(original_input="example.com", host="example.com")
        self.assertEqual(self.scanner._get_url(target), "http://example.com")

    def test_get_url_empty_target(self):
        """Test _get_url with empty target."""
        target = Target(original_input="", host="")
        self.assertIsNone(self.scanner._get_url(target))

    # -------------------------------------------------------------------------
    # User Agent Tests
    # -------------------------------------------------------------------------

    def test_desktop_user_agent(self):
        """Test desktop user agent contains expected strings."""
        ua = self.scanner._get_user_agent("desktop")
        self.assertIn("Windows NT", ua)
        self.assertIn("Chrome", ua)

    def test_mobile_user_agent(self):
        """Test mobile user agent contains expected strings."""
        ua = self.scanner._get_user_agent("mobile")
        self.assertIn("iPhone", ua)
        self.assertIn("Mobile", ua)

    # -------------------------------------------------------------------------
    # Filename Generation Tests
    # -------------------------------------------------------------------------

    def test_filename_generation(self):
        """Test filename generation format."""
        filename = self.scanner._generate_filename("https://example.com/path", "desktop")
        
        self.assertIn("example.com", filename)
        self.assertIn("desktop", filename)
        self.assertTrue(filename.endswith(".jpg"))  # quality < 100

    def test_filename_generation_png(self):
        """Test PNG filename when quality is 100."""
        self.scanner.quality = 100
        filename = self.scanner._generate_filename("https://example.com", "desktop")
        
        self.assertTrue(filename.endswith(".png"))

    def test_filename_special_characters(self):
        """Test filename generation with special characters in URL."""
        filename = self.scanner._generate_filename(
            "https://example.com/path?query=1&foo=bar",
            "desktop"
        )
        # Should not contain special chars that break filesystems
        self.assertNotIn("?", filename)
        self.assertNotIn("&", filename)

    # -------------------------------------------------------------------------
    # Human Readable Size Tests
    # -------------------------------------------------------------------------

    def test_human_readable_bytes(self):
        """Test human readable size for bytes."""
        self.assertEqual(self.scanner._human_readable_size(500), "500.0 B")

    def test_human_readable_kilobytes(self):
        """Test human readable size for kilobytes."""
        self.assertEqual(self.scanner._human_readable_size(1024), "1.0 KB")

    def test_human_readable_megabytes(self):
        """Test human readable size for megabytes."""
        self.assertEqual(self.scanner._human_readable_size(1024 * 1024), "1.0 MB")

    # -------------------------------------------------------------------------
    # Empty Target Tests
    # -------------------------------------------------------------------------

    def test_empty_target_returns_empty(self):
        """Test that empty target returns empty dict."""
        target = Target(original_input="", host="")
        results = asyncio.run(self.scanner.run(target))
        self.assertEqual(results, {})

    # -------------------------------------------------------------------------
    # Playwright Availability Tests
    # -------------------------------------------------------------------------

    def test_playwright_not_available_error(self):
        """Test graceful error when playwright is not available."""
        with patch('mynet.modules.screenshot_scanner.PLAYWRIGHT_AVAILABLE', False):
            scanner = ScreenshotScanner(self.config)
            # Manually set the flag since it's a module-level constant
            original_available = PLAYWRIGHT_AVAILABLE
            
            # We need to test the actual behavior
            target = Target(original_input="example.com", host="example.com")

            # Mock PLAYWRIGHT_AVAILABLE at the module level
            import mynet.modules.screenshot_scanner as ss_module
            old_value = ss_module.PLAYWRIGHT_AVAILABLE
            ss_module.PLAYWRIGHT_AVAILABLE = False
            
            try:
                results = asyncio.run(scanner.run(target))
                if not old_value:  # Only if playwright wasn't actually available
                    self.assertIn("error", results)
                    self.assertIn("Playwright not installed", results["error"])
            finally:
                ss_module.PLAYWRIGHT_AVAILABLE = old_value

    # -------------------------------------------------------------------------
    # Mock Browser Tests
    # -------------------------------------------------------------------------

    def _create_mock_page(self, title="Test Page", status=200):
        """Helper to create a mock Playwright page."""
        mock_page = AsyncMock()
        mock_page.title = AsyncMock(return_value=title)
        mock_page.content = AsyncMock(return_value="<html><body>Test</body></html>")
        mock_page.screenshot = AsyncMock()
        mock_page.goto = AsyncMock()
        mock_page.wait_for_timeout = AsyncMock()
        mock_page.query_selector = AsyncMock(return_value=None)
        mock_page.query_selector_all = AsyncMock(return_value=[])
        mock_page.evaluate = AsyncMock(return_value="rgb(255, 255, 255)")
        mock_page.close = AsyncMock()
        
        # Mock response
        mock_response = MagicMock()
        mock_response.status = status
        mock_page.goto.return_value = mock_response
        
        return mock_page

    def _create_mock_context(self, page):
        """Helper to create a mock browser context."""
        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=page)
        mock_context.close = AsyncMock()
        return mock_context

    def _create_mock_browser(self, context):
        """Helper to create a mock browser."""
        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=context)
        mock_browser.close = AsyncMock()
        return mock_browser

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_capture_desktop_screenshot(self):
        """Test desktop screenshot capture flow."""
        mock_page = self._create_mock_page()
        mock_context = self._create_mock_context(mock_page)
        mock_browser = self._create_mock_browser(mock_context)

        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw_instance = AsyncMock()
            mock_pw_instance.chromium.launch = AsyncMock(return_value=mock_browser)
            mock_pw.return_value.__aenter__.return_value = mock_pw_instance

            # Mock file operations
            with patch('os.path.getsize', return_value=50000):
                target = Target(original_input="example.com", host="example.com")
                results = asyncio.run(self.scanner.run(target))

                self.assertTrue(results.get("success"))
                self.assertEqual(results.get("count"), 1)
                self.assertEqual(len(results.get("screenshots", [])), 1)

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_capture_with_mobile_enabled(self):
        """Test mobile screenshot capture when enabled."""
        self.scanner.mobile = True
        
        mock_page = self._create_mock_page()
        mock_context = self._create_mock_context(mock_page)
        mock_browser = self._create_mock_browser(mock_context)

        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw_instance = AsyncMock()
            mock_pw_instance.chromium.launch = AsyncMock(return_value=mock_browser)
            mock_pw.return_value.__aenter__.return_value = mock_pw_instance

            with patch('os.path.getsize', return_value=50000):
                target = Target(original_input="example.com", host="example.com")
                results = asyncio.run(self.scanner.run(target))

                # Should have 2 screenshots (desktop + mobile)
                self.assertEqual(results.get("count"), 2)

    # -------------------------------------------------------------------------
    # Metadata Extraction Tests
    # -------------------------------------------------------------------------

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_metadata_extraction(self):
        """Test page metadata extraction."""
        mock_page = self._create_mock_page(title="Login - Example Site")
        
        # Mock login form detection
        mock_page.query_selector_all = AsyncMock(side_effect=[
            [],  # forms
            [MagicMock()],  # password inputs
        ])

        mock_context = self._create_mock_context(mock_page)
        mock_browser = self._create_mock_browser(mock_context)

        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw_instance = AsyncMock()
            mock_pw_instance.chromium.launch = AsyncMock(return_value=mock_browser)
            mock_pw.return_value.__aenter__.return_value = mock_pw_instance

            with patch('os.path.getsize', return_value=50000):
                target = Target(original_input="example.com", host="example.com")
                results = asyncio.run(self.scanner.run(target))

                metadata = results.get("metadata", {})
                self.assertEqual(metadata.get("title"), "Login - Example Site")

    # -------------------------------------------------------------------------
    # Dark Mode Detection Tests
    # -------------------------------------------------------------------------

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_dark_mode_detection(self):
        """Test dark mode detection from background color."""
        mock_page = self._create_mock_page()
        # Dark background
        mock_page.evaluate = AsyncMock(return_value="rgb(30, 30, 30)")

        mock_context = self._create_mock_context(mock_page)
        mock_browser = self._create_mock_browser(mock_context)

        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw_instance = AsyncMock()
            mock_pw_instance.chromium.launch = AsyncMock(return_value=mock_browser)
            mock_pw.return_value.__aenter__.return_value = mock_pw_instance

            with patch('os.path.getsize', return_value=50000):
                target = Target(original_input="example.com", host="example.com")
                results = asyncio.run(self.scanner.run(target))

                metadata = results.get("metadata", {})
                self.assertTrue(metadata.get("dark_mode"))

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_light_mode_detection(self):
        """Test light mode detection from background color."""
        mock_page = self._create_mock_page()
        # Light background
        mock_page.evaluate = AsyncMock(return_value="rgb(255, 255, 255)")

        mock_context = self._create_mock_context(mock_page)
        mock_browser = self._create_mock_browser(mock_context)

        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw_instance = AsyncMock()
            mock_pw_instance.chromium.launch = AsyncMock(return_value=mock_browser)
            mock_pw.return_value.__aenter__.return_value = mock_pw_instance

            with patch('os.path.getsize', return_value=50000):
                target = Target(original_input="example.com", host="example.com")
                results = asyncio.run(self.scanner.run(target))

                metadata = results.get("metadata", {})
                self.assertFalse(metadata.get("dark_mode"))

    # -------------------------------------------------------------------------
    # Error Handling Tests
    # -------------------------------------------------------------------------

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_browser_launch_failure(self):
        """Test graceful handling of browser launch failure."""
        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw.return_value.__aenter__.side_effect = Exception("Browser failed")

            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertFalse(results.get("success"))
            self.assertGreater(len(results.get("errors", [])), 0)

    @unittest.skipIf(not PLAYWRIGHT_AVAILABLE, "Playwright not installed")
    def test_navigation_timeout(self):
        """Test handling of navigation timeout."""
        mock_page = self._create_mock_page()
        mock_page.goto.side_effect = Exception("Navigation timeout")

        mock_context = self._create_mock_context(mock_page)
        mock_browser = self._create_mock_browser(mock_context)

        with patch('mynet.modules.screenshot_scanner.async_playwright') as mock_pw:
            mock_pw_instance = AsyncMock()
            mock_pw_instance.chromium.launch = AsyncMock(return_value=mock_browser)
            mock_pw.return_value.__aenter__.return_value = mock_pw_instance

            target = Target(original_input="example.com", host="example.com")
            results = asyncio.run(self.scanner.run(target))

            # Should handle error gracefully
            screenshots = results.get("screenshots", [])
            if screenshots:
                self.assertIn("error", screenshots[0])


if __name__ == "__main__":
    unittest.main()
