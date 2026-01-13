"""
Screenshot Capture Module.

Captures webpage screenshots for visual reconnaissance.
Uses Playwright for reliable cross-browser rendering.

Features:
- Full page and viewport screenshots
- Mobile viewport emulation
- Dark mode detection
- Thumbnail generation
- Page metadata extraction
- Configurable output directory
- Async batch processing
"""

import asyncio
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from .base import BaseModule
from ..core.input_parser import Target

# Playwright is optional - graceful degradation if not installed
try:
    from playwright.async_api import async_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class ScreenshotScanner(BaseModule):
    """Captures webpage screenshots for visual reconnaissance."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "Screenshot Capture"
        self.description = "Captures webpage screenshots for visual recon"

        # Configuration
        self.output_dir = getattr(config, 'screenshot_dir', './screenshots')
        self.full_page = getattr(config, 'screenshot_full_page', False)
        self.mobile = getattr(config, 'screenshot_mobile', False)
        self.timeout = getattr(config, 'timeout', 10) * 1000  # Convert to ms
        self.quality = getattr(config, 'screenshot_quality', 80)

        # Viewport settings
        self.desktop_viewport = {"width": 1920, "height": 1080}
        self.mobile_viewport = {"width": 375, "height": 812}  # iPhone X

        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    async def run(self, target: Target) -> dict:
        """Execute screenshot capture."""
        if not PLAYWRIGHT_AVAILABLE:
            return {
                "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
                "available": False,
            }

        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "url": url,
            "screenshots": [],
            "metadata": {},
            "errors": [],
        }

        try:
            async with async_playwright() as p:
                # Launch browser
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                    ]
                )

                try:
                    # Capture desktop screenshot
                    desktop_result = await self._capture_screenshot(
                        browser, url, "desktop", self.desktop_viewport
                    )
                    if desktop_result:
                        results["screenshots"].append(desktop_result)
                        results["metadata"] = desktop_result.get("page_metadata", {})

                    # Optionally capture mobile screenshot
                    if self.mobile:
                        mobile_result = await self._capture_screenshot(
                            browser, url, "mobile", self.mobile_viewport
                        )
                        if mobile_result:
                            results["screenshots"].append(mobile_result)

                except Exception as e:
                    results["errors"].append(str(e))

                finally:
                    await browser.close()

        except Exception as e:
            results["errors"].append(f"Browser launch failed: {str(e)}")

        results["success"] = len(results["screenshots"]) > 0
        results["count"] = len(results["screenshots"])

        return results

    async def _capture_screenshot(
        self,
        browser: "Browser",
        url: str,
        viewport_type: str,
        viewport: dict,
    ) -> Optional[dict]:
        """Capture a single screenshot with the given viewport."""
        context = None
        page = None

        try:
            # Create browser context with viewport
            context = await browser.new_context(
                viewport=viewport,
                user_agent=self._get_user_agent(viewport_type),
                ignore_https_errors=True,
            )

            page = await context.new_page()

            # Navigate to URL
            response = await page.goto(
                url,
                wait_until="networkidle",
                timeout=self.timeout,
            )

            if not response:
                return None

            # Wait for page to stabilize
            await page.wait_for_timeout(500)

            # Extract page metadata
            metadata = await self._extract_metadata(page, response)

            # Generate filename
            filename = self._generate_filename(url, viewport_type)
            filepath = os.path.join(self.output_dir, filename)

            # Capture screenshot
            await page.screenshot(
                path=filepath,
                full_page=self.full_page,
                type="png" if self.quality == 100 else "jpeg",
                quality=self.quality if self.quality < 100 else None,
            )

            # Get file size
            file_size = os.path.getsize(filepath)

            return {
                "viewport": viewport_type,
                "path": filepath,
                "filename": filename,
                "dimensions": f"{viewport['width']}x{viewport['height']}",
                "full_page": self.full_page,
                "file_size": file_size,
                "file_size_human": self._human_readable_size(file_size),
                "captured_at": datetime.now().isoformat(),
                "page_metadata": metadata,
            }

        except Exception as e:
            return {
                "viewport": viewport_type,
                "error": str(e),
            }

        finally:
            if page:
                await page.close()
            if context:
                await context.close()

    async def _extract_metadata(self, page: "Page", response) -> dict:
        """Extract useful metadata from the page."""
        metadata = {
            "status_code": response.status,
            "title": "",
            "description": "",
            "favicon": "",
            "technologies": [],
            "has_forms": False,
            "has_login": False,
            "dark_mode": False,
        }

        try:
            # Get title
            metadata["title"] = await page.title()

            # Get meta description
            desc_elem = await page.query_selector('meta[name="description"]')
            if desc_elem:
                metadata["description"] = await desc_elem.get_attribute("content") or ""

            # Get favicon
            favicon_elem = await page.query_selector('link[rel*="icon"]')
            if favicon_elem:
                metadata["favicon"] = await favicon_elem.get_attribute("href") or ""

            # Detect forms
            forms = await page.query_selector_all("form")
            metadata["has_forms"] = len(forms) > 0

            # Detect login forms
            login_indicators = await page.query_selector_all(
                'input[type="password"], input[name*="password"], input[name*="login"]'
            )
            metadata["has_login"] = len(login_indicators) > 0

            # Basic technology detection from page content
            metadata["technologies"] = await self._detect_technologies(page)

            # Detect dark mode
            metadata["dark_mode"] = await self._detect_dark_mode(page)

        except Exception:
            pass

        return metadata

    async def _detect_technologies(self, page: "Page") -> list:
        """Basic technology detection from page."""
        technologies = []

        try:
            html = await page.content()
            html_lower = html.lower()

            # Quick checks
            tech_signatures = {
                "React": ["react", "_reactroot", "data-reactroot"],
                "Vue.js": ["vue", "v-app", "data-v-"],
                "Angular": ["ng-app", "ng-version", "angular"],
                "jQuery": ["jquery"],
                "Bootstrap": ["bootstrap"],
                "Tailwind CSS": ["tailwind"],
                "WordPress": ["wp-content", "wordpress"],
                "Next.js": ["__next", "_next"],
                "Nuxt.js": ["__nuxt", "_nuxt"],
            }

            for tech, signatures in tech_signatures.items():
                for sig in signatures:
                    if sig in html_lower:
                        technologies.append(tech)
                        break

        except Exception:
            pass

        return list(set(technologies))

    async def _detect_dark_mode(self, page: "Page") -> bool:
        """Detect if page uses dark mode."""
        try:
            bg_color = await page.evaluate("""
                () => {
                    const body = document.body;
                    const style = window.getComputedStyle(body);
                    return style.backgroundColor;
                }
            """)

            # Parse RGB values
            if "rgb" in bg_color:
                # Extract RGB values
                values = bg_color.replace("rgb(", "").replace("rgba(", "").replace(")", "")
                parts = [int(x.strip()) for x in values.split(",")[:3]]
                # Calculate luminance
                luminance = (0.299 * parts[0] + 0.587 * parts[1] + 0.114 * parts[2]) / 255
                return luminance < 0.5

        except Exception:
            pass

        return False

    def _get_url(self, target: Target) -> Optional[str]:
        """Get URL from target."""
        if target.url:
            return target.url
        if target.host:
            return f"http://{target.host}"
        return None

    def _get_user_agent(self, viewport_type: str) -> str:
        """Get appropriate user agent for viewport type."""
        if viewport_type == "mobile":
            return (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
            )
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def _generate_filename(self, url: str, viewport_type: str) -> str:
        """Generate a unique filename for the screenshot."""
        parsed = urlparse(url)
        hostname = parsed.hostname or "unknown"

        # Create hash of full URL for uniqueness
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

        # Timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Clean hostname
        safe_hostname = "".join(c if c.isalnum() or c in "-_." else "_" for c in hostname)

        extension = "png" if self.quality == 100 else "jpg"

        return f"{safe_hostname}_{viewport_type}_{timestamp}_{url_hash}.{extension}"

    def _human_readable_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
