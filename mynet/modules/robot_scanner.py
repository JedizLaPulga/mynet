import asyncio
import aiohttp
import re
from typing import Dict, Any, List, Set
from .base import BaseModule
from ..core.input_parser import Target
from urllib.parse import urljoin

class RobotScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Robots & Sitemap Scanner"
        self.description = "Analyzes robots.txt and sitemap.xml for hidden paths"

    async def run(self, target: Target) -> dict:
        base_url = self._get_base_url(target)
        if not base_url: return {}
        
        results = {
            "robots_found": False,
            "sitemap_found": False,
            "disallowed_paths": [],
            "sitemap_count": 0,
            "sitemap_urls": [] # preview
        }
        
        async with aiohttp.ClientSession() as session:
            # 1. robots.txt
            try:
                robots_url = urljoin(base_url, "/robots.txt")
                async with session.get(robots_url, ssl=False, timeout=self.config.timeout) as resp:
                    if resp.status == 200:
                        results["robots_found"] = True
                        text = await resp.text()
                        results["disallowed_paths"] = self._parse_robots(text)
            except Exception:
                pass

            # 2. sitemap.xml
            # Often linked in robots.txt, but we check standard location too
            sitemap_url = urljoin(base_url, "/sitemap.xml")
            # If robots had a specific sitemap directive, we could parse it, but for simplicity:
            # check the default location.
            
            try:
                async with session.get(sitemap_url, ssl=False, timeout=self.config.timeout) as resp:
                    if resp.status == 200:
                        results["sitemap_found"] = True
                        text = await resp.text()
                        # Simple Regex based extraction to avoid lxml overhead
                        urls = re.findall(r'<loc>(.*?)</loc>', text)
                        results["sitemap_count"] = len(urls)
                        results["sitemap_urls"] = urls[:20] # preview
            except Exception:
                pass
                
        return results

    def _parse_robots(self, text: str) -> List[str]:
        disallowed = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)
        return disallowed

    def _get_base_url(self, target: Target) -> str:
        if target.url: return target.url
        return f"http://{target.host}"
