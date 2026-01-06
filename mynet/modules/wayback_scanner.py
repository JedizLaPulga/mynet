import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs
from typing import Set, Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class WaybackScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Wayback Machine Scanner"
        self.description = "Queries Archive.org for historical URLs to find hidden endpoints"
        
        # Ignored extensions to reduce noise
        self.ignored_exts = {
            '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', 
            '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.doc', '.docx'
        }

    async def run(self, target: Target) -> dict:
        host = target.host
        if not host:
            return {}

        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json&fl=original&collapse=urlkey"
        
        results = {
            "urls": [],
            "interesting_params": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(wayback_url, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # data is list of lists, first is header ["original"]
                        if data and len(data) > 1:
                            urls = set()
                            params_seen = set()
                            
                            for row in data[1:]:
                                url = row[0]
                                if self._is_interesting(url):
                                    urls.add(url)
                                    
                                    # Check for params
                                    parsed = urlparse(url)
                                    if parsed.query:
                                        for k in parse_qs(parsed.query).keys():
                                            params_seen.add(k)
                            
                            results["urls"] = sorted(list(urls))[:200] # Limit for display
                            results["total_found"] = len(urls)
                            results["interesting_params"] = sorted(list(params_seen))
                            
        except Exception as e:
            results["error"] = str(e)

        return results

    def _is_interesting(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check extension
        for ext in self.ignored_exts:
            if path.endswith(ext):
                return False
                
        return True
