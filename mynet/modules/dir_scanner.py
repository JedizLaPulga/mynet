import asyncio
import aiohttp
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class DirScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Dir Enumerator"
        self.description = "Scans for common directories and hidden files"
        # Small default wordlist for demo purposes
        # In a real scanner, we'd load this from a file or allow user input
        self.wordlist = [
            "admin", "login", "dashboard", "api", "backup", "robots.txt", 
            "sitemap.xml", ".git/HEAD", ".env", "config.php", "wp-admin", 
            "test", "dev", "uploads", "images"
        ]
        # Concurrency limit for this specific module instance to avoid flooding
        self.sem = asyncio.Semaphore(10)

    async def run(self, target: Target) -> dict:
        base_urls = []
        if target.url:
            base_urls.append(target.url.rstrip('/'))
        elif target.host:
            base_urls.append(f"http://{target.host}")
            base_urls.append(f"https://{target.host}")

        results = {}
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for base in base_urls:
                tasks.append(self._scan_base(session, base))
            
            # Run scan for http and https in parallel
            scan_results = await asyncio.gather(*tasks)
            
            for res in scan_results:
                results.update(res)

        return results

    async def _scan_base(self, session, base_url: str) -> Dict[str, Any]:
        """Scans a single base URL against the wordlist."""
        found = []
        
        # We also scan the root effectively by just checking / if we wanted, 
        # but the HTTP module handles that. We focus on paths here.
        
        tasks = []
        for word in self.wordlist:
            url = f"{base_url}/{word}"
            tasks.append(self._check_url(session, url))
            
        results = await asyncio.gather(*tasks)
        
        for url, status, length in results:
            if status:
                found.append({"url": url, "status": status, "length": length})
                
        if found:
            return {base_url: found}
        return {}

    async def _check_url(self, session, url: str):
        headers = {'User-Agent': self.config.user_agent}
        async with self.sem:
            try:
                # Use HEAD to be faster, but some servers block HEAD. 
                # GET is safer for accuracy but slower. 
                # Let's use GET but stream=True to avoid downloading large bodies.
                async with session.get(url, headers=headers, ssl=False, timeout=self.config.timeout, allow_redirects=False) as response:
                    # Filter logic: 
                    # We consider it "found" if 200-299, 301, 302, 307, 401, 403 (for hidden/admin)
                    # We definitely skip 404.
                    if response.status not in [404, 400, 503, 502]:
                        return url, response.status, response.content_length or 0
            except Exception:
                pass
            return url, None, 0
