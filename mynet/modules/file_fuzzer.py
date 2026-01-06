import asyncio
import aiohttp
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class FileFuzzer(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Sensitive File Fuzzer"
        self.description = "Checks for common sensitive files (config backups, env files, git exposure)"
        
        # List of paths to check
        self.paths = [
            ".env",
            ".git/HEAD",
            ".git/config",
            ".svn/entries",
            ".DS_Store",
            "config.php.bak",
            "wp-config.php.bak",
            "backup.sql",
            "database.sql",
            "id_rsa",
            "id_rsa.pub",
            "web.config",
            "package.json",
            "Dockerfile",
            "docker-compose.yml",
            "robots.txt",
            "sitemap.xml"
        ]

    async def run(self, target: Target) -> dict:
        url = self._get_base_url(target)
        if not url:
            return {}

        results = {
            "found": []
        }

        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in self.paths:
                tasks.append(self._check_path(session, url, path))
            
            # Run checks in parallel
            found_paths = await asyncio.gather(*tasks)
            
            # Filter out None results
            results["found"] = [p for p in found_paths if p]

        if not results["found"]:
            return {}
            
        return results

    async def _check_path(self, session: aiohttp.ClientSession, base_url: str, path: str) -> Dict[str, str]:
        target_url = f"{base_url.rstrip('/')}/{path}"
        try:
            async with session.get(target_url, timeout=self.config.timeout, ssl=False) as resp:
                if resp.status == 200:
                    # Basic False Positive check
                    # Some servers return 200 for everything (soft 404)
                    # We check if content length is reasonable or specific content exists
                    # For .git/HEAD, we expect "ref:"
                    text = await resp.text()
                    
                    if path == ".git/HEAD" and "ref:" not in text:
                        return None
                        
                    return {
                        "path": path,
                        "url": target_url,
                        "status": 200,
                        "size": len(text)
                    }
        except Exception:
            pass
        return None

    def _get_base_url(self, target: Target) -> str:
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
