import asyncio
import aiohttp
import re
from typing import Dict, Any, Set, List
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .base import BaseModule
from ..core.input_parser import Target

class JSSecretScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "JS Secret Scanner"
        self.description = "Scans Javascript files for hardcoded secrets and API keys"
        
        # High-confidence regex patterns
        self.patterns = [
            ("AWS Access Key ID", r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            ("AWS Secret Access Key", r"(?i:aws(.{0,20})?)['\"][0-9a-zA-Z\/+]{40}['\"]"),
            ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
            ("Firebase URL", r".*firebaseio\.com"),
            ("Slack Token", r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"),
            ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----"),
            ("SSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("Generic API Key", r"(?i)(api_key|apikey|access_token|auth_token)(.{0,20})?['\"]([a-zA-Z0-9_\-]{16,64})['\"]"),
            ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
        ]

    async def run(self, target: Target) -> dict:
        start_url = self._get_start_url(target)
        if not start_url:
            return {}

        js_urls = await self._find_js_files(start_url)
        
        results = {
            "scanned_files": len(js_urls),
            "secrets": []
        }

        if not js_urls:
            return {}

        async with aiohttp.ClientSession() as session:
            tasks = []
            for js_url in js_urls:
                tasks.append(self._scan_js_file(session, js_url))
            
            # Gather all file scan results
            file_results = await asyncio.gather(*tasks)
            
            for res in file_results:
                if res and res.get("secrets"):
                    results["secrets"].extend(res["secrets"])

        # Deduplicate secrets
        # Convert to string to hash, then list
        unique_secrets = []
        seen = set()
        for s in results["secrets"]:
            sig = f"{s['type']}:{s['value']}"
            if sig not in seen:
                seen.add(sig)
                unique_secrets.append(s)
        
        results["secrets"] = unique_secrets
        
        return results

    async def _find_js_files(self, url: str) -> Set[str]:
        headers = {'User-Agent': self.config.user_agent}
        js_files = set()
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, ssl=False, timeout=self.config.timeout) as resp:
                    if resp.status != 200:
                        return js_files
                    
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # 1. <script src="...">
                    for script in soup.find_all('script', src=True):
                        src = script.get('src')
                        full_url = urljoin(url, src)
                        if self._is_valid_js(full_url):
                            js_files.add(full_url)
            except Exception:
                pass
                
        return js_files

    async def _scan_js_file(self, session, url: str) -> Dict[str, Any]:
        try:
            async with session.get(url, ssl=False, timeout=self.config.timeout) as resp:
                if resp.status != 200:
                    return None
                
                content = await resp.text()
                
                found_secrets = []
                for name, pattern in self.patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Extract the full match or specific group if needed
                        # For simplicity, we take the full match string or reasonable context
                        val = match.group(0)
                        
                        # Cleanup quotes if they were captured in generic regex
                        val = val.strip("'").strip('"')
                        
                        found_secrets.append({
                            "type": name,
                            "value": val[:50] + "..." if len(val) > 50 else val, # Truncate for display
                            "source": url
                        })
                
                return {"url": url, "secrets": found_secrets}
                
        except Exception:
            pass
        return None

    def _is_valid_js(self, url: str) -> bool:
        # Basic check
        path = urlparse(url).path
        return path.endswith('.js') or "javascript" in path

    def _get_start_url(self, target: Target):
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
