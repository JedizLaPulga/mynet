import asyncio
import aiohttp
import re
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class VulnScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Vuln Scanner"
        self.description = "Checks detected service versions against a CVE database (NIST/CIRCL API)"
        # Caching to avoid spamming APIs for the same software version
        self.cache = {}

    async def run(self, target: Target) -> dict:
        # This module relies on the "Tech Fingerprinter" or "Port Scanner" having run first.
        # But modules run in parallel. 
        # Ideally, we would chain them, but for now we will cheat/demo by 
        # doing a quick banner grab or re-using logic if we were in a pipeline.
        #
        # For this standalone POC, we will:
        # 1. Grab HTTP Server header (lightweight)
        # 2. Query CVEs for that software + version
        
        software_list = await self._detect_software(target)
        if not software_list:
            return {}

        results = {}
        async with aiohttp.ClientSession() as session:
            for software in software_list:
                name = software['name']
                version = software['version']
                key = f"{name} {version}"
                
                if key in self.cache:
                    results[key] = self.cache[key]
                    continue
                
                cves = await self._lookup_cve_circl(session, name, version)
                self.cache[key] = cves
                if cves:
                    results[key] = cves
        
        return results

    async def _detect_software(self, target: Target) -> List[Dict[str, str]]:
        # Lightweight re-implementation of basic header check to be standalone
        urls = []
        if target.url:
            urls.append(target.url)
        elif target.host:
            urls.append(f"http://{target.host}")
        
        detected = []
        async with aiohttp.ClientSession() as session:
            for url in urls:
                try:
                    async with session.get(url, timeout=5, ssl=False) as resp:
                        header = resp.headers.get("Server", "")
                        # Parse: Apache/2.4.49 -> name=Apache, version=2.4.49
                        # Simple generic regex
                        match = re.search(r'([a-zA-Z\-]+)/([\d\.]+)', header)
                        if match:
                            detected.append({"name": match.group(1), "version": match.group(2)})
                except Exception:
                    pass
        return detected

    async def _lookup_cve_circl(self, session, name: str, version: str) -> List[Dict[str, Any]]:
        # Using CIRCL.lu API (Open/Free)
        # API: https://cve.circl.lu/api/search/apache/2.4.49
        
        url = f"https://cve.circl.lu/api/search/{name}/{version}"
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                
                # Data is a list of CVE objects
                # We prioritize high severity
                found = []
                for item in data:
                    # Basic filtering
                    cve_id = item.get("id")
                    cvss = item.get("cvss")
                    summary = item.get("summary", "")
                    
                    if cve_id:
                        found.append({
                            "id": cve_id,
                            "cvss": cvss,
                            "summary": summary[:100] + "..." # Truncate
                        })
                
                # Sort by CVSS desc
                found.sort(key=lambda x: float(x['cvss'] or 0), reverse=True)
                return found[:5] # Return top 5
        except Exception:
            return []
