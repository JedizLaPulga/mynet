import aiohttp
import asyncio
from typing import Dict, Any, List
from ..core.input_parser import Target
from .base import BaseModule

class SubdomainScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Subdomain Scanner"
        self.description = "Passive subdomain enumeration using Certificate Transparency logs (crt.sh)"
        self.semaphore = asyncio.Semaphore(2)  # Limit concurrent requests to crt.sh per instance

    async def run(self, target: Target) -> Dict[str, Any]:
        if target.type != "domain":
            return {"error": "Subdomain enumeration only works on domains"}

        domain = target.host
        if not domain:
            return {"error": "No host specified"}

        try:
            subdomains = await self._fetch_crtsh(domain)
            return {
                "count": len(subdomains),
                "subdomains": sorted(list(subdomains))
            }
        except Exception as e:
            return {"error": str(e)}

    async def _fetch_crtsh(self, domain: str) -> set:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        async with self.semaphore:
            # Add a timeout specifically for the HTTP request
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise Exception(f"crt.sh returned status {response.status}")
                    
                    try:
                        data = await response.json()
                    except Exception:
                        # Sometimes crt.sh fails to return valid JSON on errors or high load
                        text = await response.text()
                        if "Too many" in text: # naive check
                            raise Exception("Rate limited by crt.sh")
                        raise Exception("Failed to parse crt.sh response")

                    found = set()
                    if not data:
                        return found

                    for entry in data:
                        # name_value can be multi-line or contain wildcards
                        name = entry.get("name_value", "")
                        if not name:
                            continue
                        
                        # Split separate lines (some entries have multiple domains)
                        lines = name.split("\n")
                        for line in lines:
                            line = line.strip().lower()
                            # Filter out wildcards and the domain itself if desired, 
                            # but usually we want to see everything properly associated.
                            if "*" in line:
                                continue
                            
                            # Cleanup to ensure we only have subdomains of the target 
                            # (crt.sh sometimes returns slightly unrelated certs in chain)
                            if line.endswith(f".{domain}") or line == domain:
                                found.add(line)
                    
                    return found
