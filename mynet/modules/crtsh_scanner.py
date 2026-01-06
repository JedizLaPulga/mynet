import asyncio
import aiohttp
from typing import Dict, Any, List, Set
from .base import BaseModule
from ..core.input_parser import Target

class CrtShScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "CRT.sh Scanner"
        self.description = "Passive subdomain enumeration using Certificate Transparency logs"

    async def run(self, target: Target) -> dict:
        host = target.host
        if not host:
            return {}

        url = f"https://crt.sh/?q=%.{host}&output=json"
        
        results = {
            "subdomains": [],
            "count": 0
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    if resp.status == 200:
                        try:
                            # crt.sh sometimes returns invalid JSON or HTML on error
                            # Content-Type check?
                            content_type = resp.headers.get("Content-Type", "")
                            if "application/json" in content_type:
                                data = await resp.json()
                            else:
                                # Fallback: try parse text
                                text = await resp.text()
                                import json
                                # crt.sh sometimes returns multiple json objects? usually list of dicts
                                data = json.loads(text)
                            
                            found = set()
                            if data and isinstance(data, list):
                                for item in data:
                                    name_value = item.get("name_value")
                                    if name_value:
                                        # Split multiline entries
                                        for sub in name_value.split("\n"):
                                            sub = sub.strip().lower()
                                            # Remove wildcards
                                            if "*" in sub: continue
                                            if sub.endswith(f".{host}"):
                                                found.add(sub)
                                                
                            results["subdomains"] = sorted(list(found))
                            results["count"] = len(found)
                        except Exception:
                            # JSON parse error quite common with crt.sh under load
                            pass
        except Exception as e:
            results["error"] = str(e)
            
        return results
