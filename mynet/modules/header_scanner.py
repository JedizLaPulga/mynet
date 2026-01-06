import asyncio
import aiohttp
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class HeaderScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Security Headers"
        self.description = "Analyzes HTTP response headers for security best practices"
        
        # Headers to check
        self.security_headers = {
            "Strict-Transport-Security": {"missing_risk": "High", "desc": "Enforces HTTPS connections"},
            "Content-Security-Policy": {"missing_risk": "High", "desc": "Mitigates XSS and data injection attacks"},
            "X-Frame-Options": {"missing_risk": "Medium", "desc": "Prevents Clickjacking"},
            "X-Content-Type-Options": {"missing_risk": "Low", "desc": "Prevents MIME-sniffing"},
            "Referrer-Policy": {"missing_risk": "Low", "desc": "Controls referrer information leakage"},
            "Permissions-Policy": {"missing_risk": "Low", "desc": "Controls browser features access"},
        }

    async def run(self, target: Target) -> dict:
        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "score": 100,
            "missing": [],
            "present": []
        }

        async with aiohttp.ClientSession() as session:
            try:
                # HEAD request is sufficient for headers, but some servers block HEAD
                # So we use GET with verify_ssl=False
                async with session.get(url, ssl=False, timeout=self.config.timeout) as resp:
                    headers = resp.headers
                    
                    found_count = 0
                    total_count = len(self.security_headers)
                    
                    for header, info in self.security_headers.items():
                        # Case insensitive check
                        found = False
                        for h in headers:
                            if h.lower() == header.lower():
                                found = True
                                results["present"].append({
                                    "header": header,
                                    "value": headers[h]
                                })
                                found_count += 1
                                break
                        
                        if not found:
                            results["missing"].append({
                                "header": header,
                                "risk": info["missing_risk"],
                                "description": info["desc"]
                            })
                            
                            # Simple penalty scoring
                            if info["missing_risk"] == "High":
                                results["score"] -= 20
                            elif info["missing_risk"] == "Medium":
                                results["score"] -= 10
                            else:
                                results["score"] -= 5
                    
                    if results["score"] < 0:
                        results["score"] = 0
                        
            except Exception:
                pass

        return results

    def _get_url(self, target: Target):
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
