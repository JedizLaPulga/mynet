import aiohttp
import re
from typing import Any, Optional
from .base import BaseModule
from ..core.input_parser import Target

class WAFScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "WAF Detection"
        self.description = "Detects Web Application Firewalls (Cloudflare, AWS, Akamai, etc.)"
        
        # Signatures for detection
        # Format: (Name, Location, Pattern)
        # Location: 'headers', 'cookie', 'server'
        self.signatures = [
            ("Cloudflare", "headers", r"CF-RAY"),
            ("Cloudflare", "server", r"cloudflare"),
            ("Cloudflare", "cookie", r"__cfduid"),
            ("AWS WAF", "headers", r"X-Amz-Cf-Id"),
            ("AWS WAF", "headers", r"X-CDN"),
            ("Akamai", "server", r"AkamaiGHost"),
            ("Akamai", "headers", r"X-Akamai-Transformed"),
            ("Incapsula", "headers", r"X-Iinfo"),
            ("Incapsula", "cookie", r"incap_ses"),
            ("F5 BIG-IP", "cookie", r"^TS[0-9a-f]{8}"),
            ("Imperva", "headers", r"X-CDN: Incapsula"),
            ("Barracuda WAF", "cookie", r"^barra_counter_session"),
            ("Sucuri", "server", r"Sucuri/Cloudproxy"),
        ]

    async def run(self, target: Target) -> dict:
        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "detected": False,
            "wafs": []
        }

        async with aiohttp.ClientSession() as session:
            try:
                # We perform a simple GET request
                # Some WAFs only trigger on specific attacks, but most leave signature headers.
                async with session.get(url, timeout=self.config.timeout, verify_ssl=False) as response:
                    
                    headers = response.headers
                    cookies = response.cookies
                    server_header = headers.get("Server", "")
                    
                    found_wafs = set()

                    # Check Headers
                    for name, loc, pattern in self.signatures:
                        if loc == "headers":
                            for h_name, h_val in headers.items():
                                if re.search(pattern, h_name, re.IGNORECASE) or re.search(pattern, h_val, re.IGNORECASE):
                                    found_wafs.add(name)
                        
                        elif loc == "server":
                            if re.search(pattern, server_header, re.IGNORECASE):
                                found_wafs.add(name)
                                
                        elif loc == "cookie":
                            for cookie in cookies:
                                if re.search(pattern, cookie, re.IGNORECASE):
                                    found_wafs.add(name)

                    if found_wafs:
                        results["detected"] = True
                        results["wafs"] = list(found_wafs)

            except Exception as e:
                results["error"] = str(e)

        return results

    def _get_url(self, target: Target) -> Optional[str]:
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
