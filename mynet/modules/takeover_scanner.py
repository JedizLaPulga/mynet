import asyncio
import aiohttp
import dns.asyncresolver
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class TakeoverScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Subdomain Takeover"
        self.description = "Checks for dangling CNAME records indicating potential subdomain takeover"
        
        # Fingerprints
        # CNAME Pattern -> Response Content Pattern
        self.fingerprints = {
            "s3.amazonaws.com": "The specified bucket does not exist",
            "github.io": "There isn't a GitHub Pages site here",
            "herokuapp.com": "There is no app configured at this hostname",
            "azurewebsites.net": "404 Web Site not found",
            "pantheonsite.io": "The gods are wise, but do not know of the site which you seek",
            "readme.io": "Project doesnt exist... yet!",
            "ghost.io": "The thing you were looking for is no longer here",
            "cargo.site": "If you're moving your domain away from Cargo",
            "surge.sh": "project not found",
            "wordpress.com": "Do you want to register",
            "shopify.com": "Sorry, this shop is currently unavailable"
        }

    async def run(self, target: Target) -> dict:
        # We only scan if we have a hostname (domain/subdomain)
        host = target.host
        if not host:
            return {}

        results = {
            "vulnerable": False,
            "provider": None,
            "cname": None
        }

        try:
            # 1. Resolve CNAME
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            # Using query instead of resolve for specific record type
            try:
                answers = await resolver.resolve(host, 'CNAME')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
                return {} # No CNAME or resolution failed

            cname_target = str(answers[0].target).rstrip('.')
            
            # 2. Check if CNAME matches known providers
            matched_provider = None
            expected_error = None
            
            for provider_sig, error_text in self.fingerprints.items():
                if provider_sig in cname_target:
                    matched_provider = provider_sig
                    expected_error = error_text
                    break
            
            if matched_provider:
                # 3. Verify vulnerability by checking HTTP response
                is_vuln = await self._check_http_content(host, expected_error)
                if is_vuln:
                    results["vulnerable"] = True
                    results["provider"] = matched_provider
                    results["cname"] = cname_target
                    return results

        except Exception as e:
            pass

        return {}

    async def _check_http_content(self, host: str, error_text: str) -> bool:
        url = f"http://{host}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    if error_text.lower() in text.lower():
                        return True
            except Exception:
                pass
        return False
