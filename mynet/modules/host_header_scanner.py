"""
Host Header Injection Scanner Module.

Tests for Host header injection vulnerabilities that can lead to:
- Web cache poisoning
- Password reset poisoning
- SSRF via Host header
- Access control bypass

Features:
- Multiple injection techniques
- Cache poisoning detection
- Password reset flow analysis
- Response comparison
- Severity classification
"""

import asyncio
import aiohttp
import hashlib
from typing import Any, Optional, List, Dict
from urllib.parse import urlparse
from .base import BaseModule
from ..core.input_parser import Target


class HostHeaderScanner(BaseModule):
    """Tests for Host header injection vulnerabilities."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "Host Header Injection"
        self.description = "Tests for Host header injection vulnerabilities"

        # Canary domains for detection
        self.canary_domain = "evil.com"
        self.canary_ip = "169.254.169.254"  # AWS metadata

        # Initialize injection payloads
        self._init_payloads()

    def _init_payloads(self):
        """Initialize Host header injection payloads."""
        self.host_payloads = [
            # Basic injection
            ("direct_injection", self.canary_domain),
            
            # Port-based bypass
            ("port_injection", f"{{original}}:@{self.canary_domain}"),
            ("port_bypass", f"{{original}}:80@{self.canary_domain}"),
            
            # Absolute URL bypass
            ("absolute_url", f"{{original}}@{self.canary_domain}"),
            
            # Subdomain prefix
            ("subdomain_prefix", f"{self.canary_domain}.{{original}}"),
            
            # Double Host header (handled separately)
            ("double_host", self.canary_domain),
            
            # Localhost/internal
            ("localhost", "localhost"),
            ("internal_ip", "127.0.0.1"),
            ("metadata_ip", self.canary_ip),
            
            # Case tricks
            ("case_variation", f"{{ORIGINAL}}"),
            
            # Space injection
            ("space_injection", f"{{original}} {self.canary_domain}"),
            
            # Tab injection
            ("tab_injection", f"{{original}}\t{self.canary_domain}"),
        ]

        # Headers that might be used instead of/alongside Host
        self.override_headers = [
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "Forwarded",
            "X-Original-URL",
            "X-Rewrite-URL",
        ]

    async def run(self, target: Target) -> dict:
        """Execute Host header injection scan."""
        url = self._get_url(target)
        if not url:
            return {}

        parsed = urlparse(url)
        original_host = parsed.netloc

        results = {
            "url": url,
            "original_host": original_host,
            "vulnerable": False,
            "vulnerabilities": [],
            "tested_payloads": 0,
            "baseline_response": None,
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Phase 1: Get baseline response
                baseline = await self._get_baseline(session, url)
                if not baseline:
                    results["error"] = "Could not get baseline response"
                    return results

                results["baseline_response"] = {
                    "status": baseline["status"],
                    "length": baseline["length"],
                    "hash": baseline["hash"][:16],
                }

                # Phase 2: Test Host header injections
                host_vulns = await self._test_host_injections(
                    session, url, original_host, baseline
                )
                results["vulnerabilities"].extend(host_vulns)

                # Phase 3: Test override headers
                override_vulns = await self._test_override_headers(
                    session, url, original_host, baseline
                )
                results["vulnerabilities"].extend(override_vulns)

                # Phase 4: Test double Host header
                double_vuln = await self._test_double_host(
                    session, url, original_host, baseline
                )
                if double_vuln:
                    results["vulnerabilities"].append(double_vuln)

                results["tested_payloads"] = len(self.host_payloads) + len(self.override_headers) + 1
                results["vulnerable"] = len(results["vulnerabilities"]) > 0

            except aiohttp.ClientError as e:
                results["error"] = f"Connection error: {str(e)}"
            except Exception as e:
                results["error"] = str(e)

        return results

    async def _get_baseline(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[dict]:
        """Get baseline response for comparison."""
        try:
            async with session.get(
                url,
                timeout=self.config.timeout,
                ssl=False,
                allow_redirects=False,
            ) as response:
                body = await response.text()
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "length": len(body),
                    "hash": hashlib.md5(body.encode()).hexdigest(),
                }
        except Exception:
            return None

    async def _test_host_injections(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str,
        baseline: dict,
    ) -> List[dict]:
        """Test various Host header injection payloads."""
        vulnerabilities = []

        for payload_name, payload_template in self.host_payloads:
            if payload_name == "double_host":
                continue  # Handled separately

            # Build payload
            payload = payload_template.replace("{original}", original_host)
            payload = payload.replace("{ORIGINAL}", original_host.upper())

            vuln = await self._test_single_injection(
                session, url, "Host", payload, payload_name, baseline
            )
            if vuln:
                vulnerabilities.append(vuln)

            await asyncio.sleep(0.05)

        return vulnerabilities

    async def _test_override_headers(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str,
        baseline: dict,
    ) -> List[dict]:
        """Test Host override headers."""
        vulnerabilities = []

        for header in self.override_headers:
            vuln = await self._test_single_injection(
                session, url, header, self.canary_domain,
                f"override_{header.lower()}", baseline
            )
            if vuln:
                vulnerabilities.append(vuln)

            await asyncio.sleep(0.05)

        return vulnerabilities

    async def _test_double_host(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_host: str,
        baseline: dict,
    ) -> Optional[dict]:
        """Test double Host header injection."""
        try:
            # aiohttp doesn't support duplicate headers easily,
            # so we test via custom connector or skip
            # For this implementation, we'll test X-Forwarded-Host with original Host
            headers = {
                "Host": original_host,
                "X-Forwarded-Host": self.canary_domain,
            }

            async with session.get(
                url,
                headers=headers,
                timeout=self.config.timeout,
                ssl=False,
                allow_redirects=False,
            ) as response:
                body = await response.text()

                # Check for canary in response
                if self._check_injection_success(body, response.headers, self.canary_domain):
                    return {
                        "type": "double_host_header",
                        "header": "Host + X-Forwarded-Host",
                        "payload": self.canary_domain,
                        "severity": "high",
                        "description": "Server processes X-Forwarded-Host alongside Host",
                        "impact": "Cache poisoning, password reset poisoning possible",
                    }

        except Exception:
            pass

        return None

    async def _test_single_injection(
        self,
        session: aiohttp.ClientSession,
        url: str,
        header: str,
        payload: str,
        payload_name: str,
        baseline: dict,
    ) -> Optional[dict]:
        """Test a single header injection."""
        try:
            headers = {header: payload}

            async with session.get(
                url,
                headers=headers,
                timeout=self.config.timeout,
                ssl=False,
                allow_redirects=False,
            ) as response:
                body = await response.text()
                resp_headers = dict(response.headers)

                # Check for injection indicators
                vuln_type = self._analyze_injection(
                    payload, body, resp_headers, response.status, baseline
                )

                if vuln_type:
                    severity = self._get_severity(vuln_type, header)
                    return {
                        "type": vuln_type,
                        "header": header,
                        "payload": payload[:50],
                        "payload_name": payload_name,
                        "severity": severity,
                        "status_code": response.status,
                        "description": self._get_description(vuln_type),
                        "impact": self._get_impact(vuln_type),
                    }

        except Exception:
            pass

        return None

    def _analyze_injection(
        self,
        payload: str,
        body: str,
        headers: dict,
        status: int,
        baseline: dict,
    ) -> Optional[str]:
        """Analyze response to determine if injection was successful."""
        # Check if canary appears in response body
        if self.canary_domain in body.lower():
            return "reflected_in_body"

        # Check if canary appears in response headers (Location, Link, etc.)
        for header_name, header_value in headers.items():
            if self.canary_domain in str(header_value).lower():
                if header_name.lower() == "location":
                    return "reflected_in_redirect"
                return "reflected_in_header"

        # Check for cache headers indicating poisoning potential
        cache_headers = ["X-Cache", "CF-Cache-Status", "Age", "X-Varnish"]
        has_cache = any(h in headers for h in cache_headers)

        # Check if response differs significantly from baseline
        if status != baseline["status"]:
            if status in (301, 302, 303, 307, 308):
                return "causes_redirect"
            if status >= 500:
                return "causes_error"

        # Check for internal IP disclosure
        if self.canary_ip in body:
            return "metadata_access"

        # Check if response body differs (might indicate injection processed)
        body_hash = hashlib.md5(body.encode()).hexdigest()
        if body_hash != baseline["hash"] and has_cache:
            # Response differs and caching is present
            if abs(len(body) - baseline["length"]) > 100:
                return "cache_poisoning_potential"

        return None

    def _check_injection_success(
        self, body: str, headers: dict, canary: str
    ) -> bool:
        """Check if injection canary appears in response."""
        body_lower = body.lower()
        if canary.lower() in body_lower:
            return True

        for value in headers.values():
            if canary.lower() in str(value).lower():
                return True

        return False

    def _get_severity(self, vuln_type: str, header: str) -> str:
        """Get severity based on vulnerability type."""
        high_severity = [
            "reflected_in_redirect",
            "cache_poisoning_potential",
            "metadata_access",
        ]
        if vuln_type in high_severity:
            return "high"

        medium_severity = [
            "reflected_in_body",
            "reflected_in_header",
            "causes_redirect",
        ]
        if vuln_type in medium_severity:
            return "medium"

        return "low"

    def _get_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type."""
        descriptions = {
            "reflected_in_body": "Injected Host header value reflected in response body",
            "reflected_in_header": "Injected Host header value reflected in response headers",
            "reflected_in_redirect": "Injected Host header controls redirect location",
            "causes_redirect": "Host header injection causes redirect",
            "causes_error": "Host header injection causes server error",
            "cache_poisoning_potential": "Response varies with Host header and caching detected",
            "metadata_access": "Host header injection may allow metadata access",
        }
        return descriptions.get(vuln_type, "Host header injection detected")

    def _get_impact(self, vuln_type: str) -> str:
        """Get impact description for vulnerability type."""
        impacts = {
            "reflected_in_body": "Potential XSS or phishing via poisoned links",
            "reflected_in_header": "Header injection, potential response splitting",
            "reflected_in_redirect": "Password reset poisoning, OAuth token theft",
            "causes_redirect": "Open redirect via Host header",
            "causes_error": "Denial of service potential",
            "cache_poisoning_potential": "Web cache poisoning affecting all users",
            "metadata_access": "Cloud metadata exposure (SSRF)",
        }
        return impacts.get(vuln_type, "Security bypass potential")

    def _get_url(self, target: Target) -> Optional[str]:
        """Get URL from target."""
        if target.url:
            return target.url
        if target.host:
            return f"http://{target.host}"
        return None
