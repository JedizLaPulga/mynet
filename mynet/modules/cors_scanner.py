"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Scanner.

Detects CORS misconfigurations that could lead to:
- Credential theft via origin reflection
- Null origin bypass attacks
- Subdomain trust exploitation
- Wildcard misconfiguration issues
"""

import asyncio
import aiohttp
import re
from urllib.parse import urlparse
from typing import Any, Optional
from .base import BaseModule
from ..core.input_parser import Target


class CORSScanner(BaseModule):
    """Scans for CORS misconfiguration vulnerabilities."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "CORS Scanner"
        self.description = "Detects CORS misconfiguration vulnerabilities"

        # Test origins to check
        self.test_origins = []

        # Vulnerability severity levels
        self.severity_levels = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }

    async def run(self, target: Target) -> dict:
        """Execute CORS vulnerability scan."""
        url = self._get_url(target)
        if not url:
            return {}

        # Build test origins based on target
        self._build_test_origins(url)

        results = {
            "vulnerable": False,
            "vulnerabilities": [],
            "total_tests": 0,
            "cors_headers": {},
            "recommendations": [],
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Phase 1: Check baseline CORS headers
                baseline = await self._check_baseline(session, url)
                results["cors_headers"] = baseline.get("headers", {})

                # Phase 2: Test origin reflection
                reflection_vulns = await self._test_origin_reflection(session, url)
                results["vulnerabilities"].extend(reflection_vulns)

                # Phase 3: Test null origin
                null_vulns = await self._test_null_origin(session, url)
                results["vulnerabilities"].extend(null_vulns)

                # Phase 4: Test wildcard with credentials
                wildcard_vulns = await self._test_wildcard_credentials(session, url)
                results["vulnerabilities"].extend(wildcard_vulns)

                # Phase 5: Test subdomain trust
                subdomain_vulns = await self._test_subdomain_trust(session, url)
                results["vulnerabilities"].extend(subdomain_vulns)

                # Phase 6: Test special origins
                special_vulns = await self._test_special_origins(session, url)
                results["vulnerabilities"].extend(special_vulns)

                # Phase 7: Test preflight bypass
                preflight_vulns = await self._test_preflight_bypass(session, url)
                results["vulnerabilities"].extend(preflight_vulns)

                # Calculate totals and recommendations
                results["total_tests"] = len(self.test_origins) + 6  # +6 for special tests
                results["vulnerable"] = len(results["vulnerabilities"]) > 0
                results["recommendations"] = self._generate_recommendations(results["vulnerabilities"])

            except aiohttp.ClientError as e:
                results["error"] = f"Connection error: {str(e)}"
            except Exception as e:
                results["error"] = str(e)

        return results

    def _build_test_origins(self, url: str):
        """Build list of test origins based on target URL."""
        parsed = urlparse(url)
        domain = parsed.netloc
        scheme = parsed.scheme

        # Extract base domain parts
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain

        self.test_origins = [
            # Exact reflection test
            {
                "origin": f"{scheme}://evil.com",
                "type": "arbitrary_origin",
                "description": "Arbitrary external origin",
            },
            # Subdomain variations
            {
                "origin": f"{scheme}://evil.{base_domain}",
                "type": "subdomain_injection",
                "description": "Attacker-controlled subdomain",
            },
            {
                "origin": f"{scheme}://sub.evil.com",
                "type": "arbitrary_subdomain",
                "description": "Arbitrary subdomain origin",
            },
            # Suffix/prefix attacks
            {
                "origin": f"{scheme}://{base_domain}.evil.com",
                "type": "domain_suffix",
                "description": "Target domain as suffix",
            },
            {
                "origin": f"{scheme}://evil{base_domain}",
                "type": "domain_prefix",
                "description": "Target domain with evil prefix",
            },
            {
                "origin": f"{scheme}://{base_domain}evil.com",
                "type": "domain_suffix_no_dot",
                "description": "Target domain suffix without dot",
            },
            # Protocol variations
            {
                "origin": f"http://{domain}",
                "type": "protocol_downgrade",
                "description": "HTTP protocol downgrade (if HTTPS)",
            },
            # Special characters
            {
                "origin": f"{scheme}://{domain}%60.evil.com",
                "type": "encoded_char",
                "description": "URL-encoded backtick bypass",
            },
            {
                "origin": f"{scheme}://{domain}_.evil.com",
                "type": "underscore_bypass",
                "description": "Underscore character bypass",
            },
        ]

    async def _check_baseline(
        self, session: aiohttp.ClientSession, url: str
    ) -> dict:
        """Check baseline CORS configuration without Origin header."""
        result = {"headers": {}}

        try:
            async with session.get(
                url, timeout=self.config.timeout, ssl=False
            ) as response:
                headers = response.headers

                # Extract CORS-related headers
                cors_headers = [
                    "Access-Control-Allow-Origin",
                    "Access-Control-Allow-Credentials",
                    "Access-Control-Allow-Methods",
                    "Access-Control-Allow-Headers",
                    "Access-Control-Expose-Headers",
                    "Access-Control-Max-Age",
                ]

                for header in cors_headers:
                    if header in headers:
                        result["headers"][header] = headers[header]

        except Exception:
            pass

        return result

    async def _test_origin_reflection(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test if the server reflects arbitrary origins."""
        vulnerabilities = []

        for test in self.test_origins:
            origin = test["origin"]

            try:
                headers = {"Origin": origin}
                async with session.get(
                    url, headers=headers, timeout=self.config.timeout, ssl=False
                ) as response:
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")

                    # Check for origin reflection
                    if acao == origin:
                        severity = "critical" if acac.lower() == "true" else "high"
                        vulnerabilities.append({
                            "type": "origin_reflection",
                            "test_type": test["type"],
                            "origin_sent": origin,
                            "origin_reflected": acao,
                            "credentials_allowed": acac.lower() == "true",
                            "severity": severity,
                            "description": f"Server reflects {test['description']}",
                            "impact": self._get_impact(severity, acac.lower() == "true"),
                        })

            except Exception:
                continue

        return vulnerabilities

    async def _test_null_origin(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test if null origin is allowed (sandboxed iframe attack)."""
        vulnerabilities = []

        try:
            headers = {"Origin": "null"}
            async with session.get(
                url, headers=headers, timeout=self.config.timeout, ssl=False
            ) as response:
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "null":
                    severity = "critical" if acac.lower() == "true" else "high"
                    vulnerabilities.append({
                        "type": "null_origin",
                        "test_type": "null_origin_allowed",
                        "origin_sent": "null",
                        "origin_reflected": acao,
                        "credentials_allowed": acac.lower() == "true",
                        "severity": severity,
                        "description": "Server allows null origin (sandboxed iframe attack possible)",
                        "impact": "Attacker can use sandboxed iframe to steal data with null origin",
                    })

        except Exception:
            pass

        return vulnerabilities

    async def _test_wildcard_credentials(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test for wildcard with credentials misconfiguration."""
        vulnerabilities = []

        try:
            headers = {"Origin": "https://evil.com"}
            async with session.get(
                url, headers=headers, timeout=self.config.timeout, ssl=False
            ) as response:
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                # Wildcard with credentials is a misconfiguration
                if acao == "*" and acac.lower() == "true":
                    vulnerabilities.append({
                        "type": "wildcard_credentials",
                        "test_type": "wildcard_with_credentials",
                        "origin_sent": "https://evil.com",
                        "origin_reflected": acao,
                        "credentials_allowed": True,
                        "severity": "high",
                        "description": "Wildcard (*) with credentials is technically invalid but some browsers may process it",
                        "impact": "Potential credential exposure depending on browser behavior",
                    })

                # Just wildcard (informational)
                elif acao == "*":
                    vulnerabilities.append({
                        "type": "wildcard_origin",
                        "test_type": "wildcard_without_credentials",
                        "origin_sent": "https://evil.com",
                        "origin_reflected": acao,
                        "credentials_allowed": False,
                        "severity": "info",
                        "description": "Wildcard origin configured (may be intentional for public APIs)",
                        "impact": "No direct credential theft, but data may be accessible cross-origin",
                    })

        except Exception:
            pass

        return vulnerabilities

    async def _test_subdomain_trust(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test for overly permissive subdomain trust."""
        vulnerabilities = []
        parsed = urlparse(url)
        domain = parsed.netloc

        # Test if any subdomain is trusted
        test_subdomains = [
            f"https://attacker.{domain}",
            f"https://xss.{domain}",
            f"https://compromised.{domain}",
        ]

        for subdomain in test_subdomains:
            try:
                headers = {"Origin": subdomain}
                async with session.get(
                    url, headers=headers, timeout=self.config.timeout, ssl=False
                ) as response:
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == subdomain:
                        vulnerabilities.append({
                            "type": "subdomain_trust",
                            "test_type": "excessive_subdomain_trust",
                            "origin_sent": subdomain,
                            "origin_reflected": acao,
                            "credentials_allowed": acac.lower() == "true",
                            "severity": "medium",
                            "description": "Server trusts arbitrary subdomains (XSS on subdomain = full compromise)",
                            "impact": "If any subdomain has XSS, attacker can steal credentials from main domain",
                        })
                        break  # One is enough to prove the issue

            except Exception:
                continue

        return vulnerabilities

    async def _test_special_origins(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test special/edge case origins."""
        vulnerabilities = []

        special_origins = [
            ("file://", "file_protocol", "File protocol origin"),
            ("chrome-extension://abc", "chrome_extension", "Chrome extension origin"),
            ("moz-extension://abc", "firefox_extension", "Firefox extension origin"),
            ("data:", "data_uri", "Data URI origin"),
        ]

        for origin, test_type, description in special_origins:
            try:
                headers = {"Origin": origin}
                async with session.get(
                    url, headers=headers, timeout=self.config.timeout, ssl=False
                ) as response:
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == origin or acao == "*":
                        vulnerabilities.append({
                            "type": "special_origin",
                            "test_type": test_type,
                            "origin_sent": origin,
                            "origin_reflected": acao,
                            "credentials_allowed": acac.lower() == "true",
                            "severity": "medium",
                            "description": f"Server allows {description}",
                            "impact": f"May allow attacks from {description} context",
                        })

            except Exception:
                continue

        return vulnerabilities

    async def _test_preflight_bypass(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test for preflight request bypass issues."""
        vulnerabilities = []

        try:
            # Test OPTIONS preflight
            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header",
            }

            async with session.options(
                url, headers=headers, timeout=self.config.timeout, ssl=False
            ) as response:
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acam = response.headers.get("Access-Control-Allow-Methods", "")
                acah = response.headers.get("Access-Control-Allow-Headers", "")

                # Check for overly permissive preflight response
                dangerous_methods = ["PUT", "DELETE", "PATCH"]
                allowed_methods = [m.strip() for m in acam.split(",")] if acam else []

                dangerous_allowed = [m for m in dangerous_methods if m in allowed_methods]

                if acao == "https://evil.com" and dangerous_allowed:
                    vulnerabilities.append({
                        "type": "preflight_bypass",
                        "test_type": "dangerous_methods_allowed",
                        "origin_sent": "https://evil.com",
                        "origin_reflected": acao,
                        "methods_allowed": allowed_methods,
                        "dangerous_methods": dangerous_allowed,
                        "severity": "high",
                        "description": f"Preflight allows dangerous methods: {', '.join(dangerous_allowed)}",
                        "impact": "Attacker can perform state-changing operations cross-origin",
                    })

                # Check for wildcard headers
                if "*" in acah or acao == "https://evil.com":
                    if "*" in acah:
                        vulnerabilities.append({
                            "type": "preflight_bypass",
                            "test_type": "wildcard_headers",
                            "origin_sent": "https://evil.com",
                            "headers_allowed": acah,
                            "severity": "medium",
                            "description": "Preflight allows any custom headers",
                            "impact": "May allow bypassing security controls via custom headers",
                        })

        except Exception:
            pass

        return vulnerabilities

    def _get_impact(self, severity: str, credentials: bool) -> str:
        """Get impact description based on severity and credentials."""
        if credentials:
            return "Full account takeover possible - attacker can steal authenticated user's data and session"
        elif severity == "high":
            return "Cross-origin data theft possible for unauthenticated resources"
        else:
            return "Potential information disclosure"

    def _generate_recommendations(self, vulnerabilities: list) -> list:
        """Generate security recommendations based on found vulnerabilities."""
        recommendations = []
        vuln_types = set(v["type"] for v in vulnerabilities)

        if "origin_reflection" in vuln_types:
            recommendations.append({
                "priority": "critical",
                "recommendation": "Do not reflect arbitrary origins. Use a strict whitelist of allowed origins.",
            })

        if "null_origin" in vuln_types:
            recommendations.append({
                "priority": "high",
                "recommendation": "Explicitly reject 'null' origin. Never whitelist null as a valid origin.",
            })

        if "wildcard_credentials" in vuln_types or "wildcard_origin" in vuln_types:
            recommendations.append({
                "priority": "high",
                "recommendation": "Avoid using wildcard (*). If public API, ensure no sensitive data is exposed.",
            })

        if "subdomain_trust" in vuln_types:
            recommendations.append({
                "priority": "medium",
                "recommendation": "Use explicit subdomain whitelist instead of regex patterns. Audit all subdomains for XSS.",
            })

        if "preflight_bypass" in vuln_types:
            recommendations.append({
                "priority": "high",
                "recommendation": "Restrict allowed methods and headers in preflight responses. Only allow what's necessary.",
            })

        if not recommendations:
            recommendations.append({
                "priority": "info",
                "recommendation": "CORS configuration appears secure. Continue to audit when making changes.",
            })

        return recommendations

    def _get_url(self, target: Target) -> Optional[str]:
        """Extract URL from target."""
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
