"""
Open Redirect Scanner Module.

Detects open redirect vulnerabilities by testing common redirect parameters
with various bypass payloads.

Features:
- 30+ common redirect parameter names
- Multiple bypass techniques (protocol-relative, unicode, etc.)
- Redirect chain analysis
- External domain detection
- Severity classification
- OAuth/SSO context detection
"""

import asyncio
import aiohttp
import re
from typing import Any, Optional, List
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from .base import BaseModule
from ..core.input_parser import Target


class OpenRedirectScanner(BaseModule):
    """Detects open redirect vulnerabilities in web applications."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "Open Redirect Scanner"
        self.description = "Detects open redirect vulnerabilities"

        # Configuration
        self.max_redirects = getattr(config, 'redirect_max_hops', 5)
        self.test_limit = getattr(config, 'redirect_test_limit', 50)

        # Initialize test data
        self._init_parameters()
        self._init_payloads()

    def _init_parameters(self):
        """Initialize common redirect parameter names."""
        self.redirect_params = [
            # Standard redirect params
            "url", "redirect", "redirect_url", "redirect_uri",
            "next", "next_url", "return", "return_url", "returnUrl",
            "return_to", "returnTo", "continue", "continue_url",
            "dest", "destination", "target", "target_url",
            "redir", "rurl", "r_url",
            # OAuth/SSO related
            "callback", "callback_url", "callbackUrl",
            "redirect_to", "redirectTo", "login_url",
            "logout_url", "logout", "success_url", "successUrl",
            "fail_url", "failUrl", "error_url",
            # Link/navigation related
            "link", "linkurl", "go", "goto", "jump", "jump_to",
            "forward", "forward_url", "out", "outurl",
            "view", "file", "page", "path",
            # Less common but exploitable
            "uri", "u", "ref", "referrer", "site", "host",
            "domain", "location", "checkout_url", "image_url",
        ]

    def _init_payloads(self):
        """Initialize redirect payloads for testing."""
        # Use a canary domain that we control conceptually
        self.canary_domain = "evil.com"

        self.payloads = [
            # Protocol-relative URLs
            ("protocol_relative", f"//{self.canary_domain}"),
            ("protocol_relative_slash", f"///{self.canary_domain}"),
            ("backslash_bypass", f"/\\{self.canary_domain}"),
            ("backslash_double", f"\\/\\/{self.canary_domain}"),

            # Full URLs
            ("https_direct", f"https://{self.canary_domain}"),
            ("http_direct", f"http://{self.canary_domain}"),

            # URL encoding bypasses
            ("url_encoded", f"%2f%2f{self.canary_domain}"),
            ("double_encoded", f"%252f%252f{self.canary_domain}"),

            # Unicode/special char bypasses
            ("null_byte", f"//{self.canary_domain}%00"),
            ("tab_bypass", f"//{self.canary_domain}%09"),
            ("newline_bypass", f"//{self.canary_domain}%0a"),

            # @ symbol tricks (user:pass@host)
            ("at_symbol", f"https://legitimate.com@{self.canary_domain}"),
            ("at_bypass", f"//{self.canary_domain}%40legitimate.com"),

            # Subdomain confusion
            ("subdomain_prefix", f"https://{self.canary_domain}.legitimate.com"),
            ("dot_bypass", f"//{self.canary_domain}%2elegitimate.com"),

            # Fragment/query tricks
            ("fragment_bypass", f"//{self.canary_domain}#legitimate.com"),
            ("query_bypass", f"//{self.canary_domain}?legitimate.com"),

            # Mixed case
            ("mixed_proto", f"hTTps://{self.canary_domain}"),
            ("javascript_url", f"javascript:location='//{self.canary_domain}'"),

            # Data URI (rare but possible)
            ("data_redirect", f"data:text/html,<script>location='{self.canary_domain}'</script>"),
        ]

    async def run(self, target: Target) -> dict:
        """Execute open redirect vulnerability scan."""
        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "vulnerable": False,
            "vulnerabilities": [],
            "tested_params": 0,
            "tested_payloads": 0,
            "oauth_context": False,
            "recommendations": [],
        }

        async with aiohttp.ClientSession() as session:
            try:
                # First, check if URL is reachable and get base response
                base_response = await self._get_base_response(session, url)
                if not base_response:
                    results["error"] = "Target not reachable"
                    return results

                # Detect OAuth/SSO context
                results["oauth_context"] = self._detect_oauth_context(url, base_response)

                # Test each parameter with payloads
                vulnerabilities = await self._test_redirects(session, url)
                
                if vulnerabilities:
                    results["vulnerable"] = True
                    results["vulnerabilities"] = vulnerabilities
                    results["recommendations"] = self._generate_recommendations(vulnerabilities)

                results["tested_params"] = len(self.redirect_params)
                results["tested_payloads"] = len(self.payloads)

            except aiohttp.ClientError as e:
                results["error"] = f"Connection error: {str(e)}"
            except Exception as e:
                results["error"] = str(e)

        return results

    async def _get_base_response(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[dict]:
        """Get base response for comparison."""
        try:
            async with session.get(
                url,
                timeout=self.config.timeout,
                ssl=False,
                allow_redirects=False,
            ) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "url": str(response.url),
                }
        except Exception:
            return None

    def _detect_oauth_context(self, url: str, response: dict) -> bool:
        """Detect if URL is in OAuth/SSO context (higher severity)."""
        url_lower = url.lower()
        oauth_indicators = [
            "oauth", "auth", "login", "signin", "sso",
            "callback", "redirect_uri", "client_id",
            "response_type", "scope", "state",
        ]
        return any(indicator in url_lower for indicator in oauth_indicators)

    async def _test_redirects(
        self, session: aiohttp.ClientSession, url: str
    ) -> List[dict]:
        """Test all parameter/payload combinations."""
        vulnerabilities = []
        test_count = 0

        # Parse base URL
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Existing query params
        existing_params = parse_qs(parsed.query)

        for param in self.redirect_params:
            if test_count >= self.test_limit:
                break

            for payload_name, payload in self.payloads:
                if test_count >= self.test_limit:
                    break

                test_count += 1

                # Build test URL
                test_params = existing_params.copy()
                test_params[param] = [payload]
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"

                # Test the redirect
                vuln = await self._check_redirect(
                    session, test_url, param, payload, payload_name
                )

                if vuln:
                    vulnerabilities.append(vuln)

                # Small delay to avoid rate limiting
                await asyncio.sleep(0.05)

        return vulnerabilities

    async def _check_redirect(
        self,
        session: aiohttp.ClientSession,
        test_url: str,
        param: str,
        payload: str,
        payload_type: str,
    ) -> Optional[dict]:
        """Check if a specific URL triggers an open redirect."""
        try:
            redirect_chain = []

            async with session.get(
                test_url,
                timeout=self.config.timeout,
                ssl=False,
                allow_redirects=False,
            ) as response:
                status = response.status

                # Check for redirect status codes
                if status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")

                    if self._is_external_redirect(location, test_url):
                        # Follow the redirect chain
                        redirect_chain = await self._follow_redirects(
                            session, location, test_url
                        )

                        severity = self._calculate_severity(
                            param, payload_type, redirect_chain
                        )

                        return {
                            "param": param,
                            "payload": payload,
                            "payload_type": payload_type,
                            "status_code": status,
                            "location": location,
                            "redirect_chain": redirect_chain,
                            "severity": severity,
                            "test_url": test_url[:100],  # Truncate for display
                        }

                # Check for meta refresh or JavaScript redirects in body
                if status == 200:
                    try:
                        body = await response.text()
                        body = body[:10000]  # Limit body size

                        meta_redirect = self._check_meta_redirect(body)
                        if meta_redirect and self._is_external_redirect(meta_redirect, test_url):
                            return {
                                "param": param,
                                "payload": payload,
                                "payload_type": payload_type,
                                "status_code": status,
                                "location": meta_redirect,
                                "redirect_type": "meta_refresh",
                                "severity": "medium",
                                "test_url": test_url[:100],
                            }

                        js_redirect = self._check_js_redirect(body)
                        if js_redirect and self._is_external_redirect(js_redirect, test_url):
                            return {
                                "param": param,
                                "payload": payload,
                                "payload_type": payload_type,
                                "status_code": status,
                                "location": js_redirect,
                                "redirect_type": "javascript",
                                "severity": "medium",
                                "test_url": test_url[:100],
                            }
                    except Exception:
                        pass

        except Exception:
            pass

        return None

    def _is_external_redirect(self, location: str, original_url: str) -> bool:
        """Check if redirect goes to an external domain."""
        if not location:
            return False

        # Normalize the location
        location_lower = location.lower().strip()

        # Check for our canary domain
        if self.canary_domain in location_lower:
            return True

        # Protocol-relative URLs
        if location_lower.startswith("//"):
            # Extract domain from protocol-relative URL
            try:
                domain = location_lower[2:].split("/")[0].split("?")[0].split("#")[0]
                original_domain = urlparse(original_url).netloc
                return domain != original_domain
            except Exception:
                pass

        # Full URLs
        if location_lower.startswith(("http://", "https://")):
            try:
                location_domain = urlparse(location).netloc
                original_domain = urlparse(original_url).netloc
                return location_domain != original_domain
            except Exception:
                pass

        # JavaScript URLs
        if location_lower.startswith("javascript:"):
            return True

        return False

    async def _follow_redirects(
        self, session: aiohttp.ClientSession, start_url: str, original_url: str
    ) -> List[str]:
        """Follow redirect chain to final destination."""
        chain = [start_url]
        current_url = start_url
        hops = 0

        while hops < self.max_redirects:
            try:
                # Handle relative URLs
                if not current_url.startswith(("http://", "https://")):
                    if current_url.startswith("//"):
                        current_url = f"https:{current_url}"
                    else:
                        current_url = urljoin(original_url, current_url)

                async with session.get(
                    current_url,
                    timeout=self.config.timeout,
                    ssl=False,
                    allow_redirects=False,
                ) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if location and location not in chain:
                            chain.append(location)
                            current_url = location
                            hops += 1
                        else:
                            break
                    else:
                        break
            except Exception:
                break

        return chain

    def _check_meta_redirect(self, body: str) -> Optional[str]:
        """Check for meta refresh redirect in HTML body."""
        patterns = [
            r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=([^"\'>\s]+)',
            r'<meta[^>]*content=["\']?\d+;\s*url=([^"\'>\s]+)[^>]*http-equiv=["\']?refresh',
        ]

        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _check_js_redirect(self, body: str) -> Optional[str]:
        """Check for JavaScript redirect in HTML body."""
        patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                url = match.group(1)
                # Check if it contains our canary or is external
                if self.canary_domain in url or url.startswith(("//", "http")):
                    return url

        return None

    def _calculate_severity(
        self, param: str, payload_type: str, redirect_chain: List[str]
    ) -> str:
        """Calculate vulnerability severity."""
        # OAuth-related params are high severity
        oauth_params = ["redirect_uri", "callback", "callback_url", "return_url"]
        if param.lower() in oauth_params:
            return "high"

        # Direct protocol bypasses are high
        high_risk_payloads = ["https_direct", "http_direct", "protocol_relative"]
        if payload_type in high_risk_payloads:
            return "high"

        # Encoding bypasses are medium
        medium_risk_payloads = ["url_encoded", "backslash_bypass", "at_symbol"]
        if payload_type in medium_risk_payloads:
            return "medium"

        return "low"

    def _generate_recommendations(self, vulnerabilities: List[dict]) -> List[dict]:
        """Generate remediation recommendations."""
        recommendations = []

        high_count = len([v for v in vulnerabilities if v["severity"] == "high"])
        
        if high_count > 0:
            recommendations.append({
                "priority": "critical",
                "recommendation": "Implement allowlist validation for redirect URLs",
            })

        recommendations.extend([
            {
                "priority": "high",
                "recommendation": "Validate redirect URLs against a list of allowed domains",
            },
            {
                "priority": "high", 
                "recommendation": "Use relative paths instead of full URLs for internal redirects",
            },
            {
                "priority": "medium",
                "recommendation": "Implement URL parsing to extract and validate the target domain",
            },
            {
                "priority": "medium",
                "recommendation": "Add user confirmation page before redirecting to external URLs",
            },
        ])

        return recommendations

    def _get_url(self, target: Target) -> Optional[str]:
        """Get URL from target."""
        if target.url:
            return target.url
        if target.host:
            return f"http://{target.host}"
        return None
