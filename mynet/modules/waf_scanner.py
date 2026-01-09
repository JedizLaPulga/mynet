"""
WAF (Web Application Firewall) Detection Module.

Detects and fingerprints WAFs using passive signature analysis,
active probing with attack payloads, and block response detection.
"""

import aiohttp
import re
from typing import Any, Optional
from .base import BaseModule
from ..core.input_parser import Target


class WAFScanner(BaseModule):
    """Detects Web Application Firewalls through multiple detection techniques."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "WAF Detection"
        self.description = "Detects Web Application Firewalls (Cloudflare, AWS, Akamai, etc.)"

        # Signatures: (Name, Location, Pattern)
        # Location: 'headers', 'cookie', 'server', 'body'
        self.signatures = [
            # Cloudflare
            ("Cloudflare", "headers", r"CF-RAY"),
            ("Cloudflare", "headers", r"cf-cache-status"),
            ("Cloudflare", "server", r"cloudflare"),
            ("Cloudflare", "cookie", r"__cfduid|__cf_bm"),
            ("Cloudflare", "body", r"cloudflare|cf-error"),
            # AWS
            ("AWS WAF", "headers", r"X-Amz-Cf-Id"),
            ("AWS WAF", "headers", r"X-Amz-Cf-Pop"),
            ("AWS WAF", "headers", r"X-CDN"),
            ("AWS WAF", "body", r"aws\.amazon\.com"),
            # Akamai
            ("Akamai", "server", r"AkamaiGHost"),
            ("Akamai", "headers", r"X-Akamai-Transformed"),
            ("Akamai", "headers", r"Akamai-Origin-Hop"),
            ("Akamai", "body", r"akamaiedge\.net"),
            # Incapsula / Imperva
            ("Incapsula", "headers", r"X-Iinfo"),
            ("Incapsula", "headers", r"X-CDN: Incapsula"),
            ("Incapsula", "cookie", r"incap_ses|visid_incap"),
            ("Incapsula", "body", r"incapsula incident"),
            # F5 BIG-IP
            ("F5 BIG-IP", "cookie", r"^TS[0-9a-f]{8}"),
            ("F5 BIG-IP", "cookie", r"BigIP"),
            ("F5 BIG-IP", "server", r"BigIP|BIG-IP"),
            # Imperva
            ("Imperva", "headers", r"X-CDN: Incapsula"),
            ("Imperva", "body", r"imperva"),
            # Barracuda
            ("Barracuda", "cookie", r"^barra_counter_session"),
            ("Barracuda", "headers", r"barra"),
            # Sucuri
            ("Sucuri", "server", r"Sucuri"),
            ("Sucuri", "headers", r"X-Sucuri-ID"),
            ("Sucuri", "body", r"sucuri\.net|cloudproxy"),
            # ModSecurity
            ("ModSecurity", "server", r"mod_security|NOYB"),
            ("ModSecurity", "headers", r"X-Mod-Security"),
            ("ModSecurity", "body", r"mod_security|modsecurity"),
            # Fortinet FortiWeb
            ("FortiWeb", "headers", r"FORTIWAFSID"),
            ("FortiWeb", "cookie", r"cookiesession1"),
            ("FortiWeb", "body", r"fortigate|fortinet"),
            # Citrix NetScaler
            ("Citrix NetScaler", "headers", r"ns_af"),
            ("Citrix NetScaler", "cookie", r"citrix_ns_id|NSC_"),
            ("Citrix NetScaler", "server", r"NetScaler"),
            # DDoS-Guard
            ("DDoS-Guard", "server", r"ddos-guard"),
            ("DDoS-Guard", "headers", r"X-DDoS-Protection"),
            ("DDoS-Guard", "cookie", r"__ddg"),
            # Wordfence (WordPress)
            ("Wordfence", "body", r"wordfence|wfwaf"),
            ("Wordfence", "headers", r"wf-"),
            # StackPath
            ("StackPath", "headers", r"X-SP-"),
            ("StackPath", "server", r"StackPath"),
            # Fastly
            ("Fastly", "headers", r"X-Fastly-Request-ID"),
            ("Fastly", "headers", r"Fastly-Debug-"),
            ("Fastly", "server", r"Fastly"),
            # Varnish
            ("Varnish", "headers", r"X-Varnish"),
            ("Varnish", "server", r"Varnish"),
            ("Varnish", "headers", r"Via:.*varnish"),
            # KeyCDN
            ("KeyCDN", "server", r"keycdn"),
            ("KeyCDN", "headers", r"X-Edge-"),
            # Reblaze
            ("Reblaze", "cookie", r"rbzid"),
            ("Reblaze", "headers", r"X-Reblaze-"),
            # Comodo
            ("Comodo WAF", "server", r"Protected by COMODO"),
            # DenyAll
            ("DenyAll", "cookie", r"sessioncookie"),
            # SonicWall
            ("SonicWall", "server", r"SonicWALL"),
        ]

        # Attack payloads for active probing
        self.probe_payloads = [
            # SQL Injection patterns
            ("SQLi", "?id=1' OR '1'='1"),
            ("SQLi", "?id=1; DROP TABLE users--"),
            ("SQLi", "?id=UNION SELECT NULL,NULL,NULL--"),
            # XSS patterns
            ("XSS", "?q=<script>alert('xss')</script>"),
            ("XSS", "?q=<img src=x onerror=alert(1)>"),
            ("XSS", "?q=javascript:alert(1)"),
            # Path traversal
            ("LFI", "/../../../etc/passwd"),
            ("LFI", "?file=....//....//etc/passwd"),
            # Command injection
            ("RCE", "?cmd=;cat /etc/passwd"),
            ("RCE", "?cmd=|whoami"),
        ]

        # Block response indicators
        self.block_indicators = [
            (r"access denied", "Access Denied"),
            (r"blocked", "Blocked"),
            (r"forbidden", "Forbidden"),
            (r"request rejected", "Request Rejected"),
            (r"security violation", "Security Violation"),
            (r"attack detected", "Attack Detected"),
            (r"malicious", "Malicious Request"),
            (r"captcha", "Captcha Challenge"),
            (r"human verification", "Human Verification"),
            (r"bot detected", "Bot Detection"),
            (r"rate limit", "Rate Limited"),
            (r"too many requests", "Rate Limited"),
        ]

        # Bypass hints for detected WAFs
        self.bypass_hints = {
            "Cloudflare": [
                "Try finding origin IP via historical DNS records",
                "Check for subdomain that bypasses Cloudflare",
                "Use Cloudflare-specific headers manipulation",
            ],
            "AWS WAF": [
                "Test for case variation in payloads",
                "Try Unicode/encoding bypass techniques",
                "Check for method-based inconsistencies",
            ],
            "Akamai": [
                "Test chunked transfer encoding",
                "Try parameter pollution techniques",
                "Check for HTTP/2 specific bypasses",
            ],
            "ModSecurity": [
                "Check paranoia level (may allow some payloads)",
                "Test for rule ID specific bypasses",
                "Try alternative encoding schemes",
            ],
            "Incapsula": [
                "Check for backend IP disclosure",
                "Test with mobile user agents",
                "Try origin IP via email headers",
            ],
            "F5 BIG-IP": [
                "Test for ASM policy weaknesses",
                "Check cookie manipulation",
                "Try HTTP smuggling techniques",
            ],
            "Wordfence": [
                "Check for whitelisted IPs/user agents",
                "Test with wp-admin paths",
                "Try JSON-based payloads",
            ],
        }

    async def run(self, target: Target) -> dict:
        """Execute WAF detection scan."""
        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "detected": False,
            "wafs": [],
            "confidence": 0,
            "detection_methods": [],
            "block_behavior": None,
            "bypass_hints": [],
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Phase 1: Passive detection via normal request
                passive_wafs, passive_matches = await self._passive_detection(session, url)

                # Phase 2: Active probing with attack payloads
                active_wafs, block_info = await self._active_probe(session, url)

                # Phase 3: Multi-method testing
                method_wafs = await self._multi_method_test(session, url)

                # Combine all detected WAFs
                all_wafs = passive_wafs | active_wafs | method_wafs

                if all_wafs:
                    results["detected"] = True
                    results["wafs"] = list(all_wafs)
                    results["confidence"] = self._calculate_confidence(
                        passive_matches, len(active_wafs) > 0, len(method_wafs) > 0
                    )
                    results["detection_methods"] = self._get_detection_methods(
                        passive_wafs, active_wafs, method_wafs
                    )
                    results["bypass_hints"] = self._get_bypass_hints(all_wafs)

                if block_info:
                    results["block_behavior"] = block_info

            except aiohttp.ClientError as e:
                results["error"] = f"Connection error: {str(e)}"
            except Exception as e:
                results["error"] = str(e)

        return results

    async def _passive_detection(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[set, int]:
        """Detect WAF through passive signature analysis."""
        found_wafs = set()
        match_count = 0

        try:
            async with session.get(
                url, timeout=self.config.timeout, ssl=False
            ) as response:
                headers = response.headers
                cookies = response.cookies
                server_header = headers.get("Server", "")

                # Read body for signature matching (limit to 50KB)
                body = ""
                try:
                    body = await response.text()
                    body = body[:51200]
                except Exception:
                    pass

                for name, loc, pattern in self.signatures:
                    if self._check_signature(loc, pattern, headers, cookies, server_header, body):
                        found_wafs.add(name)
                        match_count += 1

        except Exception:
            pass

        return found_wafs, match_count

    def _check_signature(
        self,
        location: str,
        pattern: str,
        headers: Any,
        cookies: Any,
        server: str,
        body: str,
    ) -> bool:
        """Check if a signature matches in the specified location."""
        try:
            if location == "headers":
                for h_name, h_val in headers.items():
                    if re.search(pattern, h_name, re.IGNORECASE) or re.search(
                        pattern, h_val, re.IGNORECASE
                    ):
                        return True

            elif location == "server":
                if re.search(pattern, server, re.IGNORECASE):
                    return True

            elif location == "cookie":
                for cookie in cookies:
                    if re.search(pattern, cookie, re.IGNORECASE):
                        return True

            elif location == "body":
                if re.search(pattern, body, re.IGNORECASE):
                    return True

        except re.error:
            pass

        return False

    async def _active_probe(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[set, Optional[dict]]:
        """Actively probe for WAF by sending attack payloads."""
        found_wafs = set()
        block_info = None

        # Get baseline response
        baseline_status = None
        try:
            async with session.get(url, timeout=self.config.timeout, ssl=False) as resp:
                baseline_status = resp.status
        except Exception:
            return found_wafs, block_info

        # Test with attack payloads
        for attack_type, payload in self.probe_payloads[:5]:  # Limit probes
            probe_url = url.rstrip("/") + payload
            try:
                async with session.get(
                    probe_url, timeout=self.config.timeout, ssl=False
                ) as response:
                    status = response.status

                    # WAF typically returns 403, 406, 429, or custom codes
                    if status in (403, 406, 429, 503) and baseline_status not in (
                        403, 406, 429, 503
                    ):
                        body = ""
                        try:
                            body = await response.text()
                            body = body[:10240]
                        except Exception:
                            pass

                        # Check for WAF signatures in block page
                        for name, loc, pattern in self.signatures:
                            if loc == "body" and re.search(pattern, body, re.IGNORECASE):
                                found_wafs.add(name)

                        # Analyze block message
                        block_type = self._detect_block_type(body)
                        if block_type and not block_info:
                            block_info = {
                                "trigger": attack_type,
                                "status_code": status,
                                "block_type": block_type,
                            }

            except Exception:
                continue

        return found_wafs, block_info

    def _detect_block_type(self, body: str) -> Optional[str]:
        """Identify the type of block message in response body."""
        body_lower = body.lower()
        for pattern, block_type in self.block_indicators:
            if re.search(pattern, body_lower):
                return block_type
        return None

    async def _multi_method_test(
        self, session: aiohttp.ClientSession, url: str
    ) -> set:
        """Test different HTTP methods for WAF detection."""
        found_wafs = set()
        methods = ["POST", "PUT", "DELETE", "OPTIONS"]

        for method in methods:
            try:
                async with session.request(
                    method, url, timeout=self.config.timeout, ssl=False
                ) as response:
                    # Some WAFs block non-GET methods differently
                    if response.status in (403, 405, 406):
                        headers = response.headers
                        server = headers.get("Server", "")

                        for name, loc, pattern in self.signatures:
                            if loc == "server" and re.search(pattern, server, re.IGNORECASE):
                                found_wafs.add(name)
                            elif loc == "headers":
                                for h_name, h_val in headers.items():
                                    if re.search(pattern, h_name, re.IGNORECASE) or re.search(
                                        pattern, h_val, re.IGNORECASE
                                    ):
                                        found_wafs.add(name)

            except Exception:
                continue

        return found_wafs

    def _calculate_confidence(
        self, passive_matches: int, active_detected: bool, method_detected: bool
    ) -> int:
        """Calculate detection confidence score (0-100)."""
        score = 0

        # Passive signature matches
        if passive_matches >= 3:
            score += 50
        elif passive_matches >= 2:
            score += 35
        elif passive_matches >= 1:
            score += 20

        # Active probing detected WAF
        if active_detected:
            score += 30

        # Multi-method testing confirmed
        if method_detected:
            score += 20

        return min(score, 100)

    def _get_detection_methods(
        self, passive_wafs: set, active_wafs: set, method_wafs: set
    ) -> list:
        """Return list of methods that detected WAFs."""
        methods = []
        if passive_wafs:
            methods.append("passive_signatures")
        if active_wafs:
            methods.append("active_probing")
        if method_wafs:
            methods.append("method_testing")
        return methods

    def _get_bypass_hints(self, wafs: set) -> list:
        """Get bypass hints for detected WAFs."""
        hints = []
        for waf in wafs:
            if waf in self.bypass_hints:
                hints.extend(self.bypass_hints[waf])
        return hints

    def _get_url(self, target: Target) -> Optional[str]:
        """Extract URL from target."""
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
