"""
WAF (Web Application Firewall) Detection Module.

Detects and fingerprints WAFs using passive signature analysis,
active probing with attack payloads, and block response detection.

Features:
- 40+ WAF signature detection
- Active probing with customizable payloads
- Bypass hint suggestions
- Block response analysis
- Multi-method HTTP testing
- Confidence scoring
- Rate limiting for stealth
- Evasion mode with bypass testing
- Stealth mode for reduced detection
- Custom payload file support
"""

import asyncio
import aiohttp
import re
import json
from pathlib import Path
from typing import Any, Optional
from .base import BaseModule
from ..core.input_parser import Target


class WAFScanner(BaseModule):
    """Detects Web Application Firewalls through multiple detection techniques."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "WAF Detection"
        self.description = "Detects Web Application Firewalls (Cloudflare, AWS, Akamai, etc.)"

        # Configuration options
        self.rate_limit_delay = getattr(config, 'waf_rate_limit', 0.5)  # seconds between requests
        self.stealth_mode = getattr(config, 'waf_stealth', False)
        self.evasion_mode = getattr(config, 'waf_evasion', False)
        self.custom_payload_file = getattr(config, 'waf_payload_file', None)

        # Initialize signatures and payloads
        self._init_signatures()
        self._init_payloads()
        self._init_evasion_techniques()
        self._init_block_indicators()
        self._init_bypass_hints()

    def _init_signatures(self):
        """Initialize WAF detection signatures."""
        # Signatures: (Name, Location, Pattern)
        # Location: 'headers', 'cookie', 'server', 'body'
        self.signatures = [
            # Cloudflare
            ("Cloudflare", "headers", r"CF-RAY"),
            ("Cloudflare", "headers", r"cf-cache-status"),
            ("Cloudflare", "headers", r"cf-request-id"),
            ("Cloudflare", "server", r"cloudflare"),
            ("Cloudflare", "cookie", r"__cfduid|__cf_bm"),
            ("Cloudflare", "body", r"cloudflare|cf-error|cf-ray"),
            # AWS WAF / CloudFront
            ("AWS WAF", "headers", r"X-Amz-Cf-Id"),
            ("AWS WAF", "headers", r"X-Amz-Cf-Pop"),
            ("AWS WAF", "headers", r"X-CDN"),
            ("AWS WAF", "headers", r"x-amz-request-id"),
            ("AWS WAF", "body", r"aws\.amazon\.com|Request blocked"),
            # AWS Shield
            ("AWS Shield", "headers", r"X-Amz-Shield"),
            ("AWS Shield", "body", r"shield\.aws"),
            # Azure WAF
            ("Azure WAF", "headers", r"X-Azure-Ref"),
            ("Azure WAF", "headers", r"X-MSEdge-Ref"),
            ("Azure WAF", "cookie", r"ApplicationGatewayAffinity"),
            ("Azure WAF", "body", r"azure|microsoft"),
            # Akamai
            ("Akamai", "server", r"AkamaiGHost"),
            ("Akamai", "headers", r"X-Akamai-Transformed"),
            ("Akamai", "headers", r"Akamai-Origin-Hop"),
            ("Akamai", "headers", r"X-Akamai-Request-ID"),
            ("Akamai", "body", r"akamaiedge\.net|akamai"),
            # Incapsula / Imperva
            ("Incapsula", "headers", r"X-Iinfo"),
            ("Incapsula", "headers", r"X-CDN: Incapsula"),
            ("Incapsula", "cookie", r"incap_ses|visid_incap"),
            ("Incapsula", "body", r"incapsula incident|_Incapsula_Resource"),
            # Imperva SecureSphere
            ("Imperva SecureSphere", "headers", r"X-SL-CompState"),
            ("Imperva SecureSphere", "body", r"SecureSphere|imperva"),
            # F5 BIG-IP
            ("F5 BIG-IP", "cookie", r"^TS[0-9a-f]{8}"),
            ("F5 BIG-IP", "cookie", r"BigIP|BIGipServer"),
            ("F5 BIG-IP", "server", r"BigIP|BIG-IP"),
            ("F5 BIG-IP", "headers", r"X-WA-Info"),
            # Barracuda
            ("Barracuda", "cookie", r"^barra_counter_session"),
            ("Barracuda", "headers", r"barra|barracuda"),
            ("Barracuda", "body", r"barracuda"),
            # Sucuri
            ("Sucuri", "server", r"Sucuri"),
            ("Sucuri", "headers", r"X-Sucuri-ID"),
            ("Sucuri", "headers", r"X-Sucuri-Cache"),
            ("Sucuri", "body", r"sucuri\.net|cloudproxy"),
            # ModSecurity
            ("ModSecurity", "server", r"mod_security|NOYB"),
            ("ModSecurity", "headers", r"X-Mod-Security"),
            ("ModSecurity", "body", r"mod_security|modsecurity"),
            # Fortinet FortiWeb
            ("FortiWeb", "headers", r"FORTIWAFSID"),
            ("FortiWeb", "cookie", r"cookiesession1"),
            ("FortiWeb", "body", r"fortigate|fortinet|fortiWeb"),
            # Citrix NetScaler
            ("Citrix NetScaler", "headers", r"ns_af"),
            ("Citrix NetScaler", "cookie", r"citrix_ns_id|NSC_"),
            ("Citrix NetScaler", "server", r"NetScaler"),
            # DDoS-Guard
            ("DDoS-Guard", "server", r"ddos-guard"),
            ("DDoS-Guard", "headers", r"X-DDoS-Protection"),
            ("DDoS-Guard", "cookie", r"__ddg"),
            # Wordfence (WordPress)
            ("Wordfence", "body", r"wordfence|wfwaf|This request has been blocked"),
            ("Wordfence", "headers", r"wf-"),
            # StackPath
            ("StackPath", "headers", r"X-SP-"),
            ("StackPath", "server", r"StackPath"),
            ("StackPath", "headers", r"X-Edge-IP"),
            # Fastly
            ("Fastly", "headers", r"X-Fastly-Request-ID"),
            ("Fastly", "headers", r"Fastly-Debug-"),
            ("Fastly", "headers", r"X-Served-By.*cache"),
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
            # Comodo WAF
            ("Comodo WAF", "server", r"Protected by COMODO"),
            ("Comodo WAF", "body", r"comodo"),
            # DenyAll
            ("DenyAll", "cookie", r"sessioncookie"),
            ("DenyAll", "body", r"denyall"),
            # SonicWall
            ("SonicWall", "server", r"SonicWALL"),
            ("SonicWall", "body", r"sonicwall"),
            # Radware AppWall
            ("Radware AppWall", "headers", r"X-SL-CompState"),
            ("Radware AppWall", "body", r"radware|appwall"),
            # Palo Alto
            ("Palo Alto", "headers", r"X-PAN-"),
            ("Palo Alto", "body", r"paloalto|pan-os"),
            # Check Point
            ("Check Point", "headers", r"X-Check-Point"),
            ("Check Point", "body", r"checkpoint"),
            # Wallarm
            ("Wallarm", "headers", r"X-Wallarm-"),
            ("Wallarm", "body", r"wallarm"),
            # Signal Sciences
            ("Signal Sciences", "headers", r"X-SigSci-"),
            # PerimeterX
            ("PerimeterX", "cookie", r"_px"),
            ("PerimeterX", "body", r"perimeterx|px-captcha"),
            # DataDome
            ("DataDome", "cookie", r"datadome"),
            ("DataDome", "headers", r"X-DataDome"),
            # Distil Networks
            ("Distil Networks", "cookie", r"D_"),
            ("Distil Networks", "body", r"distil"),
            # ShieldSquare (Radware Bot Manager)
            ("ShieldSquare", "headers", r"X-ShieldSquare-"),
            ("ShieldSquare", "cookie", r"ss_"),
            # Webroot
            ("Webroot", "body", r"webroot"),
            # Kona Site Defender (Akamai)
            ("Kona Site Defender", "headers", r"X-Kona-"),
            ("Kona Site Defender", "body", r"kona|akamai"),
        ]

    def _init_payloads(self):
        """Initialize attack payloads for active probing."""
        self.probe_payloads = [
            # SQL Injection patterns
            ("SQLi", "?id=1' OR '1'='1"),
            ("SQLi", "?id=1; DROP TABLE users--"),
            ("SQLi", "?id=UNION SELECT NULL,NULL,NULL--"),
            ("SQLi", "?id=1' AND SLEEP(5)--"),
            # XSS patterns
            ("XSS", "?q=<script>alert('xss')</script>"),
            ("XSS", "?q=<img src=x onerror=alert(1)>"),
            ("XSS", "?q=javascript:alert(1)"),
            ("XSS", "?q=<svg/onload=alert(1)>"),
            # Path traversal / LFI
            ("LFI", "/../../../etc/passwd"),
            ("LFI", "?file=....//....//etc/passwd"),
            ("LFI", "?page=php://filter/read=convert.base64-encode/resource=index"),
            # Command injection
            ("RCE", "?cmd=;cat /etc/passwd"),
            ("RCE", "?cmd=|whoami"),
            ("RCE", "?cmd=$(id)"),
            # SSRF indicators
            ("SSRF", "?url=http://169.254.169.254/latest/meta-data/"),
            ("SSRF", "?url=http://localhost:22"),
        ]

        # Load custom payloads if file specified
        self._load_custom_payloads()

    def _load_custom_payloads(self):
        """Load custom payloads from external file if specified."""
        if not self.custom_payload_file:
            return

        payload_path = Path(self.custom_payload_file)
        if not payload_path.exists():
            return

        try:
            with open(payload_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Format: TYPE|PAYLOAD or just PAYLOAD
                    if '|' in line:
                        parts = line.split('|', 1)
                        self.probe_payloads.append((parts[0], parts[1]))
                    else:
                        self.probe_payloads.append(("Custom", line))
        except Exception:
            pass  # Silently ignore file read errors

    def _init_evasion_techniques(self):
        """Initialize WAF evasion/bypass techniques."""
        self.evasion_techniques = [
            {
                "name": "Case Variation",
                "description": "Mixed case keywords",
                "payload": "?id=1' uNiOn SeLeCt NULL--",
                "type": "SQLi",
            },
            {
                "name": "URL Encoding",
                "description": "Double URL encoding",
                "payload": "?id=1%27%20OR%20%271%27%3D%271",
                "type": "SQLi",
            },
            {
                "name": "Unicode Bypass",
                "description": "Unicode/UTF-8 encoding",
                "payload": "?id=1%u0027%u0020OR%u00201=1",
                "type": "SQLi",
            },
            {
                "name": "Comment Injection",
                "description": "SQL comments to break patterns",
                "payload": "?id=1'/**/OR/**/1=1--",
                "type": "SQLi",
            },
            {
                "name": "Newline Injection",
                "description": "Newline characters in payload",
                "payload": "?id=1'%0aOR%0a1=1--",
                "type": "SQLi",
            },
            {
                "name": "Tab Characters",
                "description": "Tab characters instead of spaces",
                "payload": "?id=1'\tOR\t1=1--",
                "type": "SQLi",
            },
            {
                "name": "Null Bytes",
                "description": "Null byte injection",
                "payload": "?id=1'%00OR%001=1--",
                "type": "SQLi",
            },
            {
                "name": "HTTP Parameter Pollution",
                "description": "Duplicate parameters",
                "payload": "?id=1&id=1' OR '1'='1",
                "type": "HPP",
            },
            {
                "name": "JSON Payload",
                "description": "JSON format for XSS",
                "payload_type": "json",
                "payload": '{"search":"<script>alert(1)</script>"}',
                "type": "XSS",
            },
            {
                "name": "SVG XSS",
                "description": "SVG-based XSS",
                "payload": "?q=<svg><script>alert(1)</script></svg>",
                "type": "XSS",
            },
            {
                "name": "Chunked Transfer",
                "description": "Chunked encoding bypass",
                "headers": {"Transfer-Encoding": "chunked"},
                "type": "Encoding",
            },
        ]

    def _init_block_indicators(self):
        """Initialize block response indicators."""
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
            (r"suspicious activity", "Suspicious Activity"),
            (r"automated access", "Bot Detection"),
            (r"please wait", "Challenge Page"),
            (r"checking your browser", "Browser Check"),
        ]

    def _init_bypass_hints(self):
        """Initialize bypass hints for detected WAFs."""
        self.bypass_hints = {
            "Cloudflare": [
                "Try finding origin IP via historical DNS records (SecurityTrails, ViewDNS)",
                "Check for subdomain that bypasses Cloudflare proxy",
                "Use Cloudflare-specific headers manipulation",
                "Test SSL certificate to find origin IP",
                "Check for direct IP in MX or SPF records",
            ],
            "AWS WAF": [
                "Test for case variation in payloads",
                "Try Unicode/encoding bypass techniques",
                "Check for method-based inconsistencies",
                "Test with different Content-Type headers",
                "Use HTTP/2 multiplexing",
            ],
            "Akamai": [
                "Test chunked transfer encoding",
                "Try parameter pollution techniques",
                "Check for HTTP/2 specific bypasses",
                "Test with different User-Agent strings",
                "Use JSON payloads instead of form data",
            ],
            "ModSecurity": [
                "Check paranoia level (may allow some payloads)",
                "Test for rule ID specific bypasses",
                "Try alternative encoding schemes",
                "Use SQL comment variations",
                "Test OWASP CRS rule gaps",
            ],
            "Incapsula": [
                "Check for backend IP disclosure",
                "Test with mobile user agents",
                "Try origin IP via email headers",
                "Test API endpoints separately",
            ],
            "F5 BIG-IP": [
                "Test for ASM policy weaknesses",
                "Check cookie manipulation",
                "Try HTTP smuggling techniques",
                "Test with different HTTP versions",
            ],
            "Wordfence": [
                "Check for whitelisted IPs/user agents",
                "Test with wp-admin paths",
                "Try JSON-based payloads",
                "Check for REST API endpoints",
            ],
            "Sucuri": [
                "Find origin IP via subdomains",
                "Check for cache poisoning",
                "Test with fragmented payloads",
            ],
            "Imperva SecureSphere": [
                "Test with encoded payloads",
                "Check for policy gaps",
                "Try HTTP smuggling",
            ],
            "Azure WAF": [
                "Test for rule set gaps",
                "Use encoding variations",
                "Check for backend CORS issues",
            ],
            "Fastly": [
                "Check for VCL configuration issues",
                "Test cache key manipulation",
                "Find origin via headers",
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
            "fingerprint": {},  # Detailed per-WAF data
            "evasion_results": [],  # Results from evasion testing
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Phase 1: Passive detection via normal request
                passive_wafs, passive_matches, fingerprint = await self._passive_detection(session, url)
                results["fingerprint"] = fingerprint

                # Phase 2: Active probing with attack payloads
                if not self.stealth_mode:
                    active_wafs, block_info = await self._active_probe(session, url)
                else:
                    active_wafs, block_info = set(), None

                # Phase 3: Multi-method testing
                if not self.stealth_mode:
                    method_wafs = await self._multi_method_test(session, url)
                else:
                    method_wafs = set()

                # Phase 4: Evasion testing (if enabled)
                if self.evasion_mode and (passive_wafs or active_wafs):
                    evasion_results = await self._test_evasion(session, url)
                    results["evasion_results"] = evasion_results

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
    ) -> tuple[set, int, dict]:
        """Detect WAF through passive signature analysis."""
        found_wafs = set()
        match_count = 0
        fingerprint = {}

        try:
            headers_to_send = self._get_stealth_headers() if self.stealth_mode else {}

            async with session.get(
                url, timeout=self.config.timeout, ssl=False, headers=headers_to_send
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

                        # Build detailed fingerprint
                        if name not in fingerprint:
                            fingerprint[name] = {
                                "signatures_matched": [],
                                "headers_found": {},
                                "cookies_found": [],
                            }
                        fingerprint[name]["signatures_matched"].append({
                            "location": loc,
                            "pattern": pattern,
                        })

                # Store relevant headers in fingerprint
                for waf in found_wafs:
                    if waf in fingerprint:
                        # Capture headers that might be useful
                        interesting_headers = {}
                        for h_name, h_val in headers.items():
                            if any(x in h_name.lower() for x in ['cf-', 'x-', 'set-cookie', 'server']):
                                interesting_headers[h_name] = h_val
                        fingerprint[waf]["headers_found"] = interesting_headers
                        fingerprint[waf]["cookies_found"] = list(cookies.keys())

        except Exception:
            pass

        return found_wafs, match_count, fingerprint

    def _get_stealth_headers(self) -> dict:
        """Get headers for stealth mode to appear as normal browser."""
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

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

        # Limit probes in stealth mode
        probes_to_test = self.probe_payloads[:3] if self.stealth_mode else self.probe_payloads[:8]

        for attack_type, payload in probes_to_test:
            # Rate limiting
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)

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
                                "payload": payload[:50],  # Truncate for safety
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

        # Reduce methods in stealth mode
        if self.stealth_mode:
            methods = ["OPTIONS"]

        for method in methods:
            # Rate limiting
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)

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

    async def _test_evasion(
        self, session: aiohttp.ClientSession, url: str
    ) -> list:
        """Test WAF evasion techniques and report which ones bypass."""
        evasion_results = []

        # First, confirm WAF is blocking with a standard payload
        baseline_blocked = False
        try:
            test_url = url.rstrip("/") + "?id=1' OR '1'='1"
            async with session.get(test_url, timeout=self.config.timeout, ssl=False) as resp:
                if resp.status in (403, 406, 429, 503):
                    baseline_blocked = True
        except Exception:
            return evasion_results

        if not baseline_blocked:
            return evasion_results  # Nothing to evade

        # Test each evasion technique
        for technique in self.evasion_techniques:
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)

            try:
                payload = technique.get("payload", "")
                if not payload:
                    continue

                # Handle special payload types
                if technique.get("payload_type") == "json":
                    # POST with JSON body
                    async with session.post(
                        url,
                        json=json.loads(payload),
                        timeout=self.config.timeout,
                        ssl=False,
                    ) as response:
                        status = response.status
                else:
                    # GET with query string
                    test_url = url.rstrip("/") + payload
                    extra_headers = technique.get("headers", {})
                    async with session.get(
                        test_url,
                        timeout=self.config.timeout,
                        ssl=False,
                        headers=extra_headers,
                    ) as response:
                        status = response.status

                # Check if bypass was successful (not blocked)
                bypassed = status not in (403, 406, 429, 503)

                evasion_results.append({
                    "technique": technique["name"],
                    "description": technique["description"],
                    "type": technique["type"],
                    "bypassed": bypassed,
                    "status_code": status,
                })

            except Exception as e:
                evasion_results.append({
                    "technique": technique["name"],
                    "description": technique["description"],
                    "type": technique["type"],
                    "bypassed": False,
                    "error": str(e),
                })

        return evasion_results

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

    def export_fingerprint_json(self, results: dict) -> str:
        """Export detailed fingerprint data as JSON for SIEM integration."""
        export_data = {
            "scan_type": "waf_detection",
            "detected": results.get("detected", False),
            "wafs": results.get("wafs", []),
            "confidence": results.get("confidence", 0),
            "fingerprint": results.get("fingerprint", {}),
            "block_behavior": results.get("block_behavior"),
            "evasion_results": results.get("evasion_results", []),
            "bypass_hints": results.get("bypass_hints", []),
        }
        return json.dumps(export_data, indent=2)
