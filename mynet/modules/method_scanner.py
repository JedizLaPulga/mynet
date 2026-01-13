"""
HTTP Method Scanner Module.

Tests for dangerous or misconfigured HTTP methods that could lead to
security vulnerabilities.

Features:
- Tests all standard HTTP methods
- WebDAV method detection (PROPFIND, MKCOL, COPY, MOVE, etc.)
- TRACE/TRACK XST vulnerability detection
- PUT/DELETE file upload/deletion risks
- OPTIONS information disclosure
- CORS preflight analysis
- Custom method testing
"""

import asyncio
import aiohttp
from typing import Any, Optional, List, Dict
from .base import BaseModule
from ..core.input_parser import Target


class HTTPMethodScanner(BaseModule):
    """Tests for dangerous or misconfigured HTTP methods."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "HTTP Method Scanner"
        self.description = "Tests for dangerous HTTP methods"

        # Standard HTTP methods
        self.standard_methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH",
            "HEAD", "OPTIONS", "TRACE", "CONNECT",
        ]

        # WebDAV methods
        self.webdav_methods = [
            "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "ORDERPATCH", "ACL", "SEARCH",
        ]

        # Other potentially dangerous methods
        self.other_methods = [
            "TRACK",  # Similar to TRACE
            "DEBUG",  # ASP.NET debug
            "PURGE",  # Cache purge
            "LINK", "UNLINK",
        ]

        # Risk classifications
        self.high_risk_methods = {"PUT", "DELETE", "TRACE", "TRACK", "DEBUG", "CONNECT"}
        self.medium_risk_methods = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "PATCH"}

    async def run(self, target: Target) -> dict:
        """Execute HTTP method scan."""
        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "url": url,
            "allowed_methods": [],
            "dangerous_methods": [],
            "webdav_enabled": False,
            "vulnerabilities": [],
            "options_headers": {},
            "method_responses": {},
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Phase 1: OPTIONS request to discover allowed methods
                options_result = await self._test_options(session, url)
                if options_result:
                    results["allowed_methods"] = options_result.get("allowed", [])
                    results["options_headers"] = options_result.get("headers", {})

                # Phase 2: Test each method individually
                all_methods = self.standard_methods + self.webdav_methods + self.other_methods
                method_results = await self._test_methods(session, url, all_methods)
                results["method_responses"] = method_results

                # Phase 3: Analyze results
                self._analyze_results(results)

            except aiohttp.ClientError as e:
                results["error"] = f"Connection error: {str(e)}"
            except Exception as e:
                results["error"] = str(e)

        return results

    async def _test_options(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[dict]:
        """Send OPTIONS request to discover allowed methods."""
        try:
            async with session.options(
                url,
                timeout=self.config.timeout,
                ssl=False,
            ) as response:
                headers = dict(response.headers)
                allowed = []

                # Parse Allow header
                allow_header = headers.get("Allow", "")
                if allow_header:
                    allowed = [m.strip().upper() for m in allow_header.split(",")]

                # Also check Access-Control-Allow-Methods for CORS
                cors_methods = headers.get("Access-Control-Allow-Methods", "")
                if cors_methods:
                    cors_list = [m.strip().upper() for m in cors_methods.split(",")]
                    allowed = list(set(allowed + cors_list))

                return {
                    "status": response.status,
                    "allowed": allowed,
                    "headers": {
                        k: v for k, v in headers.items()
                        if k.lower() in [
                            "allow", "access-control-allow-methods",
                            "access-control-allow-origin", "server",
                            "x-powered-by", "dav", "ms-author-via",
                        ]
                    },
                }
        except Exception:
            return None

    async def _test_methods(
        self,
        session: aiohttp.ClientSession,
        url: str,
        methods: List[str],
    ) -> Dict[str, dict]:
        """Test each HTTP method against the target."""
        results = {}

        for method in methods:
            try:
                result = await self._test_single_method(session, url, method)
                if result:
                    results[method] = result
            except Exception:
                pass

            # Small delay to avoid overwhelming the server
            await asyncio.sleep(0.05)

        return results

    async def _test_single_method(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[dict]:
        """Test a single HTTP method."""
        try:
            # Special handling for methods that might need a body
            kwargs = {
                "timeout": self.config.timeout,
                "ssl": False,
                "allow_redirects": False,
            }

            # TRACE should reflect the request back
            if method in ("TRACE", "TRACK"):
                kwargs["headers"] = {"X-Custom-Header": "TraceTest"}

            async with session.request(method, url, **kwargs) as response:
                status = response.status
                headers = dict(response.headers)

                result = {
                    "status": status,
                    "allowed": status not in (405, 501),
                    "server": headers.get("Server", ""),
                }

                # For TRACE, check if headers are reflected (XST vulnerability)
                if method in ("TRACE", "TRACK") and status == 200:
                    try:
                        body = await response.text()
                        if "X-Custom-Header" in body or "TraceTest" in body:
                            result["xst_vulnerable"] = True
                            result["body_preview"] = body[:200]
                    except Exception:
                        pass

                # Check for WebDAV indicators
                if method == "PROPFIND" and status in (200, 207):
                    result["webdav"] = True
                    try:
                        body = await response.text()
                        if "multistatus" in body.lower() or "d:response" in body.lower():
                            result["webdav_response"] = True
                    except Exception:
                        pass

                # Check for dangerous PUT/DELETE success
                if method == "PUT" and status in (200, 201, 204):
                    result["put_enabled"] = True
                if method == "DELETE" and status in (200, 202, 204):
                    result["delete_enabled"] = True

                return result

        except asyncio.TimeoutError:
            return {"status": "timeout", "allowed": False}
        except Exception as e:
            return {"status": "error", "error": str(e), "allowed": False}

    def _analyze_results(self, results: dict):
        """Analyze method test results and identify vulnerabilities."""
        method_responses = results.get("method_responses", {})
        vulnerabilities = []
        dangerous_methods = []

        for method, data in method_responses.items():
            if not isinstance(data, dict):
                continue

            is_allowed = data.get("allowed", False)
            status = data.get("status")

            if not is_allowed:
                continue

            # Check for dangerous methods
            if method in self.high_risk_methods:
                dangerous_methods.append(method)

                if method in ("TRACE", "TRACK"):
                    if data.get("xst_vulnerable"):
                        vulnerabilities.append({
                            "type": "XST",
                            "method": method,
                            "severity": "high",
                            "description": f"{method} method enabled - Cross-Site Tracing (XST) vulnerability",
                            "impact": "Attackers can steal cookies marked HttpOnly via XSS + TRACE",
                            "remediation": f"Disable {method} method in web server configuration",
                        })
                    else:
                        vulnerabilities.append({
                            "type": "TRACE_ENABLED",
                            "method": method,
                            "severity": "medium",
                            "description": f"{method} method enabled",
                            "impact": "May be exploitable for XST if combined with XSS",
                            "remediation": f"Disable {method} method",
                        })

                elif method == "PUT":
                    if data.get("put_enabled"):
                        vulnerabilities.append({
                            "type": "PUT_ENABLED",
                            "method": "PUT",
                            "severity": "high",
                            "description": "PUT method enabled and may allow file uploads",
                            "impact": "Attackers may be able to upload malicious files",
                            "remediation": "Disable PUT or restrict to authenticated users",
                        })

                elif method == "DELETE":
                    if data.get("delete_enabled"):
                        vulnerabilities.append({
                            "type": "DELETE_ENABLED",
                            "method": "DELETE",
                            "severity": "high",
                            "description": "DELETE method enabled and may allow file deletion",
                            "impact": "Attackers may be able to delete files",
                            "remediation": "Disable DELETE or restrict to authenticated users",
                        })

                elif method == "DEBUG":
                    vulnerabilities.append({
                        "type": "DEBUG_ENABLED",
                        "method": "DEBUG",
                        "severity": "high",
                        "description": "DEBUG method enabled (ASP.NET)",
                        "impact": "May expose sensitive debugging information",
                        "remediation": "Disable DEBUG method and debugging in production",
                    })

                elif method == "CONNECT":
                    vulnerabilities.append({
                        "type": "CONNECT_ENABLED",
                        "method": "CONNECT",
                        "severity": "medium",
                        "description": "CONNECT method enabled",
                        "impact": "Server may be usable as a proxy",
                        "remediation": "Disable CONNECT unless required for proxy functionality",
                    })

            elif method in self.medium_risk_methods:
                dangerous_methods.append(method)

            # WebDAV detection
            if method == "PROPFIND" and data.get("webdav"):
                results["webdav_enabled"] = True
                vulnerabilities.append({
                    "type": "WEBDAV_ENABLED",
                    "method": "PROPFIND",
                    "severity": "medium",
                    "description": "WebDAV is enabled on this server",
                    "impact": "WebDAV may expose sensitive file operations",
                    "remediation": "Disable WebDAV if not required",
                })

        results["dangerous_methods"] = dangerous_methods
        results["vulnerabilities"] = vulnerabilities

        # Update allowed methods list if OPTIONS didn't return them
        if not results["allowed_methods"]:
            results["allowed_methods"] = [
                m for m, d in method_responses.items()
                if isinstance(d, dict) and d.get("allowed")
            ]

    def _get_url(self, target: Target) -> Optional[str]:
        """Get URL from target."""
        if target.url:
            return target.url
        if target.host:
            return f"http://{target.host}"
        return None
