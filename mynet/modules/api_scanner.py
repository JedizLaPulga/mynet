"""
API Endpoint Discovery and Security Scanner.

Discovers and analyzes API endpoints for:
- Common API paths and versioning
- Authentication mechanisms
- Rate limiting behavior
- Sensitive data exposure
- Authorization issues
- OpenAPI/Swagger documentation
"""

import asyncio
import aiohttp
import re
import json
from urllib.parse import urlparse, urljoin
from typing import Any, Optional
from .base import BaseModule
from ..core.input_parser import Target


class APIScanner(BaseModule):
    """Discovers and analyzes API endpoints for security issues."""

    def __init__(self, config):
        super().__init__(config)
        self.name = "API Scanner"
        self.description = "Discovers API endpoints and tests for security issues"

        # Rate limit tracking
        self.rate_limit_delay = getattr(config, 'api_rate_limit', 0.3)

        # Initialize path lists
        self._init_api_paths()
        self._init_auth_headers()

    def _init_api_paths(self):
        """Initialize common API discovery paths."""
        self.api_paths = [
            # API Documentation
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/api-docs",
            "/api-docs.json",
            "/openapi.json",
            "/openapi.yaml",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/v3/openapi.json",
            "/docs",
            "/redoc",
            "/graphql",
            "/graphiql",
            "/playground",
            "/.well-known/openapi.json",

            # Version prefixes
            "/api",
            "/api/",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/v1",
            "/v2",
            "/v3",
            "/rest",
            "/rest/v1",

            # Common endpoints
            "/api/health",
            "/api/status",
            "/api/version",
            "/api/info",
            "/api/config",
            "/api/settings",
            "/health",
            "/healthz",
            "/ready",
            "/readyz",
            "/status",
            "/ping",
            "/version",

            # User/Auth related
            "/api/users",
            "/api/user",
            "/api/me",
            "/api/profile",
            "/api/account",
            "/api/auth",
            "/api/login",
            "/api/register",
            "/api/logout",
            "/api/token",
            "/api/refresh",
            "/api/oauth",
            "/api/sessions",
            "/users",
            "/auth",
            "/login",
            "/oauth/token",
            "/oauth/authorize",

            # Admin endpoints
            "/api/admin",
            "/api/admin/users",
            "/api/internal",
            "/admin/api",
            "/internal/api",
            "/management",
            "/actuator",
            "/actuator/health",
            "/actuator/info",
            "/actuator/env",
            "/actuator/beans",
            "/actuator/mappings",

            # Debug/Dev endpoints
            "/api/debug",
            "/debug",
            "/api/test",
            "/test",
            "/api/dev",
            "/dev",
            "/console",
            "/metrics",
            "/prometheus",

            # GraphQL
            "/graphql",
            "/graphql/console",
            "/api/graphql",
            "/v1/graphql",

            # Common resources
            "/api/products",
            "/api/items",
            "/api/orders",
            "/api/search",
            "/api/data",
            "/api/export",
            "/api/import",
            "/api/upload",
            "/api/download",
            "/api/files",
            "/api/documents",
        ]

    def _init_auth_headers(self):
        """Initialize authentication header patterns to detect."""
        self.auth_patterns = {
            "bearer_token": r"Bearer\s+[\w\-\.]+",
            "basic_auth": r"Basic\s+[\w\+/=]+",
            "api_key_header": r"X-API-Key|X-Api-Key|api-key|apikey",
            "jwt_pattern": r"eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+",
            "session_cookie": r"session|JSESSIONID|PHPSESSID|ASP\.NET_SessionId",
        }

    async def run(self, target: Target) -> dict:
        """Execute API discovery and security scan."""
        url = self._get_url(target)
        if not url:
            return {}

        results = {
            "base_url": url,
            "discovered_endpoints": [],
            "api_documentation": None,
            "authentication": {},
            "rate_limiting": {},
            "security_issues": [],
            "technologies": [],
            "graphql": None,
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Phase 1: Discover API endpoints
                endpoints = await self._discover_endpoints(session, url)
                results["discovered_endpoints"] = endpoints

                # Phase 2: Check for API documentation
                api_docs = await self._find_api_documentation(session, url)
                results["api_documentation"] = api_docs

                # Phase 3: Analyze authentication
                auth_info = await self._analyze_authentication(session, url, endpoints)
                results["authentication"] = auth_info

                # Phase 4: Test rate limiting
                rate_info = await self._test_rate_limiting(session, url)
                results["rate_limiting"] = rate_info

                # Phase 5: Check for security issues
                issues = await self._check_security_issues(session, url, endpoints)
                results["security_issues"] = issues

                # Phase 6: Detect technologies
                techs = self._detect_technologies(endpoints, api_docs)
                results["technologies"] = techs

                # Phase 7: GraphQL introspection
                graphql_info = await self._check_graphql(session, url)
                results["graphql"] = graphql_info

            except aiohttp.ClientError as e:
                results["error"] = f"Connection error: {str(e)}"
            except Exception as e:
                results["error"] = str(e)

        return results

    async def _discover_endpoints(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> list:
        """Discover accessible API endpoints."""
        discovered = []
        tested = 0

        for path in self.api_paths:
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)

            url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))

            try:
                async with session.get(
                    url, timeout=self.config.timeout, ssl=False,
                    allow_redirects=False
                ) as response:
                    tested += 1
                    status = response.status
                    content_type = response.headers.get("Content-Type", "")

                    # Consider 2xx, 401, 403 as "found" (endpoint exists)
                    if status in range(200, 300) or status in (401, 403, 405):
                        # Try to get response body for analysis
                        body = ""
                        try:
                            body = await response.text()
                            body = body[:2048]  # Limit size
                        except Exception:
                            pass

                        endpoint_info = {
                            "path": path,
                            "url": url,
                            "status": status,
                            "content_type": content_type,
                            "auth_required": status in (401, 403),
                            "method": "GET",
                            "response_size": len(body),
                        }

                        # Check if it's JSON API
                        if "application/json" in content_type:
                            endpoint_info["is_json"] = True
                            try:
                                data = json.loads(body)
                                if isinstance(data, dict):
                                    endpoint_info["response_keys"] = list(data.keys())[:10]
                            except json.JSONDecodeError:
                                pass

                        # Check for interesting headers
                        interesting_headers = {}
                        for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining",
                                  "X-Powered-By", "Server", "X-Request-Id"]:
                            if h in response.headers:
                                interesting_headers[h] = response.headers[h]
                        if interesting_headers:
                            endpoint_info["headers"] = interesting_headers

                        discovered.append(endpoint_info)

            except Exception:
                continue

        return discovered

    async def _find_api_documentation(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> Optional[dict]:
        """Find and parse API documentation (OpenAPI/Swagger)."""
        doc_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/swagger/v1/swagger.json",
            "/v1/swagger.json",
            "/v2/swagger.json",
            "/openapi.yaml",
            "/api/swagger.json",
        ]

        for path in doc_paths:
            url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))

            try:
                async with session.get(
                    url, timeout=self.config.timeout, ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        content_type = response.headers.get("Content-Type", "")

                        if "json" in content_type or content.strip().startswith('{'):
                            try:
                                spec = json.loads(content)
                                return {
                                    "found": True,
                                    "url": url,
                                    "type": "openapi" if "openapi" in spec else "swagger",
                                    "version": spec.get("openapi") or spec.get("swagger"),
                                    "title": spec.get("info", {}).get("title"),
                                    "endpoints_count": len(spec.get("paths", {})),
                                    "paths": list(spec.get("paths", {}).keys())[:20],
                                }
                            except json.JSONDecodeError:
                                pass

            except Exception:
                continue

        return {"found": False}

    async def _analyze_authentication(
        self, session: aiohttp.ClientSession, base_url: str, endpoints: list
    ) -> dict:
        """Analyze authentication mechanisms used by the API."""
        auth_info = {
            "mechanisms_detected": [],
            "protected_endpoints": [],
            "unprotected_endpoints": [],
            "auth_headers_found": [],
        }

        for endpoint in endpoints:
            if endpoint.get("auth_required"):
                auth_info["protected_endpoints"].append(endpoint["path"])
            else:
                auth_info["unprotected_endpoints"].append(endpoint["path"])

        # Test common auth endpoints
        auth_endpoints = ["/api/auth", "/api/login", "/oauth/token", "/api/token"]

        for path in auth_endpoints:
            url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))

            try:
                # Try OPTIONS to see what's supported
                async with session.options(
                    url, timeout=self.config.timeout, ssl=False
                ) as response:
                    allow = response.headers.get("Allow", "")
                    if "POST" in allow:
                        auth_info["mechanisms_detected"].append({
                            "endpoint": path,
                            "type": "form_login" if "login" in path else "oauth",
                        })

                # Try POST with empty body to see response
                async with session.post(
                    url, timeout=self.config.timeout, ssl=False,
                    headers={"Content-Type": "application/json"},
                    data="{}"
                ) as response:
                    if response.status in (400, 401, 422):
                        # Endpoint exists and expects auth
                        body = await response.text()
                        if "jwt" in body.lower():
                            auth_info["mechanisms_detected"].append({
                                "endpoint": path,
                                "type": "JWT",
                            })
                        elif "bearer" in body.lower():
                            auth_info["mechanisms_detected"].append({
                                "endpoint": path,
                                "type": "Bearer Token",
                            })
                        elif "api_key" in body.lower() or "apikey" in body.lower():
                            auth_info["mechanisms_detected"].append({
                                "endpoint": path,
                                "type": "API Key",
                            })

            except Exception:
                continue

        return auth_info

    async def _test_rate_limiting(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict:
        """Test for rate limiting implementation."""
        rate_info = {
            "implemented": False,
            "limit": None,
            "remaining": None,
            "reset": None,
            "behavior": None,
        }

        test_url = base_url

        try:
            # Make a single request first to check headers
            async with session.get(
                test_url, timeout=self.config.timeout, ssl=False
            ) as response:
                headers = response.headers

                # Check for rate limit headers
                rate_headers = {
                    "X-RateLimit-Limit": headers.get("X-RateLimit-Limit"),
                    "X-RateLimit-Remaining": headers.get("X-RateLimit-Remaining"),
                    "X-RateLimit-Reset": headers.get("X-RateLimit-Reset"),
                    "RateLimit-Limit": headers.get("RateLimit-Limit"),
                    "RateLimit-Remaining": headers.get("RateLimit-Remaining"),
                    "Retry-After": headers.get("Retry-After"),
                }

                # Clean up None values
                rate_headers = {k: v for k, v in rate_headers.items() if v}

                if rate_headers:
                    rate_info["implemented"] = True
                    rate_info["headers"] = rate_headers

                    # Parse values
                    rate_info["limit"] = (
                        rate_headers.get("X-RateLimit-Limit") or
                        rate_headers.get("RateLimit-Limit")
                    )
                    rate_info["remaining"] = (
                        rate_headers.get("X-RateLimit-Remaining") or
                        rate_headers.get("RateLimit-Remaining")
                    )

        except Exception:
            pass

        return rate_info

    async def _check_security_issues(
        self, session: aiohttp.ClientSession, base_url: str, endpoints: list
    ) -> list:
        """Check for common API security issues."""
        issues = []

        # Check for exposed sensitive endpoints
        sensitive_paths = [
            ("/actuator/env", "Spring Boot Actuator - Environment variables exposed"),
            ("/actuator/heapdump", "Spring Boot Actuator - Heap dump exposed"),
            ("/debug", "Debug endpoint exposed"),
            ("/api/internal", "Internal API exposed"),
            ("/api/admin", "Admin API potentially exposed"),
            ("/graphql", "GraphQL endpoint - check for introspection"),
            ("/api/config", "Configuration endpoint exposed"),
            ("/metrics", "Metrics endpoint exposed"),
        ]

        for endpoint in endpoints:
            path = endpoint["path"]
            status = endpoint["status"]

            # Check if sensitive path is accessible
            for sensitive_path, description in sensitive_paths:
                if path == sensitive_path and status == 200:
                    issues.append({
                        "type": "sensitive_endpoint",
                        "path": path,
                        "severity": "high",
                        "description": description,
                        "recommendation": f"Restrict access to {path} or disable in production",
                    })

            # Check for unprotected data endpoints
            if status == 200 and not endpoint.get("auth_required"):
                data_patterns = ["/users", "/accounts", "/orders", "/data", "/export"]
                for pattern in data_patterns:
                    if pattern in path:
                        issues.append({
                            "type": "unprotected_data",
                            "path": path,
                            "severity": "medium",
                            "description": f"Data endpoint {path} accessible without authentication",
                            "recommendation": "Implement authentication for sensitive data endpoints",
                        })
                        break

        # Check for verbose error messages
        test_url = urljoin(base_url, "/api/doesnotexist12345")
        try:
            async with session.get(
                test_url, timeout=self.config.timeout, ssl=False
            ) as response:
                body = await response.text()

                # Check for stack traces or verbose errors
                error_indicators = [
                    "stack trace",
                    "exception",
                    "traceback",
                    "debug",
                    "line ",
                    "at org.",
                    "at java.",
                    "at com.",
                    "File \"",
                ]

                for indicator in error_indicators:
                    if indicator.lower() in body.lower():
                        issues.append({
                            "type": "verbose_error",
                            "path": "/api/doesnotexist12345",
                            "severity": "low",
                            "description": "Verbose error messages may leak implementation details",
                            "recommendation": "Implement generic error messages in production",
                        })
                        break

        except Exception:
            pass

        # Check for missing security headers on API responses
        try:
            async with session.get(
                base_url, timeout=self.config.timeout, ssl=False
            ) as response:
                headers = response.headers
                missing_headers = []

                security_headers = [
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Cache-Control",
                ]

                for header in security_headers:
                    if header not in headers:
                        missing_headers.append(header)

                if missing_headers:
                    issues.append({
                        "type": "missing_headers",
                        "severity": "low",
                        "description": f"Missing security headers: {', '.join(missing_headers)}",
                        "recommendation": "Add security headers to API responses",
                    })

        except Exception:
            pass

        return issues

    def _detect_technologies(self, endpoints: list, api_docs: Optional[dict]) -> list:
        """Detect backend technologies from responses."""
        technologies = []
        seen = set()

        for endpoint in endpoints:
            headers = endpoint.get("headers", {})

            # X-Powered-By
            powered_by = headers.get("X-Powered-By", "")
            if powered_by and powered_by not in seen:
                technologies.append({
                    "name": powered_by,
                    "source": "X-Powered-By header",
                })
                seen.add(powered_by)

            # Server header
            server = headers.get("Server", "")
            if server and server not in seen:
                technologies.append({
                    "name": server,
                    "source": "Server header",
                })
                seen.add(server)

            # Detect from paths
            path = endpoint["path"]
            if "/actuator" in path and "Spring Boot" not in seen:
                technologies.append({
                    "name": "Spring Boot",
                    "source": "Actuator endpoints",
                })
                seen.add("Spring Boot")
            elif "/graphql" in path and "GraphQL" not in seen:
                technologies.append({
                    "name": "GraphQL",
                    "source": "GraphQL endpoint",
                })
                seen.add("GraphQL")

        # From API docs
        if api_docs and api_docs.get("found"):
            doc_type = api_docs.get("type", "OpenAPI")
            version = api_docs.get("version", "")
            tech_name = f"{doc_type} {version}".strip()
            if tech_name not in seen:
                technologies.append({
                    "name": tech_name,
                    "source": "API documentation",
                })

        return technologies

    async def _check_graphql(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> Optional[dict]:
        """Check for GraphQL endpoint and introspection."""
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql"]
        graphql_info = None

        introspection_query = {
            "query": """
                query {
                    __schema {
                        types {
                            name
                        }
                    }
                }
            """
        }

        for path in graphql_paths:
            url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))

            try:
                # Test POST with introspection query
                async with session.post(
                    url,
                    json=introspection_query,
                    timeout=self.config.timeout,
                    ssl=False,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        body = await response.json()

                        if "data" in body and "__schema" in body.get("data", {}):
                            types = body["data"]["__schema"].get("types", [])
                            type_names = [t["name"] for t in types if not t["name"].startswith("__")]

                            graphql_info = {
                                "found": True,
                                "url": url,
                                "introspection_enabled": True,
                                "types_count": len(type_names),
                                "types_sample": type_names[:15],
                                "security_issue": True,
                                "recommendation": "Disable introspection in production",
                            }
                            return graphql_info

                        elif "errors" in body:
                            # GraphQL exists but introspection disabled
                            graphql_info = {
                                "found": True,
                                "url": url,
                                "introspection_enabled": False,
                                "security_issue": False,
                            }
                            return graphql_info

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        return graphql_info

    def _get_url(self, target: Target) -> Optional[str]:
        """Extract URL from target."""
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
