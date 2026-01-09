"""Tests for API Scanner module."""

import unittest
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch
from mynet.modules.api_scanner import APIScanner
from mynet.core.config import Config
from mynet.core.input_parser import Target


class TestAPIScanner(unittest.TestCase):
    """Test cases for APIScanner class."""

    def setUp(self):
        self.config = Config()
        self.config.api_rate_limit = 0  # No delay for tests
        self.scanner = APIScanner(self.config)

    def _create_mock_response(self, headers=None, status=200, body="", json_data=None):
        """Helper to create a mock aiohttp response."""
        mock_response = AsyncMock()
        mock_response.headers = headers or {}
        mock_response.status = status

        if json_data:
            mock_response.text = AsyncMock(return_value=json.dumps(json_data))
            mock_response.json = AsyncMock(return_value=json_data)
        else:
            mock_response.text = AsyncMock(return_value=body)
            mock_response.json = AsyncMock(side_effect=json.JSONDecodeError("", "", 0))

        return mock_response

    def _create_mock_session(self, responses):
        """Create mock session returning responses in order."""
        mock_session = MagicMock()
        response_iter = iter(responses)

        def get_next_response(*args, **kwargs):
            try:
                resp = next(response_iter)
            except StopIteration:
                resp = self._create_mock_response(status=404)

            mock_cm = MagicMock()
            mock_cm.__aenter__.return_value = resp
            mock_cm.__aexit__.return_value = None
            return mock_cm

        mock_session.get.side_effect = get_next_response
        mock_session.post.side_effect = get_next_response
        mock_session.options.side_effect = get_next_response

        return mock_session

    def _patch_session(self, mock_session):
        """Create patched ClientSession context manager."""
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = None
        return mock_session_cm

    # -------------------------------------------------------------------------
    # Endpoint Discovery Tests
    # -------------------------------------------------------------------------

    def test_endpoint_discovery(self):
        """Test discovery of API endpoints."""
        responses = [
            # First few paths return 200
            self._create_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                json_data={"version": "1.0.0"}
            ),
            self._create_mock_response(status=200),
            self._create_mock_response(status=401),  # Auth required
            *[self._create_mock_response(status=404) for _ in range(200)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("discovered_endpoints", results)
            self.assertGreater(len(results["discovered_endpoints"]), 0)

    def test_endpoint_auth_detection(self):
        """Test detection of endpoints requiring authentication."""
        responses = [
            self._create_mock_response(status=401),  # Auth required
            self._create_mock_response(status=403),  # Forbidden
            self._create_mock_response(status=200),  # Public
            *[self._create_mock_response(status=404) for _ in range(200)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            endpoints = results["discovered_endpoints"]
            auth_required = [e for e in endpoints if e.get("auth_required")]
            public = [e for e in endpoints if not e.get("auth_required")]

            self.assertGreater(len(auth_required), 0)
            self.assertGreater(len(public), 0)

    # -------------------------------------------------------------------------
    # API Documentation Tests
    # -------------------------------------------------------------------------

    def test_swagger_detection(self):
        """Test detection of Swagger/OpenAPI documentation."""
        swagger_spec = {
            "swagger": "2.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {},
                "/products": {},
                "/orders": {},
            }
        }

        responses = [
            *[self._create_mock_response(status=404) for _ in range(100)],
            # Swagger endpoint
            self._create_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                json_data=swagger_spec
            ),
            *[self._create_mock_response(status=404) for _ in range(100)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            # Check if api_documentation exists in results
            self.assertIn("api_documentation", results)

    def test_openapi_detection(self):
        """Test detection of OpenAPI 3 documentation."""
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/api/users": {},
            }
        }

        responses = [
            self._create_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                json_data=openapi_spec
            ),
            *[self._create_mock_response(status=404) for _ in range(200)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("api_documentation", results)

    # -------------------------------------------------------------------------
    # Rate Limiting Tests
    # -------------------------------------------------------------------------

    def test_rate_limit_detection(self):
        """Test detection of rate limiting headers."""
        responses = [
            *[self._create_mock_response(status=404) for _ in range(100)],
            # Response with rate limit headers
            self._create_mock_response(
                status=200,
                headers={
                    "X-RateLimit-Limit": "100",
                    "X-RateLimit-Remaining": "95",
                    "X-RateLimit-Reset": "1609459200",
                }
            ),
            *[self._create_mock_response(status=404) for _ in range(100)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("rate_limiting", results)

    # -------------------------------------------------------------------------
    # Security Issues Tests
    # -------------------------------------------------------------------------

    def test_sensitive_endpoint_detection(self):
        """Test detection of exposed sensitive endpoints."""
        responses = [
            # Return 200 for actuator/env (sensitive)
            *[self._create_mock_response(status=404) for _ in range(50)],
            self._create_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                json_data={"activeProfiles": ["production"]}
            ),
            *[self._create_mock_response(status=404) for _ in range(150)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("security_issues", results)

    def test_verbose_error_detection(self):
        """Test detection of verbose error messages."""
        responses = [
            *[self._create_mock_response(status=404) for _ in range(100)],
            # Verbose error with stack trace
            self._create_mock_response(
                status=500,
                body="Error: stack trace at org.example.Service.method(Service.java:123)"
            ),
            *[self._create_mock_response(status=404) for _ in range(100)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("security_issues", results)

    # -------------------------------------------------------------------------
    # GraphQL Tests
    # -------------------------------------------------------------------------

    def test_graphql_introspection_enabled(self):
        """Test detection of GraphQL with introspection enabled."""
        graphql_response = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query"},
                        {"name": "User"},
                        {"name": "Product"},
                    ]
                }
            }
        }

        responses = [
            *[self._create_mock_response(status=404) for _ in range(150)],
            # GraphQL introspection response
            self._create_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                json_data=graphql_response
            ),
            *[self._create_mock_response(status=404) for _ in range(50)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("graphql", results)

    def test_graphql_introspection_disabled(self):
        """Test detection of GraphQL with introspection disabled."""
        graphql_response = {
            "errors": [{"message": "Introspection disabled"}]
        }

        responses = [
            *[self._create_mock_response(status=404) for _ in range(150)],
            self._create_mock_response(
                status=200,
                headers={"Content-Type": "application/json"},
                json_data=graphql_response
            ),
            *[self._create_mock_response(status=404) for _ in range(50)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("graphql", results)

    # -------------------------------------------------------------------------
    # Technology Detection Tests
    # -------------------------------------------------------------------------

    def test_technology_detection(self):
        """Test detection of backend technologies."""
        responses = [
            self._create_mock_response(
                status=200,
                headers={
                    "X-Powered-By": "Express",
                    "Server": "nginx/1.18.0",
                }
            ),
            *[self._create_mock_response(status=404) for _ in range(200)],
        ]
        mock_session = self._create_mock_session(responses)

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            self.assertIn("technologies", results)
            tech_names = [t["name"] for t in results["technologies"]]
            self.assertIn("Express", tech_names)

    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------

    def test_empty_target(self):
        """Test with empty target."""
        target = Target(original_input="", host="")
        results = asyncio.run(self.scanner.run(target))
        self.assertEqual(results, {})

    def test_connection_error_handling(self):
        """Test graceful handling of connection errors."""
        # When requests fail, the scanner should still return a valid structure
        import aiohttp

        mock_session = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__.side_effect = aiohttp.ClientError("Connection failed")
        mock_session.get.return_value = mock_cm
        mock_session.post.return_value = mock_cm
        mock_session.options.return_value = mock_cm

        with patch('aiohttp.ClientSession', return_value=self._patch_session(mock_session)):
            target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
            results = asyncio.run(self.scanner.run(target))

            # Should still return valid structure even with failures
            self.assertIn("discovered_endpoints", results)
            self.assertEqual(results["discovered_endpoints"], [])

    # -------------------------------------------------------------------------
    # Unit Tests
    # -------------------------------------------------------------------------

    def test_api_paths_initialized(self):
        """Test that API paths list is initialized."""
        self.assertGreater(len(self.scanner.api_paths), 50)

    def test_auth_patterns_initialized(self):
        """Test that auth patterns are initialized."""
        self.assertIn("bearer_token", self.scanner.auth_patterns)
        self.assertIn("jwt_pattern", self.scanner.auth_patterns)

    def test_detect_technologies_spring_boot(self):
        """Test Spring Boot detection from actuator paths."""
        endpoints = [{"path": "/actuator/health", "headers": {}}]
        techs = self.scanner._detect_technologies(endpoints, None)

        tech_names = [t["name"] for t in techs]
        self.assertIn("Spring Boot", tech_names)

    def test_detect_technologies_graphql(self):
        """Test GraphQL detection from path."""
        endpoints = [{"path": "/graphql", "headers": {}}]
        techs = self.scanner._detect_technologies(endpoints, None)

        tech_names = [t["name"] for t in techs]
        self.assertIn("GraphQL", tech_names)

    def test_get_url_with_host(self):
        """Test URL extraction from host target."""
        target = Target(original_input="api.example.com", host="api.example.com")
        self.assertEqual(self.scanner._get_url(target), "http://api.example.com")

    def test_get_url_with_url(self):
        """Test URL extraction from URL target."""
        target = Target(original_input="https://api.example.com", host="api.example.com", url="https://api.example.com")
        self.assertEqual(self.scanner._get_url(target), "https://api.example.com")


if __name__ == "__main__":
    unittest.main()
