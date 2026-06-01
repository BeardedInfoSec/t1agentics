# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Test Runner Service

Tests user-defined integrations against real or mock APIs to verify
they work correctly before publishing.
"""

import httpx
import json
import re
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from uuid import uuid4
from pydantic import BaseModel, Field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TestStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class TestType(str, Enum):
    DRY_RUN = "dry_run"      # Validate without calling API
    MOCK = "mock"            # Test with mock responses
    LIVE = "live"            # Test against real API


# ============================================================
# Test Result Models
# ============================================================

class ActionTestResult(BaseModel):
    """Result of testing a single action"""
    action_name: str
    status: TestStatus
    test_type: TestType
    request_url: Optional[str] = None
    request_method: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    response_time_ms: Optional[float] = None
    mapped_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)


class IntegrationTestResult(BaseModel):
    """Result of testing an entire integration"""
    test_id: str = Field(default_factory=lambda: str(uuid4()))
    integration_name: str
    test_type: TestType
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    overall_status: TestStatus = TestStatus.PENDING
    action_results: List[ActionTestResult] = Field(default_factory=list)
    summary: Optional[str] = None

    def complete(self, status: TestStatus, summary: str = None):
        self.completed_at = datetime.utcnow()
        self.overall_status = status
        self.summary = summary


# ============================================================
# Integration Test Runner
# ============================================================

class IntegrationTestRunner:
    """
    Service for testing user-defined integrations.

    Supports:
    - Dry run: Validates configuration without making requests
    - Mock test: Tests with predefined mock responses
    - Live test: Tests against the real API
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.mock_responses: Dict[str, Dict[str, Any]] = {}

    async def dry_run(
        self,
        integration: Dict[str, Any],
        credential: Optional[Dict[str, Any]] = None
    ) -> IntegrationTestResult:
        """
        Perform a dry run validation without making actual API calls.

        Validates:
        - URL construction
        - Header configuration
        - Body template rendering
        - Credential availability
        """
        result = IntegrationTestResult(
            integration_name=integration['name'],
            test_type=TestType.DRY_RUN
        )

        for action in integration.get('actions', []):
            action_result = await self._dry_run_action(
                integration, action, credential
            )
            result.action_results.append(action_result)

        # Determine overall status
        failed = any(r.status == TestStatus.FAILED for r in result.action_results)
        result.complete(
            status=TestStatus.FAILED if failed else TestStatus.SUCCESS,
            summary=f"Dry run {'failed' if failed else 'passed'} for {len(result.action_results)} actions"
        )

        return result

    async def _dry_run_action(
        self,
        integration: Dict[str, Any],
        action: Dict[str, Any],
        credential: Optional[Dict[str, Any]]
    ) -> ActionTestResult:
        """Dry run a single action."""
        warnings = []

        try:
            # Build request URL
            base_url = integration['base_url']
            endpoint = action['endpoint']

            # Replace placeholders with test values
            test_value = self._get_test_value(action.get('observable_type'))
            url = f"{base_url}{endpoint}".replace('{value}', test_value)
            url = re.sub(r'\{[^}]+\}', 'test_param', url)

            # Build headers
            headers = self._build_headers(integration, credential)
            if not headers and integration['auth_type'] != 'none':
                if not credential:
                    warnings.append("No credential provided - authentication will fail in live test")

            # Build body
            body = None
            if action.get('body_template'):
                body = action['body_template'].replace('{value}', test_value)
                body = re.sub(r'\{[^}]+\}', '"test_param"', body)

                # Try to parse as JSON
                try:
                    json.loads(body)
                except json.JSONDecodeError as e:
                    return ActionTestResult(
                        action_name=action['name'],
                        status=TestStatus.FAILED,
                        test_type=TestType.DRY_RUN,
                        request_url=url,
                        request_method=action.get('method', 'GET'),
                        error_message=f"Invalid body template JSON: {str(e)}",
                        warnings=warnings
                    )

            return ActionTestResult(
                action_name=action['name'],
                status=TestStatus.SUCCESS,
                test_type=TestType.DRY_RUN,
                request_url=url,
                request_method=action.get('method', 'GET'),
                request_headers={k: '***' if 'auth' in k.lower() or 'key' in k.lower() else v
                                for k, v in headers.items()},
                request_body=body,
                warnings=warnings
            )

        except Exception as e:
            return ActionTestResult(
                action_name=action['name'],
                status=TestStatus.FAILED,
                test_type=TestType.DRY_RUN,
                error_message=str(e),
                warnings=warnings
            )

    async def test_live(
        self,
        integration: Dict[str, Any],
        credential: Dict[str, Any],
        test_values: Optional[Dict[str, str]] = None,
        actions_to_test: Optional[List[str]] = None
    ) -> IntegrationTestResult:
        """
        Test integration against the real API.

        Args:
            integration: Integration definition
            credential: Decrypted credential with API key/token
            test_values: Optional dict of observable_type -> test_value
            actions_to_test: Optional list of action names to test (tests all if None)
        """
        result = IntegrationTestResult(
            integration_name=integration['name'],
            test_type=TestType.LIVE
        )

        # Filter actions if specified
        actions = integration.get('actions', [])
        if actions_to_test:
            actions = [a for a in actions if a['name'] in actions_to_test]

        # Test each action
        for action in actions:
            # Skip actions that require approval or modify data
            if action.get('requires_approval') and not action.get('read_only', True):
                result.action_results.append(ActionTestResult(
                    action_name=action['name'],
                    status=TestStatus.SKIPPED,
                    test_type=TestType.LIVE,
                    error_message="Skipped: action requires approval or modifies data"
                ))
                continue

            action_result = await self._test_action_live(
                integration, action, credential, test_values
            )
            result.action_results.append(action_result)

        # Determine overall status
        failed = any(r.status == TestStatus.FAILED for r in result.action_results)
        skipped = all(r.status == TestStatus.SKIPPED for r in result.action_results)

        if skipped:
            status = TestStatus.SKIPPED
            summary = "All actions were skipped"
        elif failed:
            status = TestStatus.FAILED
            failed_count = sum(1 for r in result.action_results if r.status == TestStatus.FAILED)
            summary = f"Failed: {failed_count}/{len(result.action_results)} actions failed"
        else:
            status = TestStatus.SUCCESS
            success_count = sum(1 for r in result.action_results if r.status == TestStatus.SUCCESS)
            summary = f"Success: {success_count}/{len(result.action_results)} actions passed"

        result.complete(status=status, summary=summary)
        return result

    async def _test_action_live(
        self,
        integration: Dict[str, Any],
        action: Dict[str, Any],
        credential: Dict[str, Any],
        test_values: Optional[Dict[str, str]]
    ) -> ActionTestResult:
        """Test a single action against the real API."""
        warnings = []
        start_time = datetime.utcnow()

        try:
            # Get test value
            observable_type = action.get('observable_type')
            if test_values and observable_type in test_values:
                test_value = test_values[observable_type]
            else:
                test_value = self._get_test_value(observable_type)

            # Build request
            base_url = integration['base_url']
            endpoint = action['endpoint'].replace('{value}', test_value)
            endpoint = re.sub(r'\{[^}]+\}', 'test', endpoint)
            url = f"{base_url}{endpoint}"

            headers = self._build_headers(integration, credential)
            method = action.get('method', 'GET')

            body = None
            if action.get('body_template'):
                body = action['body_template'].replace('{value}', test_value)
                body = re.sub(r'\{[^}]+\}', '"test"', body)

            # Make request
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if method == 'GET':
                    response = await client.get(url, headers=headers)
                elif method == 'POST':
                    response = await client.post(url, headers=headers, content=body)
                elif method == 'PUT':
                    response = await client.put(url, headers=headers, content=body)
                elif method == 'PATCH':
                    response = await client.patch(url, headers=headers, content=body)
                elif method == 'DELETE':
                    response = await client.delete(url, headers=headers)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

            end_time = datetime.utcnow()
            response_time_ms = (end_time - start_time).total_seconds() * 1000

            # Parse response
            response_body = response.text
            try:
                response_json = response.json()
            except:
                response_json = None

            # Check status code
            if response.status_code >= 400:
                return ActionTestResult(
                    action_name=action['name'],
                    status=TestStatus.FAILED,
                    test_type=TestType.LIVE,
                    request_url=url,
                    request_method=method,
                    request_headers=self._redact_headers(headers),
                    request_body=body,
                    response_status=response.status_code,
                    response_body=response_body[:1000] if response_body else None,
                    response_time_ms=response_time_ms,
                    error_message=f"HTTP {response.status_code}: {response.reason_phrase}",
                    warnings=warnings
                )

            # Apply output mapping
            mapped_output = None
            if response_json and action.get('output_mapping'):
                mapped_output = self._apply_output_mapping(
                    response_json,
                    action['output_mapping']
                )
                if not mapped_output:
                    warnings.append("Output mapping returned empty results")

            return ActionTestResult(
                action_name=action['name'],
                status=TestStatus.SUCCESS,
                test_type=TestType.LIVE,
                request_url=url,
                request_method=method,
                request_headers=self._redact_headers(headers),
                request_body=body,
                response_status=response.status_code,
                response_body=response_body[:1000] if len(response_body) > 1000 else response_body,
                response_time_ms=response_time_ms,
                mapped_output=mapped_output,
                warnings=warnings
            )

        except httpx.TimeoutException:
            return ActionTestResult(
                action_name=action['name'],
                status=TestStatus.FAILED,
                test_type=TestType.LIVE,
                error_message=f"Request timed out after {self.timeout}s",
                warnings=warnings
            )
        except httpx.ConnectError as e:
            return ActionTestResult(
                action_name=action['name'],
                status=TestStatus.FAILED,
                test_type=TestType.LIVE,
                error_message=f"Connection failed: {str(e)}",
                warnings=warnings
            )
        except Exception as e:
            logger.exception(f"Error testing action {action['name']}")
            return ActionTestResult(
                action_name=action['name'],
                status=TestStatus.FAILED,
                test_type=TestType.LIVE,
                error_message=str(e),
                warnings=warnings
            )

    def _build_headers(
        self,
        integration: Dict[str, Any],
        credential: Optional[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        # Add default headers
        if integration.get('default_headers'):
            headers.update(integration['default_headers'])

        # Add authentication
        if credential and integration.get('auth_type'):
            auth_type = integration['auth_type']

            if auth_type == 'api_key':
                header_name = integration.get('auth_config', {}).get('header_name', 'X-API-Key')
                api_key = credential.get('api_key') or credential.get('value')
                if api_key:
                    headers[header_name] = api_key

            elif auth_type == 'bearer_token':
                token = credential.get('token') or credential.get('api_key') or credential.get('value')
                if token:
                    headers['Authorization'] = f'Bearer {token}'

            elif auth_type == 'basic_auth':
                import base64
                username = credential.get('username', '')
                password = credential.get('password', '')
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers['Authorization'] = f'Basic {credentials}'

        return headers

    def _redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive values from headers for logging."""
        sensitive_keys = ['authorization', 'x-api-key', 'api-key', 'token', 'secret']
        return {
            k: '***REDACTED***' if any(s in k.lower() for s in sensitive_keys) else v
            for k, v in headers.items()
        }

    def _get_test_value(self, observable_type: Optional[str]) -> str:
        """Get a safe test value for an observable type."""
        test_values = {
            'ip': '8.8.8.8',  # Google DNS - safe to query
            'domain': 'google.com',  # Safe domain
            'url': 'https://www.google.com',
            'email': 'test@example.com',
            'file_hash': 'd41d8cd98f00b204e9800998ecf8427e',  # MD5 of empty string
            'user': 'testuser',
            'host': 'testhost',
        }
        return test_values.get(observable_type, 'test_value')

    def _apply_output_mapping(
        self,
        response_data: Any,
        mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """Apply JSONPath-like output mapping to response data."""
        result = {}

        for output_key, json_path in mapping.items():
            try:
                value = self._extract_json_path(response_data, json_path)
                if value is not None:
                    result[output_key] = value
            except Exception as e:
                logger.warning(f"Failed to extract {json_path}: {e}")

        return result

    def _extract_json_path(self, data: Any, path: str) -> Any:
        """
        Simple JSONPath extraction.

        Supports:
        - $.field - direct field access
        - $.field.nested - nested field access
        - $.array[0] - array index
        - $.array[*] - all array elements
        """
        if not path.startswith('$'):
            path = '$.' + path

        # Remove leading $.
        path = path[2:] if path.startswith('$.') else path[1:]

        if not path:
            return data

        parts = self._parse_json_path(path)
        current = data

        for part in parts:
            if current is None:
                return None

            if part == '*':
                # Return all elements if array
                if isinstance(current, list):
                    return current
                return None

            elif part.isdigit():
                # Array index
                idx = int(part)
                if isinstance(current, list) and idx < len(current):
                    current = current[idx]
                else:
                    return None

            else:
                # Object field
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None

        return current

    def _parse_json_path(self, path: str) -> List[str]:
        """Parse JSONPath into parts."""
        parts = []
        current = ''

        i = 0
        while i < len(path):
            char = path[i]

            if char == '.':
                if current:
                    parts.append(current)
                    current = ''

            elif char == '[':
                if current:
                    parts.append(current)
                    current = ''
                # Find closing bracket
                j = path.find(']', i)
                if j > i:
                    index = path[i+1:j]
                    parts.append(index)
                    i = j

            else:
                current += char

            i += 1

        if current:
            parts.append(current)

        return parts


# ============================================================
# Singleton instance
# ============================================================

_test_runner: Optional[IntegrationTestRunner] = None


def get_test_runner() -> IntegrationTestRunner:
    """Get singleton test runner instance."""
    global _test_runner
    if _test_runner is None:
        _test_runner = IntegrationTestRunner()
    return _test_runner
