#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Alpha Testing Smoke Test

Run this script to verify basic functionality before alpha testing.
Requires the backend to be running on localhost:8000.

Usage:
    python scripts/alpha_smoke_test.py [--base-url http://localhost:8000]
"""

import argparse
import sys
import json
import time
import requests
from typing import Tuple, List, Optional
from dataclasses import dataclass

# Test configuration
DEFAULT_BASE_URL = "http://localhost:8000"
TEST_USERNAME = "admin"
TEST_PASSWORD = "admin"  # Change if you've updated the default


@dataclass
class TestResult:
    name: str
    passed: bool
    message: str
    duration_ms: float


class SmokeTest:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token: Optional[str] = None
        self.results: List[TestResult] = []

    def run_all(self) -> bool:
        """Run all smoke tests. Returns True if all pass."""
        print("\n" + "=" * 60)
        print("T1 AGENTICS ALPHA SMOKE TEST")
        print("=" * 60)
        print(f"Target: {self.base_url}\n")

        tests = [
            ("Health Check", self.test_health),
            ("Login", self.test_login),
            ("List Alerts", self.test_list_alerts),
            ("List Investigations", self.test_list_investigations),
            ("List Playbooks", self.test_list_playbooks),
            ("List Integrations", self.test_list_integrations),
            ("AI Health (Riggs)", self.test_riggs_health),
            ("Security Headers", self.test_security_headers),
            ("CORS Check", self.test_cors),
            ("Test Endpoint Blocked", self.test_test_endpoint_blocked),
        ]

        for name, test_func in tests:
            self._run_test(name, test_func)

        return self._print_summary()

    def _run_test(self, name: str, test_func):
        """Run a single test and record result."""
        start = time.time()
        try:
            passed, message = test_func()
            duration = (time.time() - start) * 1000
            self.results.append(TestResult(name, passed, message, duration))

            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"  {status}: {name}")
            if not passed:
                print(f"         {message}")

        except Exception as e:
            duration = (time.time() - start) * 1000
            self.results.append(TestResult(name, False, str(e), duration))
            print(f"  ✗ ERROR: {name}")
            print(f"         {e}")

    def _print_summary(self) -> bool:
        """Print test summary. Returns True if all passed."""
        print("\n" + "-" * 60)
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        total_time = sum(r.duration_ms for r in self.results)

        print(f"Results: {passed}/{len(self.results)} passed, {failed} failed")
        print(f"Total time: {total_time:.0f}ms")

        if failed > 0:
            print("\nFailed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.message}")

        print("=" * 60 + "\n")
        return failed == 0

    # ========================================================================
    # Test Methods
    # ========================================================================

    def test_health(self) -> Tuple[bool, str]:
        """Check health endpoint."""
        resp = self.session.get(f"{self.base_url}/health", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "healthy":
                return True, "Backend is healthy"
        return False, f"Health check failed: {resp.status_code}"

    def test_login(self) -> Tuple[bool, str]:
        """Test login and get auth token."""
        resp = self.session.post(
            f"{self.base_url}/api/v1/admin/login",
            json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
            timeout=10
        )

        if resp.status_code == 200:
            data = resp.json()
            self.token = data.get("access_token")
            if self.token:
                self.session.headers["Authorization"] = f"Bearer {self.token}"
                return True, f"Logged in as {data.get('username')}"

        if resp.status_code == 503:
            return False, "Database unavailable (expected: 503 instead of dev fallback)"

        return False, f"Login failed: {resp.status_code} - {resp.text[:100]}"

    def test_list_alerts(self) -> Tuple[bool, str]:
        """Test alerts endpoint."""
        if not self.token:
            return False, "Not authenticated"

        resp = self.session.get(f"{self.base_url}/api/v1/alerts", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            count = len(data.get("alerts", []))
            return True, f"Found {count} alerts"

        return False, f"Failed: {resp.status_code}"

    def test_list_investigations(self) -> Tuple[bool, str]:
        """Test investigations endpoint."""
        if not self.token:
            return False, "Not authenticated"

        resp = self.session.get(f"{self.base_url}/api/v1/investigations", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            count = len(data.get("investigations", []))
            return True, f"Found {count} investigations"

        return False, f"Failed: {resp.status_code}"

    def test_list_playbooks(self) -> Tuple[bool, str]:
        """Test playbooks endpoint."""
        if not self.token:
            return False, "Not authenticated"

        resp = self.session.get(f"{self.base_url}/api/v1/playbooks", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            count = len(data.get("playbooks", []))
            return True, f"Found {count} playbooks"

        return False, f"Failed: {resp.status_code}"

    def test_list_integrations(self) -> Tuple[bool, str]:
        """Test integrations endpoint."""
        if not self.token:
            return False, "Not authenticated"

        resp = self.session.get(f"{self.base_url}/api/v1/integrations/v2", timeout=10)
        if resp.status_code == 200:
            return True, "Integrations API accessible"

        return False, f"Failed: {resp.status_code}"

    def test_riggs_health(self) -> Tuple[bool, str]:
        """Test Riggs AI assistant health."""
        resp = self.session.get(f"{self.base_url}/api/v1/reasoning/health", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "operational":
                return True, "Riggs AI is operational"
            return True, f"Riggs status: {data.get('status', 'unknown')}"

        return False, f"Riggs health check failed: {resp.status_code}"

    def test_security_headers(self) -> Tuple[bool, str]:
        """Check security headers are present."""
        resp = self.session.get(f"{self.base_url}/health", timeout=5)

        missing = []
        headers_to_check = [
            "X-Content-Type-Options",
            "X-Frame-Options",
        ]

        for header in headers_to_check:
            if header.lower() not in [h.lower() for h in resp.headers]:
                missing.append(header)

        if missing:
            return False, f"Missing headers: {', '.join(missing)}"

        return True, "Security headers present"

    def test_cors(self) -> Tuple[bool, str]:
        """Check CORS is not overly permissive."""
        resp = self.session.options(
            f"{self.base_url}/api/v1/alerts",
            headers={"Origin": "https://evil.com"},
            timeout=5
        )

        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "")

        # Fail if wildcard with credentials
        if allow_origin == "*" and allow_creds.lower() == "true":
            return False, "CORS allows credentials with wildcard origin"

        return True, f"CORS configured (origin: {allow_origin or 'not set'})"

    def test_test_endpoint_blocked(self) -> Tuple[bool, str]:
        """Verify test endpoint is blocked in production."""
        resp = self.session.post(
            f"{self.base_url}/api/v1/test/alert",
            json={"title": "smoke-test", "severity": "low"},
            timeout=5
        )

        if resp.status_code == 403:
            return True, "Test endpoint correctly blocked (403)"

        if resp.status_code == 200:
            return False, "Test endpoint is accessible (should be blocked in prod)"

        return True, f"Test endpoint returned {resp.status_code}"


def main():
    parser = argparse.ArgumentParser(description="T1 Agentics Alpha Smoke Test")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Backend URL (default: {DEFAULT_BASE_URL})"
    )
    parser.add_argument(
        "--username",
        default=TEST_USERNAME,
        help="Login username"
    )
    parser.add_argument(
        "--password",
        default=TEST_PASSWORD,
        help="Login password"
    )

    args = parser.parse_args()

    global TEST_USERNAME, TEST_PASSWORD
    TEST_USERNAME = args.username
    TEST_PASSWORD = args.password

    tester = SmokeTest(args.base_url)

    try:
        success = tester.run_all()
        sys.exit(0 if success else 1)
    except requests.exceptions.ConnectionError:
        print(f"\n✗ ERROR: Cannot connect to {args.base_url}")
        print("  Make sure the backend is running.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
