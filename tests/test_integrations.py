#!/usr/bin/env python3
"""
AgentCore API Integration Testing Script
Tests webhook ingestion and result forwarding capabilities.
"""

import requests
import json
import time
from typing import Dict, Any


API_BASE = "http://localhost:8000"


def print_section(title: str):
    """Print formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def print_success(message: str):
    """Print success message"""
    print(f"✓ {message}")


def print_error(message: str):
    """Print error message"""
    print(f"✗ {message}")


class IntegrationTester:
    """Test AgentCore integrations"""
    
    def __init__(self, base_url: str = API_BASE):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_webhook_creation(self):
        """Test creating a custom webhook"""
        print_section("Test 1: Create Custom Webhook")
        
        webhook_config = {
            "webhook_id": "test-webhook",
            "enabled": True,
            "allowed_sources": ["test-system"]
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/webhooks/manage/create",
            json=webhook_config
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success(f"Webhook created: {result['webhook_id']}")
            print(f"  Endpoint: {result['endpoint']}")
            return True
        else:
            print_error(f"Failed to create webhook: {response.status_code}")
            return False
    
    def test_list_webhooks(self):
        """Test listing webhooks"""
        print_section("Test 2: List Webhooks")
        
        response = self.session.get(
            f"{self.base_url}/api/v1/webhooks/manage/list"
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success(f"Found {len(result['webhooks'])} webhooks")
            for webhook in result['webhooks']:
                print(f"  - {webhook['webhook_id']}: {'enabled' if webhook['enabled'] else 'disabled'}")
            return True
        else:
            print_error(f"Failed to list webhooks: {response.status_code}")
            return False
    
    def test_send_alert_to_webhook(self):
        """Test sending alert to webhook"""
        print_section("Test 3: Send Alert via Webhook")
        
        alert = {
            "title": "Test Alert from Integration Script",
            "description": "This is a test alert with IP 192.168.1.100 and domain test-malicious.com",
            "user": "testuser",
            "ip": "192.168.1.100",
            "domain": "test-malicious.com"
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/webhooks/ingest/default",
            headers={
                "X-Webhook-ID": "default",
                "X-Source": "test-system"
            },
            json=alert
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success("Alert submitted successfully")
            print(f"  Alert ID: {result['alert_id']}")
            print(f"  Investigation ID: {result['investigation_id']}")
            return result['investigation_id']
        else:
            print_error(f"Failed to send alert: {response.status_code}")
            return None
    
    def test_splunk_webhook(self):
        """Test Splunk-specific webhook"""
        print_section("Test 4: Splunk Alert Webhook")
        
        splunk_alert = {
            "sid": "test_sid_12345",
            "search_name": "Test Malware Detection",
            "owner": "admin",
            "app": "search",
            "results_link": "http://splunk/app/search",
            "result": {
                "_raw": "Malware detected: hash 44d88612fea8a8f36de82e1278abb02f",
                "host": "WORKSTATION-01",
                "hash": "44d88612fea8a8f36de82e1278abb02f"
            }
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/webhooks/splunk/alert",
            json=splunk_alert
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success("Splunk alert submitted successfully")
            print(f"  Investigation ID: {result['investigation_id']}")
            return result['investigation_id']
        else:
            print_error(f"Failed to send Splunk alert: {response.status_code}")
            return None
    
    def test_register_webhook_integration(self):
        """Test registering a webhook integration for forwarding"""
        print_section("Test 5: Register Webhook Integration")
        
        integration_config = {
            "name": "test-webhook-integration",
            "type": "webhook",
            "enabled": True,
            "config": {
                "url": "https://webhook.site/unique-url",  # Use your test URL
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json"
                }
            }
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/integrations/register",
            json=integration_config
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success(f"Integration registered: {result['name']}")
            return True
        else:
            print_error(f"Failed to register integration: {response.status_code}")
            print(f"  Response: {response.text}")
            return False
    
    def test_list_integrations(self):
        """Test listing integrations"""
        print_section("Test 6: List Integrations")
        
        response = self.session.get(
            f"{self.base_url}/api/v1/integrations"
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success(f"Found {len(result['integrations'])} integrations")
            for integration in result['integrations']:
                status = "enabled" if integration['enabled'] else "disabled"
                print(f"  - {integration['name']} ({integration['type']}): {status}")
            return True
        else:
            print_error(f"Failed to list integrations: {response.status_code}")
            return False
    
    def test_forward_investigation(self, investigation_id: str):
        """Test forwarding investigation results"""
        print_section("Test 7: Forward Investigation")
        
        if not investigation_id:
            print_error("No investigation ID provided")
            return False
        
        # Wait for investigation to complete
        print("Waiting for investigation to complete...")
        time.sleep(3)
        
        response = self.session.post(
            f"{self.base_url}/api/v1/investigations/{investigation_id}/forward",
            json={"integrations": ["test-webhook-integration"]}
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success("Investigation forwarded")
            for forward_result in result['results']:
                status = forward_result['status']
                integration = forward_result['integration']
                print(f"  {integration}: {status}")
            return True
        else:
            print_error(f"Failed to forward investigation: {response.status_code}")
            print(f"  Response: {response.text}")
            return False
    
    def test_get_investigation(self, investigation_id: str):
        """Test retrieving investigation details"""
        print_section("Test 8: Retrieve Investigation")
        
        if not investigation_id:
            print_error("No investigation ID provided")
            return False
        
        response = self.session.get(
            f"{self.base_url}/api/v1/investigations/{investigation_id}"
        )
        
        if response.status_code == 200:
            investigation = response.json()
            print_success("Investigation retrieved")
            print(f"  Verdict: {investigation['verdict']}")
            print(f"  Severity: {investigation['severity']}")
            print(f"  Confidence: {investigation['confidence']}")
            print(f"  Findings: {len(investigation['technical_findings'])}")
            print(f"  IOCs: {len(investigation['ioc_summary']['ips'])} IPs, {len(investigation['ioc_summary']['domains'])} domains")
            return True
        else:
            print_error(f"Failed to retrieve investigation: {response.status_code}")
            return False
    
    def test_end_to_end_flow(self):
        """Test complete end-to-end flow"""
        print_section("Test 9: End-to-End Flow")
        
        print("1. Sending alert...")
        investigation_id = self.test_send_alert_to_webhook()
        
        if not investigation_id:
            print_error("End-to-end flow failed at alert submission")
            return False
        
        print("\n2. Waiting for investigation to complete...")
        time.sleep(3)
        
        print("\n3. Retrieving results...")
        if not self.test_get_investigation(investigation_id):
            print_error("End-to-end flow failed at retrieval")
            return False
        
        print("\n4. Forwarding to integrations...")
        if not self.test_forward_investigation(investigation_id):
            print_error("End-to-end flow failed at forwarding")
            return False
        
        print_success("\nEnd-to-end flow completed successfully!")
        return True
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("\n" + "="*70)
        print("  AgentCore API Integration Tests")
        print("="*70)
        
        results = []
        
        # Test webhook management
        results.append(("Create Webhook", self.test_webhook_creation()))
        results.append(("List Webhooks", self.test_list_webhooks()))
        
        # Test alert ingestion
        investigation_id = self.test_send_alert_to_webhook()
        results.append(("Send Alert", investigation_id is not None))
        
        splunk_inv_id = self.test_splunk_webhook()
        results.append(("Splunk Webhook", splunk_inv_id is not None))
        
        # Test integration management
        results.append(("Register Integration", self.test_register_webhook_integration()))
        results.append(("List Integrations", self.test_list_integrations()))
        
        # Test forwarding
        if investigation_id:
            results.append(("Forward Investigation", self.test_forward_investigation(investigation_id)))
            results.append(("Retrieve Investigation", self.test_get_investigation(investigation_id)))
        
        # Summary
        print_section("Test Summary")
        
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        for test_name, result in results:
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{status}: {test_name}")
        
        print(f"\n{passed}/{total} tests passed")
        
        if passed == total:
            print("\n🎉 All tests passed!")
            return True
        else:
            print(f"\n⚠️  {total - passed} tests failed")
            return False


def main():
    """Main test runner"""
    tester = IntegrationTester()
    
    try:
        # Check if AgentCore is running
        response = requests.get(f"{API_BASE}/api/v1/health", timeout=5)
        if response.status_code != 200:
            print_error("AgentCore is not responding correctly")
            print("Make sure AgentCore is running: uvicorn app:app --reload")
            return
    except requests.exceptions.ConnectionError:
        print_error("Cannot connect to AgentCore")
        print("Make sure AgentCore is running on http://localhost:8000")
        return
    
    # Run tests
    success = tester.run_all_tests()
    
    # Exit with appropriate code
    exit(0 if success else 1)


if __name__ == "__main__":
    main()
