#!/usr/bin/env python3
"""
Example script demonstrating AgentCore API usage.
Tests various investigation scenarios.
"""

import requests
import json
import time
from typing import Dict, Any


API_BASE = "http://localhost:8000"


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def test_health():
    """Test the health endpoint"""
    print_section("Testing Health Endpoint")
    response = requests.get(f"{API_BASE}/api/v1/health")
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))


def create_investigation(alert_data: Dict[str, Any]) -> str:
    """Create a new investigation"""
    print_section(f"Creating Investigation: {alert_data['title']}")
    
    response = requests.post(
        f"{API_BASE}/api/v1/investigate",
        json=alert_data
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Investigation created: {result['investigation_id']}")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"\n  Summary: {result['executive_summary'][:200]}...")
        return result['investigation_id']
    else:
        print(f"✗ Failed to create investigation: {response.status_code}")
        return None


def get_investigation(investigation_id: str):
    """Retrieve investigation details"""
    print_section(f"Retrieving Investigation: {investigation_id}")
    
    response = requests.get(f"{API_BASE}/api/v1/investigations/{investigation_id}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Investigation retrieved")
        print(f"\n  Technical Findings: {len(result['technical_findings'])}")
        print(f"  Timeline Events: {len(result['timeline'])}")
        print(f"  Recommended Actions: {len(result['recommended_actions'])}")
        print(f"  Enrichment Results: {len(result['enrichment_results'])}")
        
        if result['technical_findings']:
            print("\n  Top Finding:")
            finding = result['technical_findings'][0]
            print(f"    - {finding['title']} ({finding['severity']})")
        
        return result
    else:
        print(f"✗ Failed to retrieve investigation: {response.status_code}")
        return None


def test_malicious_scenario():
    """Test with known malicious indicators"""
    alert = {
        "title": "Malware Execution Detected",
        "description": "Suspicious file with hash 44d88612fea8a8f36de82e1278abb02f detected attempting execution. File communicated with domain malicious-site.com",
        "source": "endpoint_protection",
        "metadata": {
            "host": "WORKSTATION-01",
            "user": "john.doe",
            "hash": "44d88612fea8a8f36de82e1278abb02f",
            "domain": "malicious-site.com",
            "file_path": "C:\\Users\\Public\\suspicious.exe"
        }
    }
    
    investigation_id = create_investigation(alert)
    if investigation_id:
        time.sleep(1)
        get_investigation(investigation_id)


def test_suspicious_scenario():
    """Test with suspicious but not definitively malicious activity"""
    alert = {
        "title": "Unusual Login Pattern",
        "description": "User admin logged in from IP 203.0.113.45 at unusual time (3:00 AM) from new location",
        "source": "authentication_logs",
        "metadata": {
            "user": "admin",
            "ip": "203.0.113.45",
            "time": "03:00:00",
            "location": "Unknown"
        }
    }
    
    investigation_id = create_investigation(alert)
    if investigation_id:
        time.sleep(1)
        get_investigation(investigation_id)


def test_benign_scenario():
    """Test with benign activity"""
    alert = {
        "title": "Software Update Process",
        "description": "Automated software update check to update.example.com",
        "source": "network_monitor",
        "metadata": {
            "process": "updater.exe",
            "domain": "update.example.com",
            "destination_ip": "93.184.216.34"
        }
    }
    
    investigation_id = create_investigation(alert)
    if investigation_id:
        time.sleep(1)
        get_investigation(investigation_id)


def test_phishing_scenario():
    """Test phishing email detection"""
    alert = {
        "title": "Potential Phishing Email",
        "description": "Email from suspicious sender phishing@malicious-site.com containing URL http://malicious-site.com/login claiming to be from IT department",
        "source": "email_gateway",
        "metadata": {
            "from": "phishing@malicious-site.com",
            "to": "employee@company.com",
            "subject": "Urgent: Verify Your Account",
            "url": "http://malicious-site.com/login",
            "domain": "malicious-site.com"
        }
    }
    
    investigation_id = create_investigation(alert)
    if investigation_id:
        time.sleep(1)
        get_investigation(investigation_id)


def get_statistics():
    """Get system statistics"""
    print_section("System Statistics")
    
    response = requests.get(f"{API_BASE}/api/v1/stats")
    
    if response.status_code == 200:
        stats = response.json()
        print(f"Total Investigations: {stats['total_investigations']}")
        print(f"Total Alerts: {stats['total_alerts']}")
        print(f"Average Confidence: {stats['average_confidence']}")
        
        if stats['verdict_distribution']:
            print("\nVerdict Distribution:")
            for verdict, count in stats['verdict_distribution'].items():
                print(f"  {verdict}: {count}")
        
        if stats['severity_distribution']:
            print("\nSeverity Distribution:")
            for severity, count in stats['severity_distribution'].items():
                print(f"  {severity}: {count}")
    else:
        print(f"✗ Failed to get statistics: {response.status_code}")


def main():
    """Run all test scenarios"""
    print("\n🛡️  AgentCore API Testing Script")
    print("="*70)
    
    # Test health
    test_health()
    
    # Run test scenarios
    test_malicious_scenario()
    test_phishing_scenario()
    test_suspicious_scenario()
    test_benign_scenario()
    
    # Get final statistics
    get_statistics()
    
    print_section("Testing Complete")
    print("✓ All scenarios executed successfully\n")


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Could not connect to AgentCore API")
        print("   Make sure the backend is running on http://localhost:8000")
        print("   Start it with: cd backend && uvicorn app:app --reload\n")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}\n")
