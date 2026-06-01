# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

import requests
import json
from datetime import datetime
import time

# -------------------------------
# Webhook configuration
# -------------------------------
WEBHOOK_URL = "http://localhost:8000/api/v1/webhooks/alerts"
WEBHOOK_TOKEN = "whtoken_zlRaz-MCcxhODkMzRi3zRK7o7rWxGgL5MscoyCxdpQA"

# List endpoint to verify
LIST_URL = "http://localhost:8000/api/v1/alerts"

# -------------------------------
# Build alert payload
# -------------------------------
def create_test_alert(test_number):
    """Create a unique test alert"""
    return {
        "id": f"webhook-test-{test_number}-{int(time.time())}",  # Unique ID
        "title": f"Webhook Test Alert #{test_number}",
        "description": f"This is webhook test alert number {test_number}",
        "severity": "high",
        "source": "webhook_test",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user": {
            "username": "testuser",
            "privileged": False
        },
        "host": {
            "hostname": "test-host",
            "ip": "192.168.1.100"
        },
        "tags": ["test", "webhook", f"test-{test_number}"]
    }

# -------------------------------
# Send webhook (PLAIN JSON)
# -------------------------------
def send_webhook(alert_payload):
    """Sends plain JSON alert to webhook."""
    try:
        resp = requests.post(
            WEBHOOK_URL,
            headers={
                "X-Webhook-Token": WEBHOOK_TOKEN,
                "Content-Type": "application/json"
            },
            json={"alert_data": alert_payload},
            timeout=10
        )

        print(f"Webhook Response: {resp.status_code}")
        result = resp.json()
        print(json.dumps(result, indent=2))
        return result

    except Exception as e:
        print(f"[FAIL] Failed to send webhook: {e}")
        return None

def list_alerts():
    """List all alerts from API"""
    try:
        resp = requests.get(LIST_URL, timeout=5)
        print(f"\n[LIST] List Alerts Response: {resp.status_code}")
        
        if resp.status_code == 200:
            alerts = resp.json()
            print(f"Total alerts: {len(alerts)}")
            
            if alerts:
                print("\nRecent alerts:")
                for i, alert in enumerate(alerts[:5]):
                    print(f"  {i+1}. [{alert.get('alert_id')}] {alert.get('title')} - {alert.get('severity')}")
            else:
                print("[WARN]  No alerts found!")
        else:
            print(f"[FAIL] Failed to fetch alerts: {resp.text}")
            
    except Exception as e:
        print(f"[FAIL] Failed to list alerts: {e}")

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    print("="*60)
    print("WEBHOOK TEST SCRIPT")
    print("="*60)
    
    # Test 1: Send a new alert
    print("\n[1]  Sending NEW webhook alert...")
    test_alert = create_test_alert(1)
    result = send_webhook(test_alert)
    
    if result:
        if result.get("status") == "success":
            print("[OK] Alert created successfully!")
            alert_id = result.get("alert_id")
            print(f"   Alert ID: {alert_id}")
        elif result.get("status") == "duplicate":
            print("[WARN]  Alert was marked as duplicate")
            print(f"   Existing Alert ID: {result.get('alert_id')}")
        else:
            print("❓ Unexpected response")
    
    # Wait for processing
    print("\n[WAIT] Waiting 2 seconds for alert to save...")
    time.sleep(2)
    
    # Test 2: List all alerts
    print("\n[2]  Fetching alerts from API...")
    list_alerts()
    
    # Test 3: Send same alert again (should be duplicate)
    print("\n[3]  Sending DUPLICATE alert (same ID)...")
    result2 = send_webhook(test_alert)
    
    if result2 and result2.get("status") == "duplicate":
        print("[OK] Duplicate detection working!")
    
    # Test 4: Send another new alert
    print("\n[4]  Sending ANOTHER new alert...")
    test_alert2 = create_test_alert(2)
    result3 = send_webhook(test_alert2)
    
    # Wait and check again
    print("\n[WAIT] Waiting 2 seconds...")
    time.sleep(2)
    
    print("\n[5]  Final alert count:")
    list_alerts()
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\nCheck the UI at http://localhost:3000")
    print("The alerts should now be visible!")
