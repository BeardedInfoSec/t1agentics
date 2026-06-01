# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Webhook Handler Service
Receives and processes alerts from external platforms
"""

from fastapi import HTTPException
from datetime import datetime
import json
import secrets
from typing import Dict, Any

from services.alert_id_generator import generate_alert_id_sync


class WebhookHandler:
    def __init__(self, db):
        self.db = db
        self.rate_limit_window = 3600  # 1 hour in seconds
    
    async def process_webhook(self, token: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming webhook request
        
        Args:
            token: Webhook authentication token
            alert_data: JSON alert data (unencrypted)
            
        Returns:
            Dict with status and alert_id
            
        Raises:
            HTTPException: If token invalid or rate limit exceeded
        """
        # Verify token and get webhook config
        webhook = await self.db.get_webhook_by_token(token)
        if not webhook:
            raise HTTPException(status_code=401, detail="Invalid webhook token")
        
        if not webhook.get("enabled", False):
            raise HTTPException(status_code=403, detail="Webhook is disabled")
        
        # Check rate limit
        if not await self.check_rate_limit(webhook["webhook_id"]):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Validate JSON structure
        self.validate_alert_schema(alert_data)
        
        # Check for duplicate external_id to prevent re-processing
        external_id = alert_data.get("id", f"webhook_{secrets.token_hex(8)}")
        
        # SAVE TO POSTGRESQL (PRIMARY DATABASE)
        from services.postgres_db import postgres_db
        
        # Check if alert already exists in PostgreSQL
        if postgres_db.connected:
            existing_alert = await postgres_db.get_alert_by_external_id(external_id, webhook["name"])
            
            if existing_alert:
                # Return existing alert instead of creating duplicate
                return {
                    "status": "duplicate",
                    "message": "Alert already exists",
                    "alert_id": existing_alert.get("alert_id"),
                    "external_id": external_id
                }
        else:
            # Fallback: check MongoDB for duplicates
            existing_alerts = await self.db.db.alerts.find_one({
                "external_id": external_id,
                "source": webhook["name"]
            })
            
            if existing_alerts:
                return {
                    "status": "duplicate",
                    "message": "Alert already exists",
                    "alert_id": existing_alerts.get("alert_id"),
                    "external_id": external_id
                }
        
        # Create alert with systematic ID
        alert_id = generate_alert_id_sync(
            source=webhook["name"],
            source_type='webhook',
            category=alert_data.get('category'),
            title=alert_data.get('title')
        )

        # EXTRACT FIELDS, IOCs, AND ENTITIES
        from services.field_extraction import field_extractor
        
        # Extract everything from the alert
        extraction = field_extractor.extract_all(alert_data)
        
        print(f"[EXTRACT] Field extraction for {alert_id}:")
        print(f"   IOCs: {sum(len(v) for v in extraction['iocs'].values())} total")
        print(f"   Entities: {sum(len(v) for v in extraction['entities'].values())} total")
        if extraction.get('decoded_content'):
            print(f"   Decoded base64: {len(extraction['decoded_content'])} strings found")
            for dc in extraction['decoded_content'][:3]:  # Show first 3
                print(f"      -> {dc['decoded'][:100]}...")
        if extraction.get('decoded_iocs'):
            decoded_count = sum(len(v) for v in extraction['decoded_iocs'].values())
            if decoded_count > 0:
                print(f"   IOCs from decoded content: {decoded_count}")
        if extraction.get('defanged_iocs'):
            defanged_count = sum(len(v) for v in extraction['defanged_iocs'].values())
            if defanged_count > 0:
                print(f"   Defanged IOCs extracted: {defanged_count}")
        
        # Prepare alert for PostgreSQL
        pg_alert = {
            "alert_id": alert_id,
            "external_id": external_id,
            "title": alert_data.get("title", "Untitled Alert"),
            "description": alert_data.get("description", ""),
            "severity": alert_data.get("severity", "medium").lower(),
            "status": "open",
            "source": webhook["name"],
            "source_type": "webhook",
            "raw_event": {
                **alert_data,  # Original alert data
                "_extracted": extraction  # Add extraction results
            }
        }
        
        # Save to PostgreSQL (primary)
        if postgres_db.connected:
            try:
                created_alert = await postgres_db.create_alert(pg_alert)
                print(f"[OK] Webhook alert {alert_id} saved to PostgreSQL")
            except Exception as e:
                print(f"[ERROR] Failed to save webhook alert to PostgreSQL: {e}")
                # Fallback to MongoDB
                alert = {
                    "alert_id": alert_id,
                    "external_id": external_id,
                    "source": webhook["name"],
                    "source_type": "webhook",
                    "title": alert_data.get("title", "Untitled Alert"),
                    "description": alert_data.get("description", ""),
                    "severity": alert_data.get("severity", "medium").lower(),
                    "status": "open",
                    "raw_data": alert_data,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                    "processed": False
                }
                created_alert = await self.db.create_alert(alert)
        else:
            # Fallback to MongoDB
            alert = {
                "alert_id": alert_id,
                "external_id": external_id,
                "source": webhook["name"],
                "source_type": "webhook",
                "title": alert_data.get("title", "Untitled Alert"),
                "description": alert_data.get("description", ""),
                "severity": alert_data.get("severity", "medium").lower(),
                "status": "open",
                "raw_data": alert_data,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "processed": False
            }
            created_alert = await self.db.create_alert(alert)
        
        # Update webhook stats
        await self.db.increment_webhook_count(webhook["webhook_id"])
        await self.db.update_webhook_last_used(webhook["webhook_id"])
        
        # Log webhook receipt
        await self.db.create_log({
            "level": "info",
            "message": f"Alert received via webhook: {webhook['name']}",
            "source": "webhook_handler",
            "details": {"alert_id": alert_id, "webhook_id": webhook["webhook_id"]}
        })
        
        return {
            "status": "success",
            "alert_id": alert_id,
            "message": "Alert received and processed"
        }
    
    async def check_rate_limit(self, webhook_id: str) -> bool:
        """
        Check if webhook has exceeded rate limit
        
        Args:
            webhook_id: Webhook identifier
            
        Returns:
            True if within limit, False if exceeded
        """
        webhook = await self.db.get_webhook(webhook_id)
        rate_limit = webhook.get("rate_limit", 100)
        
        # Count requests in last hour
        count = await self.db.count_webhook_requests(
            webhook_id, 
            self.rate_limit_window
        )
        
        return count < rate_limit
    
    def validate_alert_schema(self, alert_data: Dict[str, Any]) -> None:
        """
        Validate alert data has required fields
        
        Args:
            alert_data: Decrypted alert data
            
        Raises:
            HTTPException: If validation fails
        """
        # Title is required
        if "title" not in alert_data:
            raise HTTPException(
                status_code=400,
                detail="Alert must contain 'title' field"
            )
        
        # Validate severity if provided
        valid_severities = ["low", "medium", "high", "critical"]
        if "severity" in alert_data:
            if alert_data["severity"].lower() not in valid_severities:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
                )
