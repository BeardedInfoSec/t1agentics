# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Authentication and Request Helpers for Custom Integrations
"""

import httpx
import base64
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
import os

# Encryption key for storing sensitive credentials
# In production, this should be loaded from environment variable
ENCRYPTION_KEY = os.getenv("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key())
cipher = Fernet(ENCRYPTION_KEY)


def encrypt_value(value: str) -> str:
    """Encrypt a sensitive value"""
    return cipher.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a sensitive value"""
    return cipher.decrypt(encrypted_value.encode()).decode()


async def make_integration_request(
    endpoint_url: str,
    method: str = "GET",
    auth_type: str = "none",
    auth_data: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Make an HTTP request with proper authentication.
    
    Args:
        endpoint_url: Target URL
        method: HTTP method (GET, POST)
        auth_type: Authentication type (none, basic, api_key, bearer)
        auth_data: Authentication credentials
        body: Request body for POST requests
        timeout: Request timeout in seconds
    
    Returns:
        Dict with status_code, body, and success flag
    """
    headers = {}
    params = {}
    
    # Handle authentication
    if auth_type == "basic" and auth_data:
        username = auth_data.get("username", "")
        password = auth_data.get("password", "")
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    
    elif auth_type == "api_key" and auth_data:
        key_name = auth_data.get("key_name", "X-API-Key")
        key_value = auth_data.get("key_value", "")
        location = auth_data.get("location", "header")
        
        if location == "header":
            headers[key_name] = key_value
        elif location == "query":
            params[key_name] = key_value
    
    elif auth_type == "bearer" and auth_data:
        token = auth_data.get("token", "")
        headers["Authorization"] = f"Bearer {token}"
    
    # Make request
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if method.upper() == "POST":
                headers["Content-Type"] = "application/json"
                response = await client.post(
                    endpoint_url,
                    json=body,
                    headers=headers,
                    params=params
                )
            else:  # GET
                response = await client.get(
                    endpoint_url,
                    headers=headers,
                    params=params
                )
            
            return {
                "success": 200 <= response.status_code < 300,
                "status_code": response.status_code,
                "body": response.text,
                "headers": dict(response.headers)
            }
    
    except httpx.TimeoutException:
        return {
            "success": False,
            "status_code": 0,
            "body": "Request timeout",
            "error": "timeout"
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": 0,
            "body": str(e),
            "error": "request_failed"
        }


def build_auth_data(integration: Dict[str, Any], credential: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build authentication data for an integration request.
    
    Priority:
    1. If credential_id is set, use saved credential
    2. Otherwise, use auth_overrides from integration
    
    Args:
        integration: Integration configuration
        credential: Optional saved credential document
    
    Returns:
        Dict with auth_type and auth_data
    """
    # Use saved credential if provided
    if credential:
        auth_type = credential.get("auth_type", "none")
        
        if auth_type == "basic":
            return {
                "auth_type": "basic",
                "auth_data": {
                    "username": credential.get("username", ""),
                    "password": decrypt_value(credential.get("password", ""))
                }
            }
        elif auth_type == "api_key":
            return {
                "auth_type": "api_key",
                "auth_data": {
                    "key_name": credential.get("key_name", "X-API-Key"),
                    "key_value": decrypt_value(credential.get("api_key", "")),
                    "location": credential.get("key_location", "header")
                }
            }
        elif auth_type == "bearer":
            return {
                "auth_type": "bearer",
                "auth_data": {
                    "token": decrypt_value(credential.get("token", ""))
                }
            }
    
    # Fall back to integration's auth_overrides
    auth_overrides = integration.get("auth_overrides", {})
    auth_type = auth_overrides.get("auth_type", "none")
    
    return {
        "auth_type": auth_type,
        "auth_data": auth_overrides.get("auth_data", {})
    }
