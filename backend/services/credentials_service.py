# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Credentials Service - Secure Credential Management

Handles:
- Secure storage with encryption
- Multiple auth types (API Key, Bearer, Basic, OAuth2, AWS, Custom Headers)
- Credential linking to integrations
- Credential validation and testing
"""

import os
import json
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)

# Debug marker to verify new code is loaded
logger.info("=" * 60)
logger.info("[CREDENTIALS SERVICE] NEW CODE LOADED - v3.2 (last_used_at fix)")
logger.info("=" * 60)


class AuthType(str, Enum):
    """Supported authentication types"""
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer"
    BASIC_AUTH = "basic"
    OAUTH2_CLIENT = "oauth2_client"  # Client credentials flow
    OAUTH2_TOKEN = "oauth2_token"    # Already have access token
    AWS_SIGNATURE = "aws"
    CUSTOM_HEADER = "custom_header"
    NONE = "none"


class CredentialCreate(BaseModel):
    """Model for creating a credential"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    auth_type: AuthType
    
    # API Key auth
    api_key: Optional[str] = None
    api_key_header: Optional[str] = Field(default="X-API-Key", description="Header name for API key")
    api_key_prefix: Optional[str] = Field(default=None, description="Prefix like 'Bearer ' or 'Token '")
    api_key_location: Optional[str] = Field(default="header", description="header or query")
    
    # Basic auth
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Bearer token
    bearer_token: Optional[str] = None
    
    # OAuth2 client credentials
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    token_url: Optional[str] = None
    scope: Optional[str] = None
    
    # OAuth2 token (pre-obtained)
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    
    # AWS
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: Optional[str] = None
    aws_service: Optional[str] = None
    
    # Custom headers
    custom_headers: Optional[Dict[str, str]] = None
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    integration_ids: List[str] = Field(default_factory=list)  # Link to integrations


class CredentialUpdate(BaseModel):
    """Model for updating a credential"""
    name: Optional[str] = None
    description: Optional[str] = None
    
    # Allow updating secret values
    api_key: Optional[str] = None
    password: Optional[str] = None
    bearer_token: Optional[str] = None
    client_secret: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    # Non-secret updates
    api_key_header: Optional[str] = None
    api_key_prefix: Optional[str] = None
    api_key_location: Optional[str] = None
    username: Optional[str] = None
    client_id: Optional[str] = None
    token_url: Optional[str] = None
    scope: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_region: Optional[str] = None
    aws_service: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    integration_ids: Optional[List[str]] = None


class StoredCredential(BaseModel):
    """Model for stored credential (returned from DB)"""
    credential_id: str
    name: str
    description: Optional[str] = None
    auth_type: AuthType
    
    # Non-sensitive fields (can be returned)
    api_key_header: Optional[str] = None
    api_key_prefix: Optional[str] = None
    api_key_location: Optional[str] = None
    username: Optional[str] = None
    client_id: Optional[str] = None
    token_url: Optional[str] = None
    scope: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_region: Optional[str] = None
    aws_service: Optional[str] = None
    
    # Custom headers (non-sensitive parts only)
    custom_header_names: Optional[List[str]] = None
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    integration_ids: List[str] = Field(default_factory=list)
    created_by: str
    created_at: datetime
    updated_at: datetime
    last_used_at: Optional[datetime] = None
    
    # Status
    has_secret: bool = True  # Indicates if there's an encrypted secret


class CredentialsVault:
    """
    Secure credentials vault with encryption
    
    Uses Fernet symmetric encryption with a key derived from 
    an environment variable or generated secret.
    """
    
    def __init__(self):
        self._fernet: Optional[Fernet] = None
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize encryption with key from environment or generate one"""
        # Get or generate encryption key
        key_env = os.environ.get("CREDENTIALS_ENCRYPTION_KEY")
        
        if key_env:
            # Use provided key (must be base64-encoded 32-byte key)
            try:
                self._fernet = Fernet(key_env.encode())
                logger.info("Using encryption key from environment")
            except Exception as e:
                logger.warning(f"Invalid encryption key in environment: {e}")
                self._generate_key()
        else:
            self._generate_key()
    
    def _generate_key(self):
        """Derive encryption key from configured salt + password (must be set via env vars)."""
        salt = os.environ.get("CREDENTIALS_SALT")
        password = os.environ.get("CREDENTIALS_PASSWORD")
        if not salt or not password:
            logger.error(
                "CREDENTIALS_SALT and CREDENTIALS_PASSWORD env vars are required for credential encryption. "
                "Set both to strong, random values. Falling back to non-persistent key (data loss on restart!)."
            )
            salt = salt or "T1-fallback-salt-CHANGE-ME"
            password = password or secrets.token_hex(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(key)
        logger.info("Derived encryption key from CREDENTIALS_SALT + CREDENTIALS_PASSWORD")
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string value"""
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string value"""
        if not ciphertext:
            return ""
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return ""
    
    def encrypt_dict(self, data: Dict[str, str]) -> str:
        """Encrypt a dictionary as JSON"""
        if not data:
            return ""
        return self.encrypt(json.dumps(data))
    
    def decrypt_dict(self, ciphertext: str) -> Dict[str, str]:
        """Decrypt a dictionary from JSON"""
        if not ciphertext:
            return {}
        try:
            return json.loads(self.decrypt(ciphertext))
        except:
            return {}


class OAuth2TokenCache:
    """
    Cache for OAuth2 access tokens.

    Stores tokens with their expiration times to avoid
    unnecessary token requests.
    """

    def __init__(self):
        self._tokens: Dict[str, Dict[str, Any]] = {}

    def get(self, credential_id: str) -> Optional[str]:
        """Get cached token if not expired"""
        cached = self._tokens.get(credential_id)
        if not cached:
            return None

        # Check expiration (with 60s buffer)
        expires_at = cached.get("expires_at")
        if expires_at and datetime.utcnow() >= expires_at - timedelta(seconds=60):
            # Token expired or about to expire
            del self._tokens[credential_id]
            return None

        return cached.get("access_token")

    def set(self, credential_id: str, access_token: str, expires_in: int = 3600):
        """Cache a token with expiration"""
        self._tokens[credential_id] = {
            "access_token": access_token,
            "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
            "cached_at": datetime.utcnow()
        }

    def invalidate(self, credential_id: str):
        """Remove token from cache"""
        if credential_id in self._tokens:
            del self._tokens[credential_id]


class CredentialsService:
    """
    Credentials management service

    Provides secure storage, retrieval, and management of credentials.
    """

    def __init__(self, db=None):
        self.vault = CredentialsVault()
        self.db = db
        self._memory_store: Dict[str, Dict[str, Any]] = {}  # Fallback storage
        self._oauth2_cache = OAuth2TokenCache()

    def set_db(self, db):
        """Set database instance"""
        self.db = db
    
    async def create(self, credential: CredentialCreate, created_by: str = "system") -> StoredCredential:
        """Create a new credential with encrypted secrets"""
        credential_id = f"cred_{secrets.token_urlsafe(16)}"
        now = datetime.utcnow()
        
        # Extract and encrypt sensitive values
        encrypted_secrets = {}
        
        if credential.auth_type == AuthType.API_KEY and credential.api_key:
            encrypted_secrets["api_key"] = self.vault.encrypt(credential.api_key)
        
        if credential.auth_type == AuthType.BASIC_AUTH and credential.password:
            encrypted_secrets["password"] = self.vault.encrypt(credential.password)
        
        if credential.auth_type == AuthType.BEARER_TOKEN:
            if credential.bearer_token:
                encrypted_secrets["bearer_token"] = self.vault.encrypt(credential.bearer_token)
            if credential.refresh_token:
                encrypted_secrets["refresh_token"] = self.vault.encrypt(credential.refresh_token)
        
        if credential.auth_type == AuthType.OAUTH2_CLIENT:
            if credential.client_secret:
                encrypted_secrets["client_secret"] = self.vault.encrypt(credential.client_secret)
        
        if credential.auth_type == AuthType.OAUTH2_TOKEN:
            if credential.access_token:
                encrypted_secrets["access_token"] = self.vault.encrypt(credential.access_token)
            if credential.refresh_token:
                encrypted_secrets["refresh_token"] = self.vault.encrypt(credential.refresh_token)
        
        if credential.auth_type == AuthType.AWS_SIGNATURE and credential.aws_secret_access_key:
            encrypted_secrets["aws_secret_access_key"] = self.vault.encrypt(credential.aws_secret_access_key)
        
        if credential.auth_type == AuthType.CUSTOM_HEADER and credential.custom_headers:
            encrypted_secrets["custom_headers"] = self.vault.encrypt_dict(credential.custom_headers)
        
        # Build storage record
        record = {
            "credential_id": credential_id,
            "name": credential.name,
            "description": credential.description,
            "auth_type": credential.auth_type.value,
            
            # Non-sensitive config
            "api_key_header": credential.api_key_header,
            "api_key_prefix": credential.api_key_prefix,
            "api_key_location": credential.api_key_location,
            "username": credential.username,
            "client_id": credential.client_id,
            "token_url": credential.token_url,
            "scope": credential.scope,
            "aws_access_key_id": credential.aws_access_key_id,
            "aws_region": credential.aws_region,
            "aws_service": credential.aws_service,
            "token_expires_at": credential.token_expires_at.isoformat() if credential.token_expires_at else None,
            
            # Custom header names (not values)
            "custom_header_names": list(credential.custom_headers.keys()) if credential.custom_headers else None,
            
            # Encrypted secrets (stored as JSON blob)
            "encrypted_secrets": json.dumps(encrypted_secrets),
            
            # Metadata
            "tags": credential.tags,
            "integration_ids": credential.integration_ids,
            "created_by": created_by,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "last_used_at": None,
        }
        
        # Store in database or memory
        logger.debug(f"About to store credential {credential_id}")
        db = self._get_db()
        logger.debug(f"_get_db() returned: {db}")
        if db:
            logger.debug(f"Database available, calling _store_to_db()")
            await self._store_to_db(record)
            logger.debug(f"_store_to_db() completed")
        else:
            logger.warning(f"No database, storing credential {credential_id} in memory only!")
            self._memory_store[credential_id] = record

        logger.debug(f"Returning stored credential")
        return self._to_stored_credential(record)
    
    async def get(self, credential_id: str, include_secrets: bool = False) -> Optional[StoredCredential]:
        """Get a credential by ID"""
        record = await self._get_record(credential_id)
        if not record:
            return None
        
        if include_secrets:
            # Decrypt and return full credential
            return self._to_full_credential(record)
        
        return self._to_stored_credential(record)
    
    async def list(
        self,
        auth_type: Optional[AuthType] = None,
        integration_id: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> List[StoredCredential]:
        """List credentials with optional filters"""
        records = await self._get_all_records()
        
        # Apply filters
        if auth_type:
            records = [r for r in records if r.get("auth_type") == auth_type.value]
        
        if integration_id:
            records = [r for r in records if integration_id in r.get("integration_ids", [])]
        
        if tags:
            records = [r for r in records if any(t in r.get("tags", []) for t in tags)]
        
        return [self._to_stored_credential(r) for r in records]
    
    async def update(self, credential_id: str, updates: CredentialUpdate) -> Optional[StoredCredential]:
        """Update a credential"""
        record = await self._get_record(credential_id)
        if not record:
            return None
        
        # Update non-sensitive fields
        if updates.name is not None:
            record["name"] = updates.name
        if updates.description is not None:
            record["description"] = updates.description
        if updates.api_key_header is not None:
            record["api_key_header"] = updates.api_key_header
        if updates.api_key_prefix is not None:
            record["api_key_prefix"] = updates.api_key_prefix
        if updates.api_key_location is not None:
            record["api_key_location"] = updates.api_key_location
        if updates.username is not None:
            record["username"] = updates.username
        if updates.client_id is not None:
            record["client_id"] = updates.client_id
        if updates.token_url is not None:
            record["token_url"] = updates.token_url
        if updates.scope is not None:
            record["scope"] = updates.scope
        if updates.aws_access_key_id is not None:
            record["aws_access_key_id"] = updates.aws_access_key_id
        if updates.aws_region is not None:
            record["aws_region"] = updates.aws_region
        if updates.aws_service is not None:
            record["aws_service"] = updates.aws_service
        if updates.tags is not None:
            record["tags"] = updates.tags
        if updates.integration_ids is not None:
            record["integration_ids"] = updates.integration_ids
        
        # Update encrypted secrets if provided
        encrypted_secrets = json.loads(record.get("encrypted_secrets", "{}"))
        
        if updates.api_key is not None:
            encrypted_secrets["api_key"] = self.vault.encrypt(updates.api_key)
        if updates.password is not None:
            encrypted_secrets["password"] = self.vault.encrypt(updates.password)
        if updates.bearer_token is not None:
            encrypted_secrets["bearer_token"] = self.vault.encrypt(updates.bearer_token)
        if updates.client_secret is not None:
            encrypted_secrets["client_secret"] = self.vault.encrypt(updates.client_secret)
        if updates.access_token is not None:
            encrypted_secrets["access_token"] = self.vault.encrypt(updates.access_token)
        if updates.refresh_token is not None:
            encrypted_secrets["refresh_token"] = self.vault.encrypt(updates.refresh_token)
        if updates.aws_secret_access_key is not None:
            encrypted_secrets["aws_secret_access_key"] = self.vault.encrypt(updates.aws_secret_access_key)
        if updates.custom_headers is not None:
            encrypted_secrets["custom_headers"] = self.vault.encrypt_dict(updates.custom_headers)
            record["custom_header_names"] = list(updates.custom_headers.keys())
        
        record["encrypted_secrets"] = json.dumps(encrypted_secrets)
        record["updated_at"] = datetime.utcnow().isoformat()

        # Save
        db = self._get_db()
        if db:
            await self._update_in_db(credential_id, record)
        else:
            self._memory_store[credential_id] = record

        return self._to_stored_credential(record)
    
    async def delete(self, credential_id: str) -> bool:
        """Delete a credential"""
        db = self._get_db()
        if db:
            return await self._delete_from_db(credential_id)

        if credential_id in self._memory_store:
            del self._memory_store[credential_id]
            return True
        return False
    
    async def get_auth_headers(self, credential_id: str) -> Dict[str, str]:
        """
        Get authentication headers for a credential

        Returns ready-to-use headers for HTTP requests.
        """
        record = await self._get_record(credential_id)
        if not record:
            logger.warning(f"[get_auth_headers] Credential {credential_id} not found")
            return {}

        logger.info(f"[get_auth_headers] Found credential: {record.get('name')}, auth_type: {record.get('auth_type')}")

        # Get encrypted secrets - handle both string and dict
        raw_secrets = record.get("encrypted_secrets", "{}")
        if isinstance(raw_secrets, str):
            encrypted_secrets = json.loads(raw_secrets)
        elif isinstance(raw_secrets, dict):
            encrypted_secrets = raw_secrets
        else:
            logger.warning(f"[get_auth_headers] Unexpected encrypted_secrets type: {type(raw_secrets)}")
            encrypted_secrets = {}

        logger.info(f"[get_auth_headers] encrypted_secrets keys: {list(encrypted_secrets.keys())}")
        auth_type = record.get("auth_type")
        headers = {}

        # Handle API_KEY auth type, or NONE with an api_key in secrets (for Swagger imports)
        if auth_type == AuthType.API_KEY.value or (auth_type == AuthType.NONE.value and "api_key" in encrypted_secrets):
            encrypted_api_key = encrypted_secrets.get("api_key", "")
            logger.info(f"[get_auth_headers] encrypted_api_key present: {bool(encrypted_api_key)}")
            api_key = self.vault.decrypt(encrypted_api_key)
            logger.info(f"[get_auth_headers] decrypted api_key present: {bool(api_key)}")
            if api_key:
                header_name = record.get("api_key_header") or "X-API-Key"
                prefix = record.get("api_key_prefix") or ""
                location = record.get("api_key_location") or "header"
                logger.info(f"[get_auth_headers] API Key auth: header_name={header_name}, prefix={prefix}, location={location}")
                key_value = f"{prefix}{api_key}" if prefix else api_key
                if location == "query":
                    # Use special prefix so execution engine can extract as query param
                    headers[f"__auth_query__{header_name}"] = key_value
                    logger.info(f"[get_auth_headers] Added query param marker: __auth_query__{header_name}")
                else:
                    headers[header_name] = key_value
                    logger.info(f"[get_auth_headers] Added header: {header_name}")
            else:
                logger.warning(f"[get_auth_headers] No API key found or decrypt failed")
        
        elif auth_type == AuthType.BEARER_TOKEN.value:
            token = self.vault.decrypt(encrypted_secrets.get("bearer_token", ""))
            if token:
                headers["Authorization"] = f"Bearer {token}"
        
        elif auth_type == AuthType.BASIC_AUTH.value:
            import base64
            username = record.get("username", "")
            password = self.vault.decrypt(encrypted_secrets.get("password", ""))
            if username and password:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"
        
        elif auth_type == AuthType.OAUTH2_TOKEN.value:
            token = self.vault.decrypt(encrypted_secrets.get("access_token", ""))
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif auth_type == AuthType.OAUTH2_CLIENT.value:
            # OAuth2 Client Credentials Flow
            # First check cache for existing valid token
            cached_token = self._oauth2_cache.get(credential_id)
            if cached_token:
                headers["Authorization"] = f"Bearer {cached_token}"
                logger.info(f"[get_auth_headers] Using cached OAuth2 token for {credential_id}")
            else:
                # Need to acquire new token
                token_url = record.get("token_url")
                client_id = record.get("client_id")
                client_secret = self.vault.decrypt(encrypted_secrets.get("client_secret", ""))
                scope = record.get("scope")

                if token_url and client_id and client_secret:
                    try:
                        token_data = await self._acquire_oauth2_token(
                            token_url, client_id, client_secret, scope
                        )
                        if token_data and token_data.get("access_token"):
                            access_token = token_data["access_token"]
                            expires_in = token_data.get("expires_in", 3600)

                            # Cache the token
                            self._oauth2_cache.set(credential_id, access_token, expires_in)
                            headers["Authorization"] = f"Bearer {access_token}"
                            logger.info(f"[get_auth_headers] Acquired new OAuth2 token for {credential_id}, expires in {expires_in}s")
                        else:
                            logger.error(f"[get_auth_headers] Failed to acquire OAuth2 token: no access_token in response")
                    except Exception as e:
                        logger.error(f"[get_auth_headers] OAuth2 token acquisition failed: {e}")
                else:
                    logger.warning(f"[get_auth_headers] OAuth2 client credentials incomplete: token_url={bool(token_url)}, client_id={bool(client_id)}, client_secret={bool(client_secret)}")

        elif auth_type == AuthType.CUSTOM_HEADER.value:
            custom_headers = self.vault.decrypt_dict(encrypted_secrets.get("custom_headers", ""))
            headers.update(custom_headers)
        
        # Update last used timestamp
        await self._mark_used(credential_id)
        
        return headers
    
    async def test_credential(self, credential_id: str, test_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Test a credential by making a request
        
        Returns test result with status and any errors.
        """
        import httpx
        
        headers = await self.get_auth_headers(credential_id)
        if not headers:
            return {"success": False, "error": "No auth headers generated"}
        
        if not test_url:
            return {"success": True, "message": "Headers generated successfully", "headers_count": len(headers)}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(test_url, headers=headers, timeout=10.0)
                return {
                    "success": response.status_code < 400,
                    "status_code": response.status_code,
                    "message": "Connection successful" if response.status_code < 400 else f"HTTP {response.status_code}"
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # Private helper methods

    async def _acquire_oauth2_token(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Acquire OAuth2 access token using client credentials flow.

        Args:
            token_url: Token endpoint URL
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            scope: Optional scope string (space-separated)

        Returns:
            Token response dict with access_token, expires_in, etc.
        """
        import httpx

        # Build request payload
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }

        if scope:
            data["scope"] = scope

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        logger.info(f"[_acquire_oauth2_token] Requesting token from {token_url}")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=data,
                headers=headers,
                timeout=30.0
            )

            if response.status_code >= 400:
                error_text = response.text[:500]
                logger.error(f"[_acquire_oauth2_token] Token request failed: {response.status_code} - {error_text}")
                raise Exception(f"OAuth2 token request failed: HTTP {response.status_code}")

            token_data = response.json()
            logger.info(f"[_acquire_oauth2_token] Token acquired successfully, expires_in={token_data.get('expires_in', 'unknown')}")
            return token_data

    def invalidate_oauth2_token(self, credential_id: str):
        """Invalidate cached OAuth2 token (force re-acquisition)"""
        self._oauth2_cache.invalidate(credential_id)
        logger.info(f"[invalidate_oauth2_token] Invalidated cached token for {credential_id}")

    def _to_stored_credential(self, record: Dict[str, Any]) -> StoredCredential:
        """Convert record to StoredCredential (no secrets)"""
        encrypted_secrets = json.loads(record.get("encrypted_secrets", "{}"))
        
        return StoredCredential(
            credential_id=record["credential_id"],
            name=record["name"],
            description=record.get("description"),
            auth_type=AuthType(record["auth_type"]),
            api_key_header=record.get("api_key_header"),
            api_key_prefix=record.get("api_key_prefix"),
            api_key_location=record.get("api_key_location"),
            username=record.get("username"),
            client_id=record.get("client_id"),
            token_url=record.get("token_url"),
            scope=record.get("scope"),
            aws_access_key_id=record.get("aws_access_key_id"),
            aws_region=record.get("aws_region"),
            aws_service=record.get("aws_service"),
            custom_header_names=record.get("custom_header_names"),
            tags=record.get("tags", []),
            integration_ids=record.get("integration_ids", []),
            created_by=record.get("created_by", "unknown"),
            created_at=datetime.fromisoformat(record["created_at"]) if isinstance(record["created_at"], str) else record["created_at"],
            updated_at=datetime.fromisoformat(record["updated_at"]) if isinstance(record["updated_at"], str) else record["updated_at"],
            last_used_at=datetime.fromisoformat(record["last_used_at"]) if isinstance(record.get("last_used_at"), str) else record.get("last_used_at"),
            has_secret=bool(encrypted_secrets)
        )
    
    def _to_full_credential(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Convert record to full credential dict with decrypted secrets"""
        encrypted_secrets = json.loads(record.get("encrypted_secrets", "{}"))
        
        result = {
            "credential_id": record["credential_id"],
            "name": record["name"],
            "description": record.get("description"),
            "auth_type": record["auth_type"],
        }
        
        # Decrypt and add secrets
        for key in ["api_key", "password", "bearer_token", "client_secret", "access_token", "refresh_token", "aws_secret_access_key"]:
            if key in encrypted_secrets:
                result[key] = self.vault.decrypt(encrypted_secrets[key])
        
        if "custom_headers" in encrypted_secrets:
            result["custom_headers"] = self.vault.decrypt_dict(encrypted_secrets["custom_headers"])
        
        return result
    
    async def _get_record(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Get raw record from storage"""
        logger.info(f"[_get_record] Looking for credential: {credential_id}")
        logger.info(f"[_get_record] Memory store keys: {list(self._memory_store.keys())}")

        db = self._get_db()
        if db:
            logger.info(f"[_get_record] Trying database lookup...")
            result = await self._get_from_db(credential_id)
            if result:
                logger.info(f"[_get_record] Found in database")
                return result
            logger.info(f"[_get_record] Not found in database, checking memory store")
        else:
            logger.info(f"[_get_record] No database connection, checking memory store only")

        result = self._memory_store.get(credential_id)
        if result:
            logger.info(f"[_get_record] Found in memory store")
        else:
            logger.warning(f"[_get_record] Credential NOT FOUND anywhere!")
        return result
    
    async def _get_all_records(self) -> List[Dict[str, Any]]:
        """Get all records from storage"""
        records = []
        db = self._get_db()
        if db:
            try:
                records = await self._get_all_from_db()
            except Exception as e:
                logger.error(f"Failed to get from DB, using memory: {e}")
        # Merge with memory store
        memory_ids = set(r["credential_id"] for r in records)
        for cred_id, record in self._memory_store.items():
            if cred_id not in memory_ids:
                records.append(record)
        return records
    
    async def _mark_used(self, credential_id: str):
        """Update last_used_at timestamp"""
        record = await self._get_record(credential_id)
        if record:
            record["last_used_at"] = datetime.utcnow().isoformat()
            db = self._get_db()
            if db:
                await self._update_in_db(credential_id, record)
            else:
                self._memory_store[credential_id] = record
    
    # Database operations (to be implemented with actual DB)
    
    def _get_db(self):
        """Get database connection, falling back to postgres_db singleton"""
        logger.debug("Checking database connection...")
        logger.debug(f"self.db = {self.db}")
        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            logger.debug("Using cached self.db")
            return self.db
        # Fallback: try to get postgres_db directly
        try:
            from services.postgres_db import postgres_db
            logger.debug(f"postgres_db.connected = {postgres_db.connected}")
            logger.debug(f"postgres_db.pool = {postgres_db.pool}")
            if postgres_db.connected and postgres_db.pool:
                self.db = postgres_db  # Cache for future use
                logger.debug("SUCCESS - returning postgres_db")
                return postgres_db
            else:
                logger.debug("postgres_db not connected or no pool")
        except Exception as e:
            logger.debug(f"Exception: {e}")
        logger.debug("FAILED - returning None")
        return None

    async def _store_to_db(self, record: Dict[str, Any]):
        """Store credential to database"""
        # Always store in memory as backup
        self._memory_store[record["credential_id"]] = record
        logger.debug("========== STORING CREDENTIAL ==========")
        logger.debug(f"credential_id: {record['credential_id']}")
        logger.debug(f"name: {record['name']}")
        logger.debug(f"auth_type: {record['auth_type']}")
        logger.debug("Stored in memory as backup")

        db = self._get_db()
        if not db:
            logger.error("No database connection available!")
            logger.warning("Credential stored in memory only - WILL BE LOST ON RESTART")
            return

        logger.debug(f"Database connection OK, pool exists: {db.pool is not None}")
        try:
            async with db.tenant_acquire() as conn:
                logger.debug(f" Acquired connection from pool")

                # Prepare values for insert
                # Convert ISO strings to datetime objects for PostgreSQL
                created_at = record["created_at"]
                updated_at = record["updated_at"]
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at)
                if isinstance(updated_at, str):
                    updated_at = datetime.fromisoformat(updated_at)

                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'

                values = (
                    record["credential_id"],
                    record["name"],
                    record.get("description"),
                    record["auth_type"],
                    record.get("api_key_header"),
                    record.get("api_key_prefix"),
                    record.get("api_key_location"),
                    record.get("username"),
                    record.get("client_id"),
                    record.get("token_url"),
                    record.get("scope"),
                    record.get("aws_access_key_id"),
                    record.get("aws_region"),
                    record.get("aws_service"),
                    json.dumps(record.get("custom_header_names")),
                    record.get("encrypted_secrets"),
                    json.dumps(record.get("tags", [])),
                    json.dumps(record.get("integration_ids", [])),
                    record.get("created_by"),
                    created_at,
                    updated_at,
                    _tid
                )
                logger.debug(f" Executing INSERT with credential_id={values[0]}")

                result = await conn.execute('''
                    INSERT INTO credentials_vault (
                        credential_id, name, description, auth_type,
                        api_key_header, api_key_prefix, api_key_location,
                        username, client_id, token_url, scope,
                        aws_access_key_id, aws_region, aws_service,
                        custom_header_names, encrypted_secrets,
                        tags, integration_ids, created_by, created_at, updated_at, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
                    ON CONFLICT (credential_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        encrypted_secrets = EXCLUDED.encrypted_secrets,
                        tags = EXCLUDED.tags,
                        integration_ids = EXCLUDED.integration_ids,
                        updated_at = EXCLUDED.updated_at
                ''', *values)

                logger.debug(f" INSERT result: {result}")

                # Verify the insert by reading back
                verify_row = await conn.fetchrow(
                    'SELECT credential_id, name, auth_type FROM credentials_vault WHERE credential_id = $1',
                    record["credential_id"]
                )
                if verify_row:
                    logger.debug(f" VERIFIED: Credential exists in DB: {dict(verify_row)}")
                else:
                    logger.debug(f" WARNING: Credential NOT FOUND after insert!")

                # Count total credentials
                count = await conn.fetchval('SELECT COUNT(*) FROM credentials_vault')
                logger.debug(f" Total credentials in vault: {count}")

                logger.info(f"Credential {record['credential_id']} stored to database")
                logger.debug(f" SUCCESS: Credential stored to database")

        except Exception as e:
            import traceback
            logger.debug(f" EXCEPTION: {type(e).__name__}: {e}")
            logger.debug(f" Traceback: {traceback.format_exc()}")
            logger.error(f"Failed to store credential to DB: {e}")
            # Memory backup already done above
    
    async def _get_from_db(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Get credential from database"""
        db = self._get_db()
        if not db:
            return self._memory_store.get(credential_id)
        try:
            async with db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    'SELECT * FROM credentials_vault WHERE credential_id = $1',
                    credential_id
                )
                if row:
                    record = dict(row)
                    # Parse JSON fields
                    if record.get("tags"):
                        record["tags"] = json.loads(record["tags"]) if isinstance(record["tags"], str) else record["tags"]
                    if record.get("integration_ids"):
                        record["integration_ids"] = json.loads(record["integration_ids"]) if isinstance(record["integration_ids"], str) else record["integration_ids"]
                    if record.get("custom_header_names"):
                        record["custom_header_names"] = json.loads(record["custom_header_names"]) if isinstance(record["custom_header_names"], str) else record["custom_header_names"]
                    return record
        except Exception as e:
            logger.error(f"Failed to get credential from DB: {e}")
        
        # Fallback to memory
        return self._memory_store.get(credential_id)
    
    async def _get_all_from_db(self) -> List[Dict[str, Any]]:
        """Get all credentials from database"""
        db = self._get_db()
        if not db:
            return list(self._memory_store.values())
        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch('SELECT * FROM credentials_vault ORDER BY created_at DESC')
                records = []
                for row in rows:
                    record = dict(row)
                    if record.get("tags"):
                        record["tags"] = json.loads(record["tags"]) if isinstance(record["tags"], str) else record["tags"]
                    if record.get("integration_ids"):
                        record["integration_ids"] = json.loads(record["integration_ids"]) if isinstance(record["integration_ids"], str) else record["integration_ids"]
                    if record.get("custom_header_names"):
                        record["custom_header_names"] = json.loads(record["custom_header_names"]) if isinstance(record["custom_header_names"], str) else record["custom_header_names"]
                    records.append(record)
                return records
        except Exception as e:
            logger.error(f"Failed to get credentials from DB: {e}")
        
        # Fallback to memory
        return list(self._memory_store.values())
    
    async def _update_in_db(self, credential_id: str, record: Dict[str, Any]):
        """Update credential in database"""
        db = self._get_db()
        if not db:
            self._memory_store[credential_id] = record
            return
        try:
            # Convert ISO strings to datetime objects for PostgreSQL
            updated_at = record["updated_at"]
            last_used_at = record.get("last_used_at")
            if isinstance(updated_at, str):
                updated_at = datetime.fromisoformat(updated_at)
            if isinstance(last_used_at, str):
                last_used_at = datetime.fromisoformat(last_used_at)

            async with db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE credentials_vault SET
                        name = $2, description = $3,
                        api_key_header = $4, api_key_prefix = $5, api_key_location = $6,
                        username = $7, client_id = $8, token_url = $9, scope = $10,
                        aws_access_key_id = $11, aws_region = $12, aws_service = $13,
                        custom_header_names = $14, encrypted_secrets = $15,
                        tags = $16, integration_ids = $17, updated_at = $18, last_used_at = $19
                    WHERE credential_id = $1
                ''',
                    credential_id, record["name"], record.get("description"),
                    record.get("api_key_header"), record.get("api_key_prefix"), record.get("api_key_location"),
                    record.get("username"), record.get("client_id"), record.get("token_url"), record.get("scope"),
                    record.get("aws_access_key_id"), record.get("aws_region"), record.get("aws_service"),
                    json.dumps(record.get("custom_header_names")), record.get("encrypted_secrets"),
                    json.dumps(record.get("tags", [])), json.dumps(record.get("integration_ids", [])),
                    updated_at, last_used_at
                )
        except Exception as e:
            logger.error(f"Failed to update credential in DB: {e}")
            self._memory_store[credential_id] = record
    
    async def _delete_from_db(self, credential_id: str) -> bool:
        """Delete credential from database"""
        db = self._get_db()
        if not db:
            if credential_id in self._memory_store:
                del self._memory_store[credential_id]
                return True
            return False
        try:
            async with db.tenant_acquire() as conn:
                result = await conn.execute(
                    'DELETE FROM credentials_vault WHERE credential_id = $1',
                    credential_id
                )
                # Also remove from memory store
                if credential_id in self._memory_store:
                    del self._memory_store[credential_id]
                return "DELETE" in result
        except Exception as e:
            logger.error(f"Failed to delete credential from DB: {e}")
            if credential_id in self._memory_store:
                del self._memory_store[credential_id]
                return True
        return False


# Singleton instance
_credentials_service: Optional[CredentialsService] = None


def get_credentials_service() -> CredentialsService:
    """Get the global credentials service instance"""
    global _credentials_service
    if _credentials_service is None:
        _credentials_service = CredentialsService()
    return _credentials_service
