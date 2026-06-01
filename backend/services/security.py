# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Security Module
Encryption, access control, and security utilities
"""

import os
import base64
import hashlib
import secrets
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps
from enum import Enum
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json

logger = logging.getLogger(__name__)


# ============================================================================
# ENCRYPTION AT REST
# ============================================================================

class EncryptionService:
    """
    Handles encryption at rest for sensitive data
    Uses Fernet symmetric encryption (AES-128-CBC with HMAC)
    """
    
    def __init__(self):
        self._key: Optional[bytes] = None
        self._fernet: Optional[Fernet] = None
        self._initialized = False
    
    def initialize(self, master_key: Optional[str] = None):
        """
        Initialize encryption with a master key
        Key should be stored securely (env var, secrets manager, HSM)
        """
        if master_key:
            # Derive key from master key using PBKDF2
            self._key = self._derive_key(master_key)
        else:
            # Try to get from environment
            env_key = os.environ.get('T1 Agentics_ENCRYPTION_KEY')
            if env_key:
                self._key = self._derive_key(env_key)
            else:
                # Generate a new key (for development only!)
                logger.warning("No encryption key provided - generating ephemeral key. NOT FOR PRODUCTION!")
                self._key = Fernet.generate_key()
        
        self._fernet = Fernet(self._key)
        self._initialized = True
        logger.info("Encryption service initialized")
    
    def _derive_key(self, master_key: str) -> bytes:
        """Derive a Fernet-compatible key from a master key"""
        # Use a fixed salt for deterministic key derivation
        # In production, this should be stored securely
        salt = b'T1 Agentics_v1_salt_2024'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return key
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string and return base64-encoded ciphertext"""
        if not self._initialized:
            self.initialize()
        
        try:
            encrypted = self._fernet.encrypt(plaintext.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base64-encoded ciphertext"""
        if not self._initialized:
            self.initialize()
        
        try:
            decoded = base64.urlsafe_b64decode(ciphertext.encode())
            decrypted = self._fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """Encrypt specific fields in a dictionary"""
        result = dict(data)
        for field in fields:
            if field in result and result[field]:
                if isinstance(result[field], str):
                    result[field] = self.encrypt(result[field])
                elif isinstance(result[field], dict):
                    result[field] = self.encrypt(json.dumps(result[field]))
        return result
    
    def decrypt_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """Decrypt specific fields in a dictionary"""
        result = dict(data)
        for field in fields:
            if field in result and result[field]:
                try:
                    decrypted = self.decrypt(result[field])
                    # Try to parse as JSON
                    try:
                        result[field] = json.loads(decrypted)
                    except json.JSONDecodeError:
                        result[field] = decrypted
                except Exception:
                    pass  # Field might not be encrypted
        return result
    
    def hash_value(self, value: str) -> str:
        """Create a one-way hash of a value (for indexing encrypted data)"""
        return hashlib.sha256(value.encode()).hexdigest()
    
    def rotate_key(self, new_master_key: str) -> bytes:
        """
        Rotate to a new encryption key
        Returns the new key - caller must re-encrypt all data
        """
        old_key = self._key
        self._key = self._derive_key(new_master_key)
        self._fernet = Fernet(self._key)
        logger.info("Encryption key rotated")
        return old_key  # Return old key for re-encryption


# ============================================================================
# ACCESS CONTROL
# ============================================================================

class Permission(Enum):
    """Available permissions in the system"""
    # Alert permissions
    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"
    ALERTS_DELETE = "alerts:delete"
    
    # Investigation permissions
    INVESTIGATIONS_READ = "investigations:read"
    INVESTIGATIONS_WRITE = "investigations:write"
    INVESTIGATIONS_DELETE = "investigations:delete"
    
    # IOC permissions
    IOCS_READ = "iocs:read"
    IOCS_WRITE = "iocs:write"
    
    # Integration permissions
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_WRITE = "integrations:write"
    INTEGRATIONS_EXECUTE = "integrations:execute"
    
    # Ingestion permissions (INTERNAL ONLY)
    INGESTION_READ = "ingestion:read"
    INGESTION_WRITE = "ingestion:write"
    INGESTION_PROCESS = "ingestion:process"
    
    # Admin permissions
    ADMIN_USERS = "admin:users"
    ADMIN_SYSTEM = "admin:system"
    ADMIN_AUDIT = "admin:audit"
    
    # Webhook permissions
    WEBHOOKS_READ = "webhooks:read"
    WEBHOOKS_WRITE = "webhooks:write"
    WEBHOOKS_INGEST = "webhooks:ingest"


class Role(Enum):
    """Pre-defined roles with permission sets"""
    VIEWER = "viewer"
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    ADMIN = "admin"
    SYSTEM = "system"  # Internal system role
    SERVICE = "service"  # Service-to-service communication


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[Role, List[Permission]] = {
    Role.VIEWER: [
        Permission.ALERTS_READ,
        Permission.INVESTIGATIONS_READ,
        Permission.IOCS_READ,
    ],
    Role.ANALYST: [
        Permission.ALERTS_READ,
        Permission.ALERTS_WRITE,
        Permission.INVESTIGATIONS_READ,
        Permission.INVESTIGATIONS_WRITE,
        Permission.IOCS_READ,
        Permission.IOCS_WRITE,
        Permission.INTEGRATIONS_READ,
        Permission.INTEGRATIONS_EXECUTE,
    ],
    Role.SENIOR_ANALYST: [
        Permission.ALERTS_READ,
        Permission.ALERTS_WRITE,
        Permission.ALERTS_DELETE,
        Permission.INVESTIGATIONS_READ,
        Permission.INVESTIGATIONS_WRITE,
        Permission.INVESTIGATIONS_DELETE,
        Permission.IOCS_READ,
        Permission.IOCS_WRITE,
        Permission.INTEGRATIONS_READ,
        Permission.INTEGRATIONS_WRITE,
        Permission.INTEGRATIONS_EXECUTE,
        Permission.WEBHOOKS_READ,
        Permission.WEBHOOKS_WRITE,
        Permission.INGESTION_READ,
    ],
    Role.ADMIN: [p for p in Permission],  # All permissions
    Role.SYSTEM: [p for p in Permission],  # All permissions (internal)
    Role.SERVICE: [
        Permission.WEBHOOKS_INGEST,
        Permission.INGESTION_PROCESS,
        Permission.ALERTS_WRITE,
        Permission.IOCS_WRITE,
    ],
}


@dataclass
class AccessContext:
    """Context for access control decisions"""
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Role = Role.VIEWER
    permissions: List[Permission] = None
    is_internal: bool = False  # True for internal service calls
    is_authenticated: bool = False
    api_key_id: Optional[str] = None
    source_ip: Optional[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = ROLE_PERMISSIONS.get(self.role, [])
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if context has a specific permission"""
        return permission in self.permissions or self.role == Role.ADMIN
    
    def has_any_permission(self, permissions: List[Permission]) -> bool:
        """Check if context has any of the specified permissions"""
        return any(self.has_permission(p) for p in permissions)
    
    def has_all_permissions(self, permissions: List[Permission]) -> bool:
        """Check if context has all of the specified permissions"""
        return all(self.has_permission(p) for p in permissions)


class AccessControl:
    """
    Role-based access control (RBAC) manager
    """
    
    # Endpoints that are internal-only (not exposed to external API)
    INTERNAL_ONLY_ENDPOINTS = [
        "/api/v1/ingestion/pipeline/process",
        "/api/v1/ingestion/pipeline/process-batch",
        "/api/internal/",
    ]
    
    # Endpoints that require specific permissions
    ENDPOINT_PERMISSIONS: Dict[str, List[Permission]] = {
        # Ingestion - mostly internal
        "/api/v1/ingestion/extractions": [Permission.INGESTION_READ],
        "/api/v1/ingestion/transforms": [Permission.INGESTION_READ],
        "/api/v1/ingestion/pipeline": [Permission.INGESTION_PROCESS],
        "/api/v1/ingestion/import": [Permission.INGESTION_WRITE],
        "/api/v1/ingestion/export": [Permission.INGESTION_READ],
        
        # Admin endpoints
        "/api/v1/admin/users": [Permission.ADMIN_USERS],
        "/api/v1/admin/system": [Permission.ADMIN_SYSTEM],
        "/api/v1/admin/audit": [Permission.ADMIN_AUDIT],
    }
    
    @classmethod
    def is_internal_only(cls, path: str) -> bool:
        """Check if an endpoint is internal-only"""
        return any(path.startswith(ep) for ep in cls.INTERNAL_ONLY_ENDPOINTS)
    
    @classmethod
    def get_required_permissions(cls, path: str, method: str = "GET") -> List[Permission]:
        """Get required permissions for an endpoint"""
        for endpoint, permissions in cls.ENDPOINT_PERMISSIONS.items():
            if path.startswith(endpoint):
                return permissions
        return []
    
    @classmethod
    def check_access(cls, context: AccessContext, path: str, method: str = "GET") -> bool:
        """
        Check if the access context has permission to access an endpoint
        """
        # Internal-only endpoints require internal context
        if cls.is_internal_only(path):
            if not context.is_internal:
                logger.warning(f"External access attempt to internal endpoint: {path}")
                return False
        
        # Check endpoint permissions
        required = cls.get_required_permissions(path, method)
        if required and not context.has_any_permission(required):
            logger.warning(f"Permission denied for {context.username} on {path}")
            return False
        
        return True


# ============================================================================
# SENSITIVE DATA HANDLING
# ============================================================================

class SensitiveDataHandler:
    """
    Handles masking and redaction of sensitive data
    """
    
    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = {
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'api_key': r'\b(api[_-]?key|apikey|access[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
        'password': r'\b(password|passwd|pwd)["\s:=]+["\']?([^\s"\']+)["\']?',
        'private_key': r'-----BEGIN (RSA |EC |)PRIVATE KEY-----',
    }
    
    # Fields that should always be encrypted at rest
    ENCRYPTED_FIELDS = [
        'password',
        'api_key',
        'secret',
        'token',
        'private_key',
        'credentials',
        'hec_token',
    ]
    
    # Fields that should be masked in logs/display
    MASKED_FIELDS = [
        'password',
        'api_key',
        'secret',
        'token',
        'authorization',
        'cookie',
        'credit_card',
        'ssn',
    ]
    
    @classmethod
    def mask_value(cls, value: str, visible_chars: int = 4) -> str:
        """Mask a sensitive value, showing only last N characters"""
        if not value or len(value) <= visible_chars:
            return '*' * 8
        return '*' * (len(value) - visible_chars) + value[-visible_chars:]
    
    @classmethod
    def mask_dict(cls, data: Dict[str, Any], additional_fields: List[str] = None) -> Dict[str, Any]:
        """Mask sensitive fields in a dictionary for logging/display"""
        fields_to_mask = cls.MASKED_FIELDS + (additional_fields or [])
        result = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            if any(f in key_lower for f in fields_to_mask):
                if isinstance(value, str):
                    result[key] = cls.mask_value(value)
                else:
                    result[key] = '***MASKED***'
            elif isinstance(value, dict):
                result[key] = cls.mask_dict(value, additional_fields)
            elif isinstance(value, list):
                result[key] = [
                    cls.mask_dict(v, additional_fields) if isinstance(v, dict) else v
                    for v in value
                ]
            else:
                result[key] = value
        
        return result
    
    @classmethod
    def get_fields_to_encrypt(cls, data: Dict[str, Any]) -> List[str]:
        """Identify fields that should be encrypted"""
        fields = []
        for key in data.keys():
            key_lower = key.lower()
            if any(f in key_lower for f in cls.ENCRYPTED_FIELDS):
                fields.append(key)
        return fields
    
    @classmethod
    def redact_for_audit(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data for audit logging"""
        return cls.mask_dict(data)


# ============================================================================
# AUDIT LOGGING
# ============================================================================

@dataclass
class AuditEvent:
    """Represents an audit log event"""
    timestamp: datetime
    event_type: str
    actor: str
    actor_type: str  # 'user', 'system', 'service'
    action: str
    resource_type: str
    resource_id: Optional[str]
    outcome: str  # 'success', 'failure', 'denied'
    details: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'actor': self.actor,
            'actor_type': self.actor_type,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'outcome': self.outcome,
            'details': SensitiveDataHandler.redact_for_audit(self.details),
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
        }


class AuditLogger:
    """
    Security audit logging
    """
    
    def __init__(self):
        self.logger = logging.getLogger('audit')
        self._db = None
    
    def set_database(self, db):
        """Set database for persistent audit logging"""
        self._db = db
    
    async def log(self, event: AuditEvent):
        """Log an audit event"""
        # Always log to file
        self.logger.info(json.dumps(event.to_dict()))
        
        # Also persist to database if available
        if self._db:
            try:
                await self._db.save_audit_event(event.to_dict())
            except Exception as e:
                self.logger.error(f"Failed to persist audit event: {e}")
    
    async def log_access(
        self,
        context: AccessContext,
        action: str,
        resource_type: str,
        resource_id: str = None,
        outcome: str = "success",
        details: Dict = None
    ):
        """Log an access event"""
        event = AuditEvent(
            timestamp=datetime.utcnow(),
            event_type="access",
            actor=context.username or context.user_id or "anonymous",
            actor_type="user" if context.user_id else "system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            details=details or {},
            source_ip=context.source_ip,
        )
        await self.log(event)
    
    async def log_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "info",
        details: Dict = None
    ):
        """Log a security-relevant event"""
        event = AuditEvent(
            timestamp=datetime.utcnow(),
            event_type=f"security.{event_type}",
            actor="system",
            actor_type="system",
            action=event_type,
            resource_type="system",
            resource_id=None,
            outcome=severity,
            details={"description": description, **(details or {})},
        )
        await self.log(event)


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

encryption_service = EncryptionService()
audit_logger = AuditLogger()


# ============================================================================
# DECORATORS FOR ROUTE PROTECTION
# ============================================================================

def require_permission(*permissions: Permission):
    """Decorator to require specific permissions for an endpoint"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get access context from request
            request = kwargs.get('request')
            context = getattr(request.state, 'access_context', None) if request else None
            
            if not context or not context.is_authenticated:
                from fastapi import HTTPException
                raise HTTPException(401, "Authentication required")
            
            if not context.has_any_permission(list(permissions)):
                from fastapi import HTTPException
                raise HTTPException(403, "Insufficient permissions")
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def internal_only(func):
    """Decorator to mark an endpoint as internal-only"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request')
        context = getattr(request.state, 'access_context', None) if request else None
        
        if not context or not context.is_internal:
            from fastapi import HTTPException
            raise HTTPException(403, "This endpoint is internal-only")
        
        return await func(*args, **kwargs)
    return wrapper
