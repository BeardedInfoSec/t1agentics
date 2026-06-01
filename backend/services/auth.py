# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Authentication and User Management System
Implements JWT-based auth with role-based access control (RBAC).
"""

import os
import logging
import re
from typing import Optional, List
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
import secrets
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# Password Complexity Validation
# =============================================================================

SPECIAL_CHARACTERS = r'!@#$%^&*()_+\-=\[\]{}|;:,.<>?'

def validate_password_complexity(password: str) -> tuple:
    """
    Validate password meets complexity requirements.

    Requirements:
    - Minimum 12 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"

    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"

    return True, ""

# Configuration from environment variables
# CRITICAL: JWT_SECRET_KEY MUST be set via environment variables - no fallback
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "CRITICAL: JWT_SECRET_KEY environment variable is not set. "
        "Cannot start without a secret key."
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "720"))  # 12 hours default

# Admin credentials from environment (NEVER hardcode in production)
DEFAULT_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # No default - must be set
DEFAULT_ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@t1agentics.ai")


class UserRole(str, Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"


class Permission(str, Enum):
    """Granular permissions"""
    # Alert permissions
    CREATE_ALERT = "create_alert"
    VIEW_ALERT = "view_alert"
    DELETE_ALERT = "delete_alert"
    
    # Investigation permissions
    VIEW_INVESTIGATION = "view_investigation"
    DELETE_INVESTIGATION = "delete_investigation"
    FORWARD_INVESTIGATION = "forward_investigation"
    
    # Integration permissions
    MANAGE_INTEGRATIONS = "manage_integrations"
    VIEW_INTEGRATIONS = "view_integrations"
    
    # Webhook permissions
    MANAGE_WEBHOOKS = "manage_webhooks"
    VIEW_WEBHOOKS = "view_webhooks"
    
    # API Key permissions
    MANAGE_API_KEYS = "manage_api_keys"
    VIEW_API_KEYS = "view_api_keys"
    
    # User management
    MANAGE_USERS = "manage_users"
    VIEW_USERS = "view_users"
    
    # System
    VIEW_STATS = "view_stats"
    ADMIN_PANEL = "admin_panel"


# Role to permissions mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [p for p in Permission],  # All permissions
    UserRole.USER: [
        Permission.CREATE_ALERT,
        Permission.VIEW_ALERT,
        Permission.VIEW_INVESTIGATION,
        Permission.FORWARD_INVESTIGATION,
        Permission.VIEW_INTEGRATIONS,
        Permission.VIEW_WEBHOOKS,
        Permission.VIEW_STATS,
    ],
    UserRole.READONLY: [
        Permission.VIEW_ALERT,
        Permission.VIEW_INVESTIGATION,
        Permission.VIEW_INTEGRATIONS,
        Permission.VIEW_WEBHOOKS,
        Permission.VIEW_STATS,
    ]
}


# Password hashing - using bcrypt directly for better compatibility


class User(BaseModel):
    """User model"""
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.USER
    disabled: bool = False
    created_at: datetime = datetime.utcnow()
    last_login: Optional[datetime] = None
    tenant_id: Optional[str] = None  # Set by tenant middleware via request.state


class UserInDB(User):
    """User model with hashed password"""
    hashed_password: str


class UserCreate(BaseModel):
    """User creation model"""
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.USER


class UserUpdate(BaseModel):
    """User update model"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    disabled: Optional[bool] = None


class Token(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    username: str


class APIKey(BaseModel):
    """API Key model"""
    key_id: str
    name: str
    key_hash: str
    user_id: str
    role: UserRole
    permissions: List[Permission]
    created_at: datetime
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    enabled: bool = True


# In-memory storage (use database in production)
users_db: dict[str, UserInDB] = {}
api_keys_db: dict[str, APIKey] = {}


# Security utilities
security = HTTPBearer(auto_error=False)
from utils.auth_tokens import get_auth_token


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def decode_token(token: str) -> dict:
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except (jwt.DecodeError, jwt.InvalidTokenError, Exception) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate user with username and password"""
    user = users_db.get(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_api_key(name: str, user_id: str, role: UserRole, expires_days: Optional[int] = None) -> tuple[str, APIKey]:
    """Create a new API key"""
    # Generate random key
    api_key = f"T1 Agentics_{secrets.token_urlsafe(32)}"
    key_hash = get_password_hash(api_key)
    key_id = secrets.token_urlsafe(16)
    
    expires_at = None
    if expires_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
    
    api_key_obj = APIKey(
        key_id=key_id,
        name=name,
        key_hash=key_hash,
        user_id=user_id,
        role=role,
        permissions=ROLE_PERMISSIONS[role],
        created_at=datetime.utcnow(),
        expires_at=expires_at
    )
    
    api_keys_db[key_id] = api_key_obj
    
    return api_key, api_key_obj


def verify_api_key(api_key: str) -> Optional[APIKey]:
    """Verify an API key"""
    for key_obj in api_keys_db.values():
        if verify_password(api_key, key_obj.key_hash):
            # Check if expired
            if key_obj.expires_at and datetime.utcnow() > key_obj.expires_at:
                return None
            
            # Check if enabled
            if not key_obj.enabled:
                return None
            
            # Update last used
            key_obj.last_used = datetime.utcnow()
            
            return key_obj
    
    return None


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """Get current authenticated user from JWT token"""
    token = credentials.credentials if credentials else None
    if not token:
        token, _source = get_auth_token(request, None)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    payload = decode_token(token)
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user = users_db.get(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return User(**user.dict())


async def get_current_user_or_api_key(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> tuple[Optional[User], Optional[APIKey]]:
    """
    Get current user from either JWT token or API key.
    Returns (user, api_key) tuple.
    """
    token, _source = get_auth_token(request, authorization)
    if token:
        try:
            payload = decode_token(token)
            username = payload.get("sub")
            user = users_db.get(username)
            if user and not user.disabled:
                return User(**user.dict()), None
        except Exception:
            pass
    
    # Try as API key
    api_key_obj = verify_api_key(authorization) if authorization else None
    if api_key_obj:
        # Create a pseudo-user from API key
        user = User(
            username=f"api_key_{api_key_obj.key_id}",
            email="api@key.local",
            role=api_key_obj.role
        )
        return user, api_key_obj
    
    return None, None


def require_permission(permission: Permission):
    """Dependency to require specific permission"""
    async def permission_checker(user: User = Depends(get_current_user)):
        user_permissions = ROLE_PERMISSIONS.get(user.role, [])
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Required: {permission.value}"
            )
        return user
    return permission_checker


def require_role(required_role: UserRole):
    """Dependency to require specific role"""
    async def role_checker(user: User = Depends(get_current_user)):
        # Admin can do everything
        if user.role == UserRole.ADMIN:
            return user
        
        # Check if user has required role
        role_hierarchy = {
            UserRole.READONLY: 0,
            UserRole.USER: 1,
            UserRole.ADMIN: 2
        }
        
        if role_hierarchy.get(user.role, 0) < role_hierarchy.get(required_role, 2):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {required_role.value} required"
            )
        
        return user
    return role_checker


def init_default_users():
    """
    Initialize default admin user from environment variables.

    CRITICAL SECURITY: In production, you MUST set ADMIN_PASSWORD environment variable.
    The system will not create a default admin user without an explicitly set password.
    """
    if DEFAULT_ADMIN_USERNAME not in users_db:
        if not DEFAULT_ADMIN_PASSWORD:
            # In production, require explicit password
            logger.warning(
                "SECURITY WARNING: ADMIN_PASSWORD environment variable not set. "
                "Default admin user will NOT be created. "
                "Set ADMIN_PASSWORD to create the initial admin account."
            )
            return

        # Validate password strength
        if len(DEFAULT_ADMIN_PASSWORD) < 12:
            logger.warning(
                "SECURITY WARNING: ADMIN_PASSWORD is less than 12 characters. "
                "Consider using a stronger password in production."
            )

        admin_user = UserInDB(
            username=DEFAULT_ADMIN_USERNAME,
            email=DEFAULT_ADMIN_EMAIL,
            full_name="Administrator",
            role=UserRole.ADMIN,
            hashed_password=get_password_hash(DEFAULT_ADMIN_PASSWORD),
            created_at=datetime.utcnow()
        )
        users_db[DEFAULT_ADMIN_USERNAME] = admin_user
        logger.info(f"Admin user '{DEFAULT_ADMIN_USERNAME}' initialized from environment")


# Initialize on module load
init_default_users()
