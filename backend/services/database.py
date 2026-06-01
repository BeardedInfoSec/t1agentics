# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Database Service - PostgreSQL Implementation
All data is stored in PostgreSQL. This module provides compatibility
with the original interface for backward compatibility.

MongoDB has been REMOVED - this is now a pure PostgreSQL implementation.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging
import uuid
import json

logger = logging.getLogger(__name__)


class DatabaseService:
    """
    Database service backed by PostgreSQL
    Provides same interface as old MongoDB service for compatibility
    """
    
    def __init__(self):
        self.connected = False
        self._postgres = None
        
    async def connect(self):
        """Connect - delegates to PostgreSQL"""
        try:
            from services.postgres_db import postgres_db
            self._postgres = postgres_db
            
            if postgres_db.connected:
                self.connected = True
                logger.info("Database service connected (PostgreSQL backend)")
            else:
                await postgres_db.connect()
                if postgres_db.connected:
                    self.connected = True
                    logger.info("Database service connected (PostgreSQL backend)")
                else:
                    self.connected = False
                    logger.warning("Database service: PostgreSQL not available")
                    
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            self.connected = False
    
    async def disconnect(self):
        """Disconnect"""
        self.connected = False
        logger.info("Database service disconnected")
    
    def _get_pool(self):
        """Get PostgreSQL connection pool"""
        if self._postgres and self._postgres.pool:
            return self._postgres.pool
        return None
    
    # ================== USERS ==================
    
    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        if not self.connected:
            # Try to reconnect
            await self.connect()
        if not self.connected:
            return None
        return await self._postgres.get_user_by_username(username)
    
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email (uses admin bypass to check across all tenants)."""
        pool = self._get_pool()
        if not pool:
            return None
        async with pool.acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            try:
                row = await conn.fetchrow(
                    'SELECT * FROM users WHERE email = $1',
                    email
                )
                return dict(row) if row else None
            finally:
                try:
                    await conn.execute("RESET app.is_platform_admin")
                except Exception:
                    pass
    
    async def create_user(self, user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create new user with tenant_id from context or explicit value."""
        pool = self._get_pool()
        if not pool:
            raise RuntimeError("Database not connected")

        # Get tenant_id from explicit value or current context
        tenant_id = user.get('tenant_id')
        if not tenant_id:
            from middleware.tenant_middleware import get_current_tenant_id
            tenant_id = get_current_tenant_id()

        created_at = datetime.utcnow()
        async with pool.acquire() as conn:
            await conn.execute('''
                INSERT INTO users (tenant_id, username, email, full_name, role, hashed_password, disabled, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ''',
                tenant_id,
                user.get('username'),
                user.get('email'),
                user.get('full_name'),
                user.get('role', 'analyst'),
                user.get('hashed_password'),
                user.get('disabled', False),
                created_at
            )

        return {
            'username': user.get('username'),
            'email': user.get('email'),
            'full_name': user.get('full_name'),
            'role': user.get('role', 'analyst'),
            'disabled': user.get('disabled', False),
            'created_at': created_at,
            'last_login': None
        }
    
    async def update_user(self, username: str, updates: Dict[str, Any]) -> bool:
        """Update user"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            set_clauses = []
            values = []
            idx = 1
            for key, value in updates.items():
                set_clauses.append(f"{key} = ${idx}")
                values.append(value)
                idx += 1
            values.append(username)
            
            async with pool.acquire() as conn:
                await conn.execute(
                    f"UPDATE users SET {', '.join(set_clauses)} WHERE username = ${idx}",
                    *values
                )
            return True
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            return False
    
    async def delete_user(self, username: str) -> bool:
        """Delete user (soft delete)"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET disabled = TRUE WHERE username = $1",
                    username
                )
            return True
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False
    
    async def update_last_login(self, username: str) -> bool:
        """Update user's last login timestamp"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET last_login = $1 WHERE username = $2",
                    datetime.utcnow(), username
                )
            return True
        except:
            return False
    
    async def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users"""
        if not self.connected:
            return []
        return await self._postgres.get_all_users()
    
    # ================== ALERTS ==================
    
    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert by ID"""
        if not self.connected:
            return None
        return await self._postgres.get_alert_by_id(alert_id)
    
    async def get_alerts(self, limit: int = 100, skip: int = 0, **filters) -> List[Dict[str, Any]]:
        """Get alerts with filters"""
        if not self.connected:
            return []
        return await self._postgres.get_alerts(
            limit=limit,
            offset=skip,
            status=filters.get('status'),
            severity=filters.get('severity'),
            source=filters.get('source')
        )
    
    async def create_alert(self, alert: Dict[str, Any]) -> Optional[str]:
        """Create new alert"""
        if not self.connected:
            return None
        return await self._postgres.create_alert(alert)
    
    async def get_alert_by_external_id(self, external_id: str, source: str) -> Optional[Dict[str, Any]]:
        """Get alert by external ID"""
        if not self.connected:
            return None
        return await self._postgres.get_alert_by_external_id(external_id, source)
    
    async def count_alerts(self, **filters) -> int:
        """Count alerts"""
        if not self.connected:
            return 0
        alerts = await self._postgres.get_alerts(limit=10000)
        return len(alerts)
    
    # ================== INVESTIGATIONS ==================
    
    async def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Get investigation by ID"""
        if not self.connected:
            return None
        return await self._postgres.get_investigation_by_id(investigation_id)
    
    async def save_investigation(self, investigation: Dict[str, Any]) -> bool:
        """Save/create investigation"""
        if not self.connected:
            logger.error("save_investigation: not connected")
            return False
        try:
            await self._postgres.create_investigation(investigation)
            return True
        except Exception as e:
            logger.error(f"save_investigation error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    async def create_investigation(self, investigation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create investigation and return the result"""
        if not self.connected:
            return None
        try:
            inv_id = await self._postgres.create_investigation(investigation)
            return {
                'investigation_id': inv_id,
                **investigation
            }
        except Exception as e:
            logger.error(f"Error creating investigation: {e}")
            return None
    
    async def get_alert_investigation(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get investigation for an alert"""
        if not self.connected:
            return None
        return await self._postgres.get_alert_investigation(alert_id)
    
    # ================== API KEYS ==================
    
    async def create_api_key(self, key_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create API key"""
        pool = self._get_pool()
        if not pool:
            return None
        try:
            key_id = key_data.get('key_id') or f"key_{uuid.uuid4().hex[:12]}"
            created_at = datetime.utcnow()
            
            async with pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO api_keys (key_id, name, key_hash, role, created_by, created_at, expires_at, enabled)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (key_id) DO NOTHING
                ''',
                    key_id,
                    key_data.get('name'),
                    key_data.get('api_key', key_data.get('key_hash', '')),
                    key_data.get('role', 'user'),
                    key_data.get('created_by', 'admin'),
                    created_at,
                    key_data.get('expires_at'),
                    True
                )
            
            key_data['key_id'] = key_id
            key_data['created_at'] = created_at
            return key_data
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            # Return with defaults if error
            key_data['key_id'] = key_data.get('key_id') or f"key_{uuid.uuid4().hex[:12]}"
            key_data['created_at'] = datetime.utcnow()
            return key_data
    
    async def get_all_api_keys(self) -> List[Dict[str, Any]]:
        """Get all API keys"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch('SELECT * FROM api_keys ORDER BY created_at DESC')
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting API keys: {e}")
            return []
    
    async def get_api_key_by_id(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get API key by ID"""
        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow('SELECT * FROM api_keys WHERE key_id = $1', key_id)
                return dict(row) if row else None
        except:
            return None
    
    async def update_api_key(self, key_id: str, updates: Dict[str, Any]) -> bool:
        """Update API key"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                if 'enabled' in updates:
                    await conn.execute(
                        'UPDATE api_keys SET enabled = $1 WHERE key_id = $2',
                        updates['enabled'], key_id
                    )
            return True
        except:
            return False
    
    async def delete_api_key(self, key_id: str) -> bool:
        """Delete API key"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute('DELETE FROM api_keys WHERE key_id = $1', key_id)
            return True
        except:
            return False
    
    # ================== IOCs ==================
    
    async def track_ioc(self, ioc_data: Dict[str, Any]) -> bool:
        """Track or update IOC"""
        if not self.connected:
            return False
        try:
            # Normalize IOC type to match DB CHECK constraint
            normalized = dict(ioc_data)
            raw_type = normalized.get('ioc_type', '')
            type_map = {"md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256", "filename": "file_path"}
            if raw_type in type_map:
                normalized['ioc_type'] = type_map[raw_type]
            await self._postgres.track_ioc(normalized)
            return True
        except:
            return False

    async def track_or_update_ioc(self, ioc_data: Dict[str, Any]) -> bool:
        """Alias for track_ioc - used by ioc_extractor.extract_and_track()"""
        return await self.track_ioc(ioc_data)

    async def get_tracked_ioc(self, ioc_value: str, ioc_type: str = None) -> Optional[Dict[str, Any]]:
        """Get tracked IOC"""
        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                if ioc_type:
                    row = await conn.fetchrow(
                        'SELECT * FROM iocs WHERE ioc_value = $1 AND ioc_type = $2',
                        ioc_value, ioc_type
                    )
                else:
                    row = await conn.fetchrow(
                        'SELECT * FROM iocs WHERE ioc_value = $1',
                        ioc_value
                    )
                return dict(row) if row else None
        except:
            return None
    
    async def get_all_tracked_iocs(self, ioc_type: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all tracked IOCs"""
        if not self.connected:
            return []
        return await self._postgres.get_iocs(ioc_type=ioc_type, limit=limit)
    
    async def get_ioc_correlations(self, ioc_values: List[str]) -> Dict[str, Any]:
        """Get IOC correlations"""
        correlations = {}
        for ioc_value in ioc_values:
            ioc = await self.get_tracked_ioc(ioc_value)
            if ioc:
                correlations[ioc_value] = {
                    'seen_count': ioc.get('seen_count', 1),
                    'investigations': [],
                    'severity': ioc.get('severity', 'unknown')
                }
        return correlations
    
    # ================== CREDENTIALS ==================
    
    async def get_all_credentials(self) -> List[Dict[str, Any]]:
        """Get all stored credentials"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch('SELECT * FROM integration_credentials ORDER BY created_at DESC')
                credentials = []
                for row in rows:
                    cred = dict(row)
                    # Parse encrypted_value if it's JSON
                    if cred.get('encrypted_value'):
                        try:
                            extra = json.loads(cred['encrypted_value']) if isinstance(cred['encrypted_value'], str) else cred['encrypted_value']
                            cred['key_name'] = extra.get('key_name')
                            cred['key_location'] = extra.get('key_location')
                        except:
                            pass
                    cred['auth_type'] = cred.get('credential_type', 'api_key')
                    credentials.append(cred)
                return credentials
        except Exception as e:
            logger.error(f"Error getting credentials: {e}")
            return []
    
    async def create_credential(self, cred_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create credential"""
        pool = self._get_pool()
        if not pool:
            logger.error("No database pool available")
            return None
        try:
            cred_id = f"cred_{uuid.uuid4().hex[:12]}"
            created_at = datetime.utcnow()
            
            # Build encrypted value JSON - only include non-empty values
            encrypted_data = {}
            if cred_data.get('username'):
                encrypted_data['username'] = cred_data['username']
            if cred_data.get('password'):
                encrypted_data['password'] = cred_data['password']
            if cred_data.get('api_key'):
                encrypted_data['api_key'] = cred_data['api_key']
            if cred_data.get('token'):
                encrypted_data['token'] = cred_data['token']
            if cred_data.get('key_name'):
                encrypted_data['key_name'] = cred_data['key_name']
            if cred_data.get('key_location'):
                encrypted_data['key_location'] = cred_data['key_location']
            
            logger.info(f"Creating credential: {cred_data.get('name')} type={cred_data.get('auth_type')}")
            
            async with pool.acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                import uuid as _uuid
                _tenant_id = get_optional_tenant_id()

                await conn.execute('''
                    INSERT INTO integration_credentials (credential_id, name, credential_type, encrypted_value, integration_id, created_at, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                ''',
                    cred_id,
                    cred_data.get('name'),
                    cred_data.get('auth_type', cred_data.get('type', 'api_key')),
                    json.dumps(encrypted_data),
                    cred_data.get('integration_id'),
                    created_at,
                    _uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )
            
            logger.info(f"Credential created successfully: {cred_id}")
            
            return {
                'credential_id': cred_id,
                'name': cred_data.get('name'),
                'description': cred_data.get('description'),
                'auth_type': cred_data.get('auth_type', cred_data.get('type', 'api_key')),
                'created_by': cred_data.get('created_by', 'admin'),
                'created_at': created_at,
                'key_name': cred_data.get('key_name'),
                'key_location': cred_data.get('key_location')
            }
        except Exception as e:
            logger.error(f"Error creating credential: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    async def get_credential(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Get credential by ID"""
        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    'SELECT * FROM integration_credentials WHERE credential_id = $1',
                    credential_id
                )
                return dict(row) if row else None
        except:
            return None
    
    async def update_credential(self, credential_id: str, updates: Dict[str, Any]) -> bool:
        """Update credential"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                if 'name' in updates:
                    await conn.execute(
                        'UPDATE integration_credentials SET name = $1 WHERE credential_id = $2',
                        updates['name'], credential_id
                    )
            return True
        except:
            return False
    
    async def delete_credential(self, credential_id: str) -> bool:
        """Delete credential"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    'DELETE FROM integration_credentials WHERE credential_id = $1',
                    credential_id
                )
            return True
        except:
            return False
    
    # ================== INTEGRATIONS (Admin) ==================
    
    async def create_integration(self, integration_data: Dict[str, Any]) -> bool:
        """Create integration config"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO integrations (name, integration_type, config, enabled, created_at)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (name) DO UPDATE SET config = $3, enabled = $4
                ''',
                    integration_data.get('name'),
                    integration_data.get('type', 'custom'),
                    json.dumps(integration_data.get('config', {})),
                    integration_data.get('enabled', True),
                    datetime.utcnow()
                )
            return True
        except Exception as e:
            logger.error(f"Error creating integration: {e}")
            return False
    
    async def get_all_integrations(self) -> List[Dict[str, Any]]:
        """Get all integrations"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch('SELECT * FROM integrations ORDER BY name')
                return [dict(row) for row in rows]
        except:
            return []
    
    async def update_integration(self, name: str, updates: Dict[str, Any]) -> bool:
        """Update integration"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                if 'enabled' in updates:
                    await conn.execute(
                        'UPDATE integrations SET enabled = $1 WHERE name = $2',
                        updates['enabled'], name
                    )
                if 'config' in updates:
                    await conn.execute(
                        'UPDATE integrations SET config = $1 WHERE name = $2',
                        json.dumps(updates['config']), name
                    )
            return True
        except:
            return False
    
    async def delete_integration(self, name: str) -> bool:
        """Delete integration"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute('DELETE FROM integrations WHERE name = $1', name)
            return True
        except:
            return False
    
    # ================== WEBHOOKS ==================
    
    async def get_webhooks(self) -> List[Dict[str, Any]]:
        """Get webhooks from webhooks table"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM webhooks ORDER BY created_at DESC"
                )
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting webhooks: {e}")
            return []
    
    async def get_all_webhooks(self) -> List[Dict[str, Any]]:
        """Get all webhooks - alias for get_webhooks"""
        return await self.get_webhooks()
    
    async def create_webhook(self, webhook: Dict[str, Any]) -> Dict[str, Any]:
        """Create webhook in webhooks table"""
        pool = self._get_pool()
        if not pool:
            return webhook
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO webhooks (name, description, endpoint_path, token, enabled, rate_limit, created_by, trigger_count)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (name) DO UPDATE SET
                        description = EXCLUDED.description,
                        enabled = EXCLUDED.enabled,
                        rate_limit = EXCLUDED.rate_limit
                    RETURNING *
                ''',
                    webhook.get('name'),
                    webhook.get('description'),
                    webhook.get('endpoint_path', f"/api/v1/webhooks/ingest/{webhook.get('name')}"),
                    webhook.get('token'),
                    webhook.get('enabled', True),
                    webhook.get('rate_limit', 100),
                    webhook.get('created_by', 'admin'),
                    webhook.get('trigger_count', 0)
                )
                return dict(row) if row else webhook
        except Exception as e:
            logger.error(f"Error creating webhook: {e}")
            raise e
    
    async def get_webhook(self, webhook_name: str) -> Optional[Dict[str, Any]]:
        """Get webhook by name.

        Uses platform_admin bypass to read ANY tenant's webhook,
        since the ingestion endpoint resolves tenant from the webhook record.
        """
        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                row = await conn.fetchrow(
                    "SELECT * FROM webhooks WHERE name = $1",
                    webhook_name
                )
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting webhook: {e}")
            return None
    
    async def delete_webhook(self, webhook_name: str) -> bool:
        """Delete webhook by name"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM webhooks WHERE name = $1",
                    webhook_name
                )
                return 'DELETE' in result
        except Exception as e:
            logger.error(f"Error deleting webhook: {e}")
            return False
    
    async def save_webhook(self, webhook: Dict[str, Any]) -> bool:
        """Save webhook - alias for create_webhook"""
        result = await self.create_webhook(webhook)
        return result is not None

    async def update_webhook(
        self,
        webhook_name: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Update mutable fields on a webhook. Lookup is by `name` to match
        the rest of the webhook DB surface (create / get / delete all key
        on name). Returns the updated row, or None if not found.
        """
        if not updates:
            return await self.get_webhook(webhook_name)

        allowed = {"description", "rate_limit", "enabled", "name"}
        sets = []
        args: List[Any] = []
        for k, v in updates.items():
            if k in allowed and v is not None:
                args.append(v)
                sets.append(f"{k} = ${len(args)}")
        if not sets:
            return await self.get_webhook(webhook_name)

        args.append(webhook_name)
        sql = f"UPDATE webhooks SET {', '.join(sets)} WHERE name = ${len(args)} RETURNING *"

        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(sql, *args)
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error updating webhook: {e}")
            return None
    
    async def update_webhook_stats(self, webhook_name: str) -> bool:
        """Update webhook last_triggered and trigger_count"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute('''
                    UPDATE webhooks 
                    SET last_triggered = $1, trigger_count = trigger_count + 1
                    WHERE name = $2
                ''', datetime.utcnow(), webhook_name)
            return True
        except Exception as e:
            logger.error(f"Error updating webhook stats: {e}")
            return False
    
    async def create_log(self, log_data: Dict[str, Any]) -> bool:
        """Create a log entry"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                import uuid as _uuid
                _tenant_id = get_optional_tenant_id()

                await conn.execute('''
                    INSERT INTO audit_log (username, action, resource_type, resource_id, details, timestamp, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                ''',
                    log_data.get('source', 'system'),
                    log_data.get('message', log_data.get('action', '')),
                    log_data.get('level', 'info'),
                    '',
                    json.dumps(log_data.get('details', {})),
                    datetime.utcnow(),
                    _uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )
            return True
        except Exception as e:
            logger.error(f"Error creating log: {e}")
            return False
    
    # ================== SCRIPTS ==================
    
    async def save_script(self, script: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Save script"""
        return script
    
    async def get_scripts(self, **filters) -> List[Dict[str, Any]]:
        """Get scripts"""
        return []
    
    async def get_script(self, script_id: str) -> Optional[Dict[str, Any]]:
        """Get script by ID"""
        return None
    
    async def get_all_scripts(self) -> List[Dict[str, Any]]:
        """Get all scripts"""
        return []
    
    async def delete_script(self, script_id: str) -> bool:
        """Delete script"""
        return True
    
    # ================== PASSWORD RESET ==================

    async def create_password_reset_token(self, token_data: Dict[str, Any]) -> bool:
        """Create password reset token in PostgreSQL"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                try:
                    await conn.execute(
                        """INSERT INTO password_reset_tokens
                           (token, username, email, expiry, used, created_at)
                           VALUES ($1, $2, $3, $4, $5, $6)""",
                        token_data["token"],
                        token_data["username"],
                        token_data["email"],
                        token_data["expiry"],
                        token_data.get("used", False),
                        token_data.get("created_at", datetime.utcnow())
                    )
                    return True
                finally:
                    try:
                        await conn.execute("RESET app.is_platform_admin")
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Failed to create password reset token: {e}")
            return False

    async def get_password_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get password reset token from PostgreSQL"""
        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                try:
                    row = await conn.fetchrow(
                        "SELECT * FROM password_reset_tokens WHERE token = $1",
                        token
                    )
                    return dict(row) if row else None
                finally:
                    try:
                        await conn.execute("RESET app.is_platform_admin")
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Failed to get password reset token: {e}")
            return None

    async def mark_password_reset_token_used(self, token: str) -> bool:
        """Mark token as used in PostgreSQL"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                try:
                    await conn.execute(
                        "UPDATE password_reset_tokens SET used = true WHERE token = $1",
                        token
                    )
                    return True
                finally:
                    try:
                        await conn.execute("RESET app.is_platform_admin")
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Failed to mark password reset token used: {e}")
            return False
    
    # ================== AUDIT LOG ==================
    
    async def log_audit(self, action: str, user: str = "system", details: Dict = None) -> bool:
        """Log audit event"""
        if not self.connected:
            return False
        try:
            await self._postgres.log_audit(
                username=user,
                action=action,
                resource_type="system",
                resource_id="",
                details=details or {}
            )
            return True
        except:
            return False
    
    async def get_audit_logs(self, limit: int = 100, **filters) -> List[Dict[str, Any]]:
        """Get audit logs"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT $1',
                    limit
                )
                return [dict(row) for row in rows]
        except:
            return []
    
    # ================== STATS ==================
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        pool = self._get_pool()
        if not pool:
            return {}
        try:
            async with pool.acquire() as conn:
                alerts_count = await conn.fetchval('SELECT COUNT(*) FROM alerts')
                investigations_count = await conn.fetchval('SELECT COUNT(*) FROM investigations')
                users_count = await conn.fetchval('SELECT COUNT(*) FROM users WHERE disabled = FALSE')
                iocs_count = await conn.fetchval('SELECT COUNT(*) FROM iocs')
                
                return {
                    'alerts': alerts_count or 0,
                    'investigations': investigations_count or 0,
                    'users': users_count or 0,
                    'iocs': iocs_count or 0
                }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {}
    
    async def get_ioc_statistics(self) -> Dict[str, Any]:
        """Get IOC statistics"""
        pool = self._get_pool()
        if not pool:
            return {}
        try:
            async with pool.acquire() as conn:
                total = await conn.fetchval('SELECT COUNT(*) FROM iocs')
                by_type = await conn.fetch(
                    'SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type'
                )
                by_severity = await conn.fetch(
                    'SELECT severity, COUNT(*) as count FROM iocs GROUP BY severity'
                )
                
                return {
                    'total': total or 0,
                    'by_type': {row['ioc_type']: row['count'] for row in by_type},
                    'by_severity': {row['severity']: row['count'] for row in by_severity}
                }
        except:
            return {'total': 0, 'by_type': {}, 'by_severity': {}}
    
    async def get_system_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system/audit logs"""
        pool = self._get_pool()
        if not pool:
            logger.warning("No database pool available for getting logs")
            return []
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch('''
                    SELECT id, username, action, resource_type, resource_id, 
                           details, ip_address, user_agent, created_at
                    FROM audit_log 
                    ORDER BY created_at DESC 
                    LIMIT $1
                ''', limit)
                
                # Format logs for frontend
                logs = []
                for row in rows:
                    log = dict(row)
                    created_at = log.get('created_at')
                    timestamp = created_at.isoformat() if created_at else datetime.utcnow().isoformat()
                    
                    logs.append({
                        'id': str(log.get('id', '')),
                        'timestamp': timestamp,
                        'level': log.get('resource_type', 'info'),
                        'message': log.get('action', ''),
                        'source': log.get('username', 'system'),
                        'details': log.get('details') if isinstance(log.get('details'), dict) else {}
                    })
                
                logger.info(f"Retrieved {len(logs)} audit logs")
                return logs
        except Exception as e:
            logger.error(f"Error getting system logs: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []


    # ================== FORMS ==================

    async def create_form(self, form_dict: Dict[str, Any]) -> bool:
        """Create a new web form"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO web_forms (form_id, title, description, fields, output_config,
                        is_active, created_by, created_at, updated_at)
                    VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $9)
                    ON CONFLICT (form_id) DO UPDATE SET
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        fields = EXCLUDED.fields,
                        output_config = EXCLUDED.output_config,
                        updated_at = EXCLUDED.updated_at
                ''',
                    form_dict.get('form_id'),
                    form_dict.get('title', ''),
                    form_dict.get('description', ''),
                    json.dumps(form_dict.get('fields', [])),
                    json.dumps(form_dict.get('output_config', {})),
                    form_dict.get('is_active', True),
                    form_dict.get('created_by'),
                    datetime.utcnow(),
                    datetime.utcnow()
                )
            return True
        except Exception as e:
            logger.error(f"Error creating form: {e}")
            return False

    async def get_all_forms(self, created_by: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all forms, optionally filtered by creator"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                if created_by:
                    rows = await conn.fetch(
                        'SELECT * FROM web_forms WHERE created_by = $1 ORDER BY created_at DESC',
                        created_by
                    )
                else:
                    rows = await conn.fetch('SELECT * FROM web_forms ORDER BY created_at DESC')
                result = []
                for row in rows:
                    d = dict(row)
                    if isinstance(d.get('fields'), str):
                        d['fields'] = json.loads(d['fields'])
                    if isinstance(d.get('output_config'), str):
                        d['output_config'] = json.loads(d['output_config'])
                    result.append(d)
                return result
        except Exception as e:
            logger.error(f"Error getting forms: {e}")
            return []

    async def get_form(self, form_id: str) -> Optional[Dict[str, Any]]:
        """Get a form by ID"""
        pool = self._get_pool()
        if not pool:
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    'SELECT * FROM web_forms WHERE form_id = $1', form_id
                )
                if row:
                    d = dict(row)
                    if isinstance(d.get('fields'), str):
                        d['fields'] = json.loads(d['fields'])
                    if isinstance(d.get('output_config'), str):
                        d['output_config'] = json.loads(d['output_config'])
                    return d
                return None
        except Exception as e:
            logger.error(f"Error getting form {form_id}: {e}")
            return None

    async def update_form(self, form_id: str, updates: Dict[str, Any]) -> bool:
        """Update a form"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            set_clauses = []
            params = [form_id]
            idx = 2
            for key, value in updates.items():
                if key in ('fields', 'output_config'):
                    set_clauses.append(f"{key} = ${idx}::jsonb")
                    params.append(json.dumps(value))
                else:
                    set_clauses.append(f"{key} = ${idx}")
                    params.append(value)
                idx += 1
            set_clauses.append(f"updated_at = ${idx}")
            params.append(datetime.utcnow())

            async with pool.acquire() as conn:
                await conn.execute(
                    f"UPDATE web_forms SET {', '.join(set_clauses)} WHERE form_id = $1",
                    *params
                )
            return True
        except Exception as e:
            logger.error(f"Error updating form {form_id}: {e}")
            return False

    async def delete_form(self, form_id: str) -> bool:
        """Delete a form"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                result = await conn.execute(
                    'DELETE FROM web_forms WHERE form_id = $1', form_id
                )
                return 'DELETE 1' in result
        except Exception as e:
            logger.error(f"Error deleting form {form_id}: {e}")
            return False

    async def create_submission(self, submission_data: Dict[str, Any]) -> bool:
        """Create a form submission"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO form_submissions (submission_id, form_id, form_title, data,
                        submitted_at, ip_address, user_agent, status)
                    VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
                ''',
                    submission_data.get('submission_id'),
                    submission_data.get('form_id'),
                    submission_data.get('form_title', ''),
                    json.dumps(submission_data.get('data', {})),
                    submission_data.get('submitted_at', datetime.utcnow()),
                    submission_data.get('ip_address'),
                    submission_data.get('user_agent'),
                    submission_data.get('status', 'pending')
                )
            return True
        except Exception as e:
            logger.error(f"Error creating submission: {e}")
            return False

    async def get_form_submissions(self, form_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get form submissions"""
        pool = self._get_pool()
        if not pool:
            return []
        try:
            async with pool.acquire() as conn:
                if form_id:
                    rows = await conn.fetch(
                        'SELECT * FROM form_submissions WHERE form_id = $1 ORDER BY submitted_at DESC LIMIT $2',
                        form_id, limit
                    )
                else:
                    rows = await conn.fetch(
                        'SELECT * FROM form_submissions ORDER BY submitted_at DESC LIMIT $1',
                        limit
                    )
                result = []
                for row in rows:
                    d = dict(row)
                    if isinstance(d.get('data'), str):
                        d['data'] = json.loads(d['data'])
                    result.append(d)
                return result
        except Exception as e:
            logger.error(f"Error getting submissions: {e}")
            return []

    async def update_submission(self, submission_id: str, updates: Dict[str, Any]) -> bool:
        """Update a form submission"""
        pool = self._get_pool()
        if not pool:
            return False
        try:
            set_clauses = []
            params = [submission_id]
            idx = 2
            for key, value in updates.items():
                if key in ('data', 'processing_errors', 'webhook_response'):
                    set_clauses.append(f"{key} = ${idx}::jsonb")
                    params.append(json.dumps(value))
                else:
                    set_clauses.append(f"{key} = ${idx}")
                    params.append(value)
                idx += 1

            if not set_clauses:
                return True

            async with pool.acquire() as conn:
                await conn.execute(
                    f"UPDATE form_submissions SET {', '.join(set_clauses)} WHERE submission_id = $1",
                    *params
                )
            return True
        except Exception as e:
            logger.error(f"Error updating submission {submission_id}: {e}")
            return False


# Singleton instance
db = DatabaseService()


def get_db() -> DatabaseService:
    """Get database service instance"""
    return db
