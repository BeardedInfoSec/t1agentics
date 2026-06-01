# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Control Plane Service for Log Collectors
==========================================

Manages versioned, signed configurations that collectors pull.

Security Model:
- Collectors ONLY poll for configs (pull-only, no inbound commands)
- All configurations are Ed25519 signed
- Configs include version numbers for ordering
- Collectors verify signatures before applying

Flow:
1. Admin updates config via UI/API
2. Control plane increments version, signs config
3. Collector polls /api/v1/control-plane/config/{collector_id}
4. Collector verifies signature, applies if version > current
5. Collector acks to /api/v1/control-plane/config/{collector_id}/ack
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Try to import cryptography for Ed25519 signing
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography not installed - config signing disabled")


class ConfigStatus(str, Enum):
    """Configuration delivery status"""
    PENDING = "pending"           # Config created, not yet delivered
    DELIVERED = "delivered"       # Collector received config
    ACKNOWLEDGED = "acknowledged" # Collector applied config successfully
    REJECTED = "rejected"         # Collector rejected config (signature fail, validation error)


@dataclass
class CollectorConfig:
    """Configuration for a single collector"""
    collector_id: str
    version: int
    config: Dict[str, Any]
    created_at: datetime
    signature: Optional[str] = None
    content_hash: str = ""
    ttl_seconds: int = 3600  # Config valid for 1 hour
    status: ConfigStatus = ConfigStatus.PENDING
    ack_at: Optional[datetime] = None
    ack_message: Optional[str] = None


@dataclass
class ConfigChange:
    """Audit record of a configuration change"""
    change_id: str
    collector_id: str
    before_version: int
    after_version: int
    changed_by: str
    changed_at: datetime
    change_type: str  # "create", "update", "delete"
    diff: Dict[str, Any]


class ControlPlaneService:
    """
    Control Plane for Log Collector Configuration

    Responsibilities:
    - Store and version collector configurations
    - Sign configurations with Ed25519
    - Track config delivery and acknowledgment
    - Provide audit trail for all changes
    """

    def __init__(self, db_service=None):
        self.db = db_service

        # Key management
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key: Optional[Ed25519PublicKey] = None
        self._public_key_pem: Optional[str] = None

        # Initialize or load signing keys
        self._initialize_keys()

        # In-memory cache (would be Redis in production)
        self._config_cache: Dict[str, CollectorConfig] = {}
        self._change_log: List[ConfigChange] = []

    def _initialize_keys(self):
        """Initialize Ed25519 signing keys"""
        if not HAS_CRYPTO:
            logger.warning("Cryptography not available - configs will not be signed")
            return

        # Check for existing key in environment or file
        key_path = os.environ.get("CONTROL_PLANE_KEY_PATH", "/etc/t1/control_plane.key")
        pub_key_path = os.environ.get("CONTROL_PLANE_PUB_KEY_PATH", "/etc/t1/control_plane.pub")

        try:
            if os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    self._private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                self._public_key = self._private_key.public_key()
                logger.info("Loaded existing control plane signing key")
            else:
                # Generate new key pair
                self._private_key = Ed25519PrivateKey.generate()
                self._public_key = self._private_key.public_key()

                # Save keys (in production, use proper key management)
                try:
                    os.makedirs(os.path.dirname(key_path), exist_ok=True)

                    with open(key_path, 'wb') as f:
                        f.write(self._private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                    os.chmod(key_path, 0o600)

                    with open(pub_key_path, 'wb') as f:
                        f.write(self._public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ))

                    logger.info(f"Generated new control plane signing key at {key_path}")
                except (OSError, PermissionError) as e:
                    logger.warning(f"Could not save keys to disk: {e}. Using ephemeral key.")

            # Store public key PEM for distribution to collectors
            self._public_key_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to initialize signing keys: {e}")
            self._private_key = None
            self._public_key = None

    def get_public_key(self) -> Optional[str]:
        """Get public key PEM for distribution to collectors"""
        return self._public_key_pem

    def _sign_config(self, config_data: Dict[str, Any], version: int) -> Tuple[str, str]:
        """
        Sign a configuration with Ed25519

        Returns:
            Tuple of (signature_hex, content_hash)
        """
        # Create canonical JSON representation
        canonical = json.dumps(config_data, sort_keys=True, separators=(',', ':'))

        # Include version in what we sign
        signing_payload = f"v{version}:{canonical}"
        payload_bytes = signing_payload.encode('utf-8')

        # Calculate content hash
        content_hash = hashlib.sha256(payload_bytes).hexdigest()

        # Sign if we have a key
        signature = ""
        if self._private_key and HAS_CRYPTO:
            sig_bytes = self._private_key.sign(payload_bytes)
            signature = sig_bytes.hex()

        return signature, content_hash

    def _verify_signature(self, config_data: Dict[str, Any], version: int,
                          signature_hex: str) -> bool:
        """Verify a configuration signature"""
        if not self._public_key or not HAS_CRYPTO:
            return True  # Skip verification if no crypto

        try:
            canonical = json.dumps(config_data, sort_keys=True, separators=(',', ':'))
            signing_payload = f"v{version}:{canonical}"
            payload_bytes = signing_payload.encode('utf-8')

            sig_bytes = bytes.fromhex(signature_hex)
            self._public_key.verify(sig_bytes, payload_bytes)
            return True
        except (InvalidSignature, ValueError) as e:
            logger.warning(f"Signature verification failed: {e}")
            return False

    async def get_collector_config(self, collector_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current configuration for a collector

        This is what collectors poll.
        Returns the signed config package ready for delivery.
        """
        # Check cache first
        if collector_id in self._config_cache:
            cached = self._config_cache[collector_id]

            # Check TTL
            age = (datetime.now(timezone.utc) - cached.created_at).total_seconds()
            if age < cached.ttl_seconds:
                return self._build_config_response(cached)

        # Load from database
        if self.db:
            config = await self._load_config_from_db(collector_id)
            if config:
                self._config_cache[collector_id] = config
                return self._build_config_response(config)

        # Return default config for unknown collectors
        return await self._get_default_config(collector_id)

    def _build_config_response(self, config: CollectorConfig) -> Dict[str, Any]:
        """Build the config response package for collectors"""
        return {
            "collector_id": config.collector_id,
            "version": config.version,
            "config": config.config,
            "signature": config.signature,
            "content_hash": config.content_hash,
            "timestamp": config.created_at.isoformat(),
            "ttl_seconds": config.ttl_seconds,
            "public_key": self._public_key_pem
        }

    async def _load_config_from_db(self, collector_id: str) -> Optional[CollectorConfig]:
        """Load collector config from PostgreSQL"""
        if not self.db:
            return None

        try:
            # Get collector record
            collector = await self.db.fetchrow("""
                SELECT id, agent_id, hostname, config, status
                FROM log_agents
                WHERE agent_id = $1 OR id::text = $1
            """, collector_id)

            if not collector:
                return None

            # Get source assignments for this collector
            assignments = await self.db.fetch("""
                SELECT source_type, config_overrides, include_filters,
                       exclude_filters, is_enabled, target_index_name
                FROM collector_source_assignments
                WHERE agent_id = $1 AND is_enabled = true
            """, collector['id'])

            # Build the config
            sources = []
            for assignment in assignments:
                source_config = {
                    "source_type": assignment['source_type'],
                    "enabled": assignment['is_enabled'],
                    "target_index": assignment['target_index_name'],
                    "config": assignment['config_overrides'] or {},
                    "include_filters": assignment['include_filters'] or [],
                    "exclude_filters": assignment['exclude_filters'] or []
                }
                sources.append(source_config)

            # Get the current version from config
            current_config = collector['config'] or {}
            version = current_config.get('_version', 1)

            # Build full config
            config_data = {
                "collector_id": collector['agent_id'],
                "hostname": collector['hostname'],
                "sources": sources,
                "settings": {
                    "polling_interval": current_config.get('polling_interval', 5),
                    "batch_size": current_config.get('batch_size', 100),
                    "min_severity": current_config.get('min_severity', 4),
                    "dedup_window_seconds": current_config.get('dedup_window_seconds', 60),
                    "compress_logs": current_config.get('compress_logs', True)
                },
                "_generated_at": datetime.now(timezone.utc).isoformat()
            }

            # Sign the config
            signature, content_hash = self._sign_config(config_data, version)

            return CollectorConfig(
                collector_id=collector['agent_id'],
                version=version,
                config=config_data,
                created_at=datetime.now(timezone.utc),
                signature=signature,
                content_hash=content_hash,
                status=ConfigStatus.PENDING
            )

        except Exception as e:
            logger.error(f"Error loading config from DB: {e}")
            return None

    async def _get_default_config(self, collector_id: str) -> Dict[str, Any]:
        """Get default configuration for new/unknown collectors"""
        default_config = {
            "collector_id": collector_id,
            "hostname": "unknown",
            "sources": [
                {
                    "source_type": "edr_process",
                    "enabled": True,
                    "config": {"polling_interval": 5}
                },
                {
                    "source_type": "edr_network",
                    "enabled": True,
                    "config": {"polling_interval": 10}
                }
            ],
            "settings": {
                "polling_interval": 5,
                "batch_size": 100,
                "min_severity": 4,
                "dedup_window_seconds": 60,
                "compress_logs": True
            },
            "_generated_at": datetime.now(timezone.utc).isoformat()
        }

        version = 1
        signature, content_hash = self._sign_config(default_config, version)

        return {
            "collector_id": collector_id,
            "version": version,
            "config": default_config,
            "signature": signature,
            "content_hash": content_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 3600,
            "public_key": self._public_key_pem
        }

    async def update_collector_config(
        self,
        collector_id: str,
        config_updates: Dict[str, Any],
        changed_by: str
    ) -> Optional[CollectorConfig]:
        """
        Update a collector's configuration

        This is called when an admin changes settings via UI.
        Increments version, signs new config, and stores it.
        """
        # Get current config
        current = await self.get_collector_config(collector_id)
        current_version = current.get('version', 0) if current else 0
        current_config = current.get('config', {}) if current else {}

        # Merge updates
        new_config = {**current_config}
        if 'settings' in config_updates:
            new_config['settings'] = {**new_config.get('settings', {}), **config_updates['settings']}
        if 'sources' in config_updates:
            new_config['sources'] = config_updates['sources']

        new_config['_generated_at'] = datetime.now(timezone.utc).isoformat()

        # Increment version
        new_version = current_version + 1

        # Sign new config
        signature, content_hash = self._sign_config(new_config, new_version)

        # Create config object
        new_collector_config = CollectorConfig(
            collector_id=collector_id,
            version=new_version,
            config=new_config,
            created_at=datetime.now(timezone.utc),
            signature=signature,
            content_hash=content_hash,
            status=ConfigStatus.PENDING
        )

        # Store in DB
        if self.db:
            try:
                await self.db.execute("""
                    UPDATE log_agents
                    SET config = config || $1::jsonb,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = $2
                """, json.dumps({'_version': new_version, **config_updates.get('settings', {})}), collector_id)
            except Exception as e:
                logger.error(f"Error storing config update: {e}")

        # Update cache
        self._config_cache[collector_id] = new_collector_config

        # Record change
        change = ConfigChange(
            change_id=f"{collector_id}-{new_version}",
            collector_id=collector_id,
            before_version=current_version,
            after_version=new_version,
            changed_by=changed_by,
            changed_at=datetime.now(timezone.utc),
            change_type="update",
            diff=config_updates
        )
        self._change_log.append(change)

        logger.info(f"Updated config for {collector_id}: v{current_version} -> v{new_version}")

        return new_collector_config

    async def acknowledge_config(
        self,
        collector_id: str,
        version: int,
        success: bool,
        message: Optional[str] = None
    ) -> bool:
        """
        Record collector acknowledgment of config delivery

        Collectors call this after applying (or rejecting) a config.
        """
        if collector_id in self._config_cache:
            cached = self._config_cache[collector_id]
            if cached.version == version:
                cached.status = ConfigStatus.ACKNOWLEDGED if success else ConfigStatus.REJECTED
                cached.ack_at = datetime.now(timezone.utc)
                cached.ack_message = message

        # Update in DB
        if self.db:
            try:
                await self.db.execute("""
                    UPDATE log_agents
                    SET last_heartbeat = CURRENT_TIMESTAMP,
                        config = config || $1::jsonb
                    WHERE agent_id = $2
                """, json.dumps({
                    '_last_ack_version': version,
                    '_last_ack_status': 'success' if success else 'failed',
                    '_last_ack_at': datetime.now(timezone.utc).isoformat()
                }), collector_id)

                logger.info(f"Config ack from {collector_id}: v{version} {'success' if success else 'failed'}")
                return True
            except Exception as e:
                logger.error(f"Error recording config ack: {e}")
                return False

        return True

    async def get_config_history(self, collector_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get config change history for a collector"""
        history = [
            {
                "change_id": c.change_id,
                "before_version": c.before_version,
                "after_version": c.after_version,
                "changed_by": c.changed_by,
                "changed_at": c.changed_at.isoformat(),
                "change_type": c.change_type,
                "diff": c.diff
            }
            for c in self._change_log
            if c.collector_id == collector_id
        ]
        return history[-limit:]

    async def list_pending_configs(self) -> List[Dict[str, Any]]:
        """List all configs that haven't been acknowledged yet"""
        pending = [
            {
                "collector_id": c.collector_id,
                "version": c.version,
                "status": c.status.value,
                "created_at": c.created_at.isoformat()
            }
            for c in self._config_cache.values()
            if c.status == ConfigStatus.PENDING
        ]
        return pending

    async def get_collector_health(self, collector_id: str) -> Dict[str, Any]:
        """Get health status for a collector"""
        if not self.db:
            return {"status": "unknown", "collector_id": collector_id}

        try:
            collector = await self.db.fetchrow("""
                SELECT agent_id, hostname, status, last_heartbeat,
                       events_received_total, config, agent_version
                FROM log_agents
                WHERE agent_id = $1
            """, collector_id)

            if not collector:
                return {"status": "not_found", "collector_id": collector_id}

            # Calculate health
            last_heartbeat = collector['last_heartbeat']
            if last_heartbeat:
                age = (datetime.now(timezone.utc) - last_heartbeat.replace(tzinfo=timezone.utc)).total_seconds()
                is_online = age < 300  # 5 minute threshold
            else:
                age = None
                is_online = False

            config = collector['config'] or {}

            return {
                "collector_id": collector['agent_id'],
                "hostname": collector['hostname'],
                "status": collector['status'],
                "is_online": is_online,
                "last_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
                "heartbeat_age_seconds": int(age) if age else None,
                "events_total": collector['events_received_total'] or 0,
                "agent_version": collector['agent_version'],
                "config_version": config.get('_version', 0),
                "last_ack_version": config.get('_last_ack_version'),
                "last_ack_status": config.get('_last_ack_status')
            }
        except Exception as e:
            logger.error(f"Error getting collector health: {e}")
            return {"status": "error", "collector_id": collector_id, "error": str(e)}


# Singleton instance
_control_plane: Optional[ControlPlaneService] = None


def get_control_plane() -> ControlPlaneService:
    """Get the global control plane service instance"""
    global _control_plane
    if _control_plane is None:
        _control_plane = ControlPlaneService()
    return _control_plane


async def init_control_plane(db_service=None) -> ControlPlaneService:
    """Initialize control plane with database connection"""
    global _control_plane
    _control_plane = ControlPlaneService(db_service=db_service)
    return _control_plane
