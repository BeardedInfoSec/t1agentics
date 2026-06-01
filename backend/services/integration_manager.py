# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Manager Service
Central hub for managing threat intelligence integrations

Features:
- Integration CRUD operations
- Health monitoring and status tracking
- Live connection testing
- Response normalization
- Rate limiting awareness

NOTE: This module uses the legacy integration_credentials table.
For new integrations, prefer using the credentials_vault via credentials_service.py
which provides proper Fernet encryption (AES-128-CBC + HMAC-SHA256).
"""

import logging
import os
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)


class IntegrationHealth(str, Enum):
    """Integration health states"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check on an integration"""
    integration_id: str
    status: IntegrationHealth
    response_time_ms: Optional[float] = None
    last_check: datetime = field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None
    consecutive_failures: int = 0
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[datetime] = None


@dataclass
class NormalizedResponse:
    """Normalized response format for all integrations"""
    success: bool
    provider: str
    ioc_type: str
    ioc_value: str
    verdict: Optional[str] = None  # malicious, suspicious, benign, unknown
    confidence: Optional[float] = None  # 0-100
    threat_score: Optional[float] = None  # 0-100
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


# Global health status cache
_health_cache: Dict[str, HealthCheckResult] = {}

# Simple encryption for backward compatibility with legacy table
# New integrations should use credentials_service.py instead
def _get_legacy_cipher():
    """Get Fernet cipher for legacy credentials (backward compatibility)"""
    try:
        from cryptography.fernet import Fernet
        key = os.environ.get("CREDENTIALS_ENCRYPTION_KEY")
        if key:
            return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as e:
        logger.warning(f"Legacy cipher unavailable: {e}")
    return None

def _encrypt_legacy(value: str) -> str:
    """Encrypt a value for legacy storage"""
    cipher = _get_legacy_cipher()
    if cipher and value:
        try:
            return cipher.encrypt(value.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
    return value  # Return unencrypted if cipher unavailable (log warning)

def _decrypt_legacy(value: str) -> str:
    """Decrypt a value from legacy storage"""
    cipher = _get_legacy_cipher()
    if cipher and value:
        try:
            return cipher.decrypt(value.encode()).decode()
        except Exception:
            # May be already plaintext (old data)
            return value
    return value


class IntegrationManager:
    """Manages external integrations and enrichment providers"""
    
    def __init__(self, db):
        self.db = db
        self.providers = {}  # Registry of available providers
        
    def register_provider(self, provider_name: str, provider_class):
        """Register a new threat intel provider"""
        self.providers[provider_name] = provider_class
        logger.info(f"Registered provider: {provider_name}")
    
    async def create_integration(
        self,
        provider: str,
        name: str,
        config: Dict[str, Any],
        api_key: Optional[str] = None,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """
        Create a new integration
        
        Args:
            provider: Provider name (virustotal, otx, threatfox, etc.)
            name: Human-readable name
            config: Provider-specific configuration
            api_key: API key if needed
            created_by: Username who created it
            
        Returns:
            Created integration record
        """
        async with self.db.tenant_acquire() as conn:
            # Create integration
            integration_id = f"{provider}_{datetime.utcnow().timestamp()}"
            
            row = await conn.fetchrow('''
                INSERT INTO integrations (
                    integration_id, provider, name, description,
                    category, base_url, auth_type, config,
                    enabled, created_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING *
            ''',
                integration_id,
                provider,
                name,
                config.get('description'),
                config.get('category', 'threat_intel'),
                config.get('base_url'),
                'api_key' if api_key else 'none',
                json.dumps(config),
                True,
                created_by
            )
            
            integration = dict(row)
            
            # Store credentials if provided (encrypted)
            if api_key:
                from middleware.tenant_middleware import get_optional_tenant_id
                import uuid as _uuid
                _tenant_id = get_optional_tenant_id()

                encrypted_key = _encrypt_legacy(api_key)
                await conn.execute('''
                    INSERT INTO integration_credentials (
                        integration_id, credential_type, api_key, tenant_id
                    ) VALUES ($1, $2, $3, $4)
                ''',
                    integration['id'],
                    'api_key',
                    encrypted_key,
                    _uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )
            
            return integration
    
    async def get_integration(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get integration by ID"""
        async with self.db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM integrations WHERE integration_id = $1',
                integration_id
            )
            return dict(row) if row else None
    
    async def get_integration_credentials(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get credentials for an integration (decrypts stored values)"""
        async with self.db.tenant_acquire() as conn:
            # Get integration UUID
            integration = await conn.fetchrow(
                'SELECT id FROM integrations WHERE integration_id = $1',
                integration_id
            )
            if not integration:
                return None

            row = await conn.fetchrow(
                'SELECT * FROM integration_credentials WHERE integration_id = $1',
                integration['id']
            )
            if not row:
                return None

            # Decrypt sensitive fields
            result = dict(row)
            if result.get('api_key'):
                result['api_key'] = _decrypt_legacy(result['api_key'])
            return result
    
    async def list_integrations(
        self,
        category: Optional[str] = None,
        enabled_only: bool = False
    ) -> List[Dict[str, Any]]:
        """List all integrations"""
        async with self.db.tenant_acquire() as conn:
            query = 'SELECT * FROM integrations WHERE 1=1'
            params = []
            
            if category:
                query += f' AND category = ${len(params) + 1}'
                params.append(category)
            
            if enabled_only:
                query += ' AND enabled = TRUE'
            
            query += ' ORDER BY created_at DESC'
            
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    async def update_integration(
        self,
        integration_id: str,
        updates: Dict[str, Any]
    ) -> bool:
        """Update integration configuration"""
        async with self.db.tenant_acquire() as conn:
            # Build dynamic update query
            set_clauses = []
            params = []
            
            for key, value in updates.items():
                if key in ['name', 'description', 'enabled', 'config', 'base_url']:
                    set_clauses.append(f"{key} = ${len(params) + 1}")
                    if key == 'config' and isinstance(value, dict):
                        params.append(json.dumps(value))
                    else:
                        params.append(value)
            
            if not set_clauses:
                return False
            
            set_clauses.append(f"updated_at = ${len(params) + 1}")
            params.append(datetime.utcnow())
            
            params.append(integration_id)
            
            query = f'''
                UPDATE integrations
                SET {', '.join(set_clauses)}
                WHERE integration_id = ${len(params)}
            '''
            
            result = await conn.execute(query, *params)
            return result != 'UPDATE 0'
    
    async def delete_integration(self, integration_id: str) -> bool:
        """Delete an integration"""
        async with self.db.tenant_acquire() as conn:
            result = await conn.execute(
                'DELETE FROM integrations WHERE integration_id = $1',
                integration_id
            )
            return result != 'DELETE 0'
    
    async def verify_integration(self, integration_id: str) -> Dict[str, Any]:
        """
        Test integration connection and verify it works
        
        Returns:
            Dict with success status and details
        """
        integration = await self.get_integration(integration_id)
        if not integration:
            return {"success": False, "error": "Integration not found"}
        
        provider_name = integration['provider']
        
        # Get provider class
        if provider_name not in self.providers:
            return {"success": False, "error": f"Provider {provider_name} not registered"}
        
        provider_class = self.providers[provider_name]
        
        # Get credentials
        credentials = await self.get_integration_credentials(integration_id)
        api_key = credentials.get('api_key') if credentials else None
        
        # Test connection
        try:
            provider = provider_class(api_key=api_key)
            
            # Use a known-good test IOC
            if provider_name == 'virustotal':
                result = await provider.enrich_ip('8.8.8.8')
            else:
                result = await provider.test_connection()
            
            # Update verification status
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE integrations
                    SET verified = TRUE, last_verified_at = $1
                    WHERE integration_id = $2
                ''',
                    datetime.utcnow(),
                    integration_id
                )
            
            return {
                "success": True,
                "message": "Integration verified successfully",
                "test_result": result
            }
        except Exception as e:
            logger.error(f"Failed to verify {provider_name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_enrichment_from_cache(
        self,
        ioc_type: str,
        ioc_value: str,
        provider: str,
        max_age_hours: int = 24
    ) -> Optional[Dict[str, Any]]:
        """
        Get enrichment from cache if available and not expired
        
        Args:
            ioc_type: ip, domain, hash, url, email
            ioc_value: The IOC value
            provider: Provider name
            max_age_hours: Maximum cache age in hours
            
        Returns:
            Cached enrichment data or None
        """
        async with self.db.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                SELECT enrichment_data, is_malicious, threat_score, confidence
                FROM enrichment_cache
                WHERE ioc_type = $1 
                  AND ioc_value = $2 
                  AND provider = $3
                  AND cached_at > $4
                ORDER BY cached_at DESC
                LIMIT 1
            ''',
                ioc_type,
                ioc_value,
                provider,
                datetime.utcnow() - timedelta(hours=max_age_hours)
            )
            
            if row:
                # Update hit count and last accessed
                await conn.execute('''
                    UPDATE enrichment_cache
                    SET hit_count = hit_count + 1,
                        last_accessed_at = $1
                    WHERE ioc_type = $2 
                      AND ioc_value = $3 
                      AND provider = $4
                ''',
                    datetime.utcnow(),
                    ioc_type,
                    ioc_value,
                    provider
                )
                
                return dict(row)
            
            return None
    
    async def save_enrichment_to_cache(
        self,
        ioc_type: str,
        ioc_value: str,
        provider: str,
        enrichment_data: Dict[str, Any],
        cache_hours: int = 24
    ):
        """Save enrichment result to cache"""
        async with self.db.tenant_acquire() as conn:
            await conn.execute('''
                INSERT INTO enrichment_cache (
                    ioc_type, ioc_value, provider, enrichment_data,
                    is_malicious, threat_score, confidence,
                    expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (ioc_type, ioc_value, provider) 
                DO UPDATE SET
                    enrichment_data = EXCLUDED.enrichment_data,
                    is_malicious = EXCLUDED.is_malicious,
                    threat_score = EXCLUDED.threat_score,
                    confidence = EXCLUDED.confidence,
                    cached_at = CURRENT_TIMESTAMP,
                    expires_at = EXCLUDED.expires_at
            ''',
                ioc_type,
                ioc_value,
                provider,
                json.dumps(enrichment_data),
                enrichment_data.get('is_malicious'),
                enrichment_data.get('threat_score'),
                enrichment_data.get('confidence'),
                datetime.utcnow() + timedelta(hours=cache_hours)
            )
    
    async def enrich_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        providers: Optional[List[str]] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Enrich an IOC using one or more providers
        
        Args:
            ioc_type: ip, domain, hash, url, email
            ioc_value: The IOC to enrich
            providers: List of provider names, or None for all enabled
            use_cache: Whether to use cached results
            
        Returns:
            Dict with enrichment results from each provider
        """
        results = {}
        
        # Get enabled integrations
        integrations = await self.list_integrations(
            category='threat_intel',
            enabled_only=True
        )
        
        for integration in integrations:
            provider_name = integration['provider']
            
            # Skip if provider list specified and this isn't in it
            if providers and provider_name not in providers:
                continue
            
            # Check cache first
            if use_cache:
                cached = await self.get_enrichment_from_cache(
                    ioc_type, ioc_value, provider_name
                )
                if cached:
                    results[provider_name] = {
                        "source": "cache",
                        "data": cached['enrichment_data']
                    }
                    continue
            
            # Get fresh data from provider
            try:
                credentials = await self.get_integration_credentials(
                    integration['integration_id']
                )
                api_key = credentials.get('api_key') if credentials else None
                
                provider_class = self.providers.get(provider_name)
                if not provider_class:
                    results[provider_name] = {"error": "Provider not registered"}
                    continue
                
                provider = provider_class(api_key=api_key)
                
                # Call appropriate enrichment method
                if ioc_type == 'ip':
                    data = await provider.enrich_ip(ioc_value)
                elif ioc_type == 'domain':
                    data = await provider.enrich_domain(ioc_value)
                elif ioc_type == 'hash':
                    data = await provider.enrich_file_hash(ioc_value)
                else:
                    data = {"error": f"IOC type {ioc_type} not supported"}
                
                results[provider_name] = {
                    "source": "api",
                    "data": data
                }
                
                # Cache the result
                if use_cache and not data.get('error'):
                    await self.save_enrichment_to_cache(
                        ioc_type, ioc_value, provider_name, data
                    )
                
            except Exception as e:
                logger.error(f"Error enriching with {provider_name}: {e}")
                results[provider_name] = {"error": str(e)}

        return results

    # =========================================================================
    # HEALTH MONITORING
    # =========================================================================

    async def check_integration_health(
        self,
        integration_id: str,
        force: bool = False
    ) -> HealthCheckResult:
        """
        Check health of a specific integration.

        Args:
            integration_id: Integration to check
            force: Skip cache and force fresh check

        Returns:
            HealthCheckResult with status and details
        """
        global _health_cache

        # Check cache first (unless forced)
        if not force and integration_id in _health_cache:
            cached = _health_cache[integration_id]
            # Cache valid for 5 minutes
            if (datetime.utcnow() - cached.last_check).total_seconds() < 300:
                return cached

        integration = await self.get_integration(integration_id)
        if not integration:
            result = HealthCheckResult(
                integration_id=integration_id,
                status=IntegrationHealth.UNKNOWN,
                error_message="Integration not found"
            )
            _health_cache[integration_id] = result
            return result

        provider_name = integration['provider']

        # Get credentials
        credentials = await self.get_integration_credentials(integration_id)
        api_key = credentials.get('api_key') if credentials else None

        # Perform health check
        start_time = datetime.utcnow()
        try:
            provider_class = self.providers.get(provider_name)
            if not provider_class:
                result = HealthCheckResult(
                    integration_id=integration_id,
                    status=IntegrationHealth.UNKNOWN,
                    error_message=f"Provider {provider_name} not registered"
                )
                _health_cache[integration_id] = result
                return result

            provider = provider_class(api_key=api_key)

            # Use a benign test query
            if hasattr(provider, 'test_connection'):
                test_result = await provider.test_connection()
            elif hasattr(provider, 'enrich_ip'):
                # Use Google DNS as a safe test target
                test_result = await provider.enrich_ip('8.8.8.8')
            else:
                test_result = {"success": True}

            end_time = datetime.utcnow()
            response_time_ms = (end_time - start_time).total_seconds() * 1000

            # Determine health status
            if test_result.get('error'):
                if 'rate limit' in str(test_result.get('error', '')).lower():
                    status = IntegrationHealth.DEGRADED
                    error_msg = "Rate limited"
                else:
                    status = IntegrationHealth.UNHEALTHY
                    error_msg = test_result.get('error')
            elif response_time_ms > 10000:  # >10s is degraded
                status = IntegrationHealth.DEGRADED
                error_msg = f"Slow response: {response_time_ms:.0f}ms"
            else:
                status = IntegrationHealth.HEALTHY
                error_msg = None

            # Extract rate limit info if available
            rate_limit_remaining = test_result.get('rate_limit_remaining')
            rate_limit_reset = None
            if test_result.get('rate_limit_reset'):
                try:
                    rate_limit_reset = datetime.fromtimestamp(test_result['rate_limit_reset'])
                except:
                    pass

            result = HealthCheckResult(
                integration_id=integration_id,
                status=status,
                response_time_ms=response_time_ms,
                last_check=end_time,
                error_message=error_msg,
                consecutive_failures=0 if status == IntegrationHealth.HEALTHY else _health_cache.get(integration_id, HealthCheckResult(integration_id, IntegrationHealth.UNKNOWN)).consecutive_failures + 1,
                rate_limit_remaining=rate_limit_remaining,
                rate_limit_reset=rate_limit_reset
            )

            # Update database with health status
            await self._update_health_status(integration_id, result)

        except Exception as e:
            end_time = datetime.utcnow()
            response_time_ms = (end_time - start_time).total_seconds() * 1000

            previous = _health_cache.get(integration_id, HealthCheckResult(integration_id, IntegrationHealth.UNKNOWN))

            result = HealthCheckResult(
                integration_id=integration_id,
                status=IntegrationHealth.UNHEALTHY,
                response_time_ms=response_time_ms,
                last_check=end_time,
                error_message=str(e),
                consecutive_failures=previous.consecutive_failures + 1
            )

            await self._update_health_status(integration_id, result)

        _health_cache[integration_id] = result
        return result

    async def _update_health_status(
        self,
        integration_id: str,
        result: HealthCheckResult
    ):
        """Update integration health status in database"""
        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE integrations
                    SET health_status = $1,
                        last_health_check = $2,
                        last_health_error = $3,
                        avg_response_time_ms = COALESCE(
                            (avg_response_time_ms * 0.7 + $4 * 0.3),
                            $4
                        ),
                        consecutive_failures = $5,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE integration_id = $6
                ''',
                    result.status.value,
                    result.last_check,
                    result.error_message,
                    result.response_time_ms,
                    result.consecutive_failures,
                    integration_id
                )
        except Exception as e:
            logger.error(f"Failed to update health status: {e}")

    async def check_all_integrations_health(self) -> Dict[str, HealthCheckResult]:
        """
        Check health of all enabled integrations.

        Returns dict of integration_id -> HealthCheckResult
        """
        integrations = await self.list_integrations(enabled_only=True)
        results = {}

        # Check in parallel with concurrency limit
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent checks

        async def check_one(integration):
            async with semaphore:
                result = await self.check_integration_health(
                    integration['integration_id'],
                    force=True
                )
                return integration['integration_id'], result

        tasks = [check_one(i) for i in integrations]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, Exception):
                logger.error(f"Health check error: {item}")
                continue
            integration_id, result = item
            results[integration_id] = result

        return results

    async def get_health_dashboard(self) -> Dict[str, Any]:
        """
        Get overall integration health dashboard data.
        """
        integrations = await self.list_integrations()

        healthy = 0
        degraded = 0
        unhealthy = 0
        unknown = 0

        integration_details = []

        for integration in integrations:
            int_id = integration['integration_id']
            cached = _health_cache.get(int_id)

            if cached:
                status = cached.status
                if status == IntegrationHealth.HEALTHY:
                    healthy += 1
                elif status == IntegrationHealth.DEGRADED:
                    degraded += 1
                elif status == IntegrationHealth.UNHEALTHY:
                    unhealthy += 1
                else:
                    unknown += 1

                integration_details.append({
                    'integration_id': int_id,
                    'name': integration['name'],
                    'provider': integration['provider'],
                    'enabled': integration['enabled'],
                    'status': status.value,
                    'response_time_ms': cached.response_time_ms,
                    'last_check': cached.last_check.isoformat() if cached.last_check else None,
                    'error': cached.error_message,
                    'consecutive_failures': cached.consecutive_failures
                })
            else:
                unknown += 1
                integration_details.append({
                    'integration_id': int_id,
                    'name': integration['name'],
                    'provider': integration['provider'],
                    'enabled': integration['enabled'],
                    'status': 'unknown',
                    'response_time_ms': None,
                    'last_check': None,
                    'error': None,
                    'consecutive_failures': 0
                })

        total = len(integrations)
        health_score = (healthy / total * 100) if total > 0 else 0

        return {
            'summary': {
                'total': total,
                'healthy': healthy,
                'degraded': degraded,
                'unhealthy': unhealthy,
                'unknown': unknown,
                'health_score': round(health_score, 1)
            },
            'integrations': integration_details
        }

    # =========================================================================
    # LIVE TESTING
    # =========================================================================

    async def live_test_integration(
        self,
        integration_id: str,
        test_iocs: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Perform live testing of an integration with sample IOCs.

        Args:
            integration_id: Integration to test
            test_iocs: Optional dict of {ioc_type: ioc_value} to test with

        Returns:
            Test results with response times and data samples
        """
        integration = await self.get_integration(integration_id)
        if not integration:
            return {"success": False, "error": "Integration not found"}

        provider_name = integration['provider']
        provider_class = self.providers.get(provider_name)

        if not provider_class:
            return {"success": False, "error": f"Provider {provider_name} not registered"}

        credentials = await self.get_integration_credentials(integration_id)
        api_key = credentials.get('api_key') if credentials else None

        # Default test IOCs (known-safe values)
        if not test_iocs:
            test_iocs = {
                'ip': '8.8.8.8',  # Google DNS
                'domain': 'google.com',
                'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # Empty file SHA256
            }

        results = {
            'integration_id': integration_id,
            'provider': provider_name,
            'tests': [],
            'summary': {
                'passed': 0,
                'failed': 0,
                'avg_response_time_ms': 0
            }
        }

        try:
            provider = provider_class(api_key=api_key)
            total_time = 0
            test_count = 0

            for ioc_type, ioc_value in test_iocs.items():
                test_result = await self._run_single_test(provider, ioc_type, ioc_value)
                results['tests'].append(test_result)

                if test_result['success']:
                    results['summary']['passed'] += 1
                    total_time += test_result.get('response_time_ms', 0)
                    test_count += 1
                else:
                    results['summary']['failed'] += 1

            if test_count > 0:
                results['summary']['avg_response_time_ms'] = round(total_time / test_count, 2)

            results['success'] = results['summary']['failed'] == 0

        except Exception as e:
            results['success'] = False
            results['error'] = str(e)

        return results

    async def _run_single_test(
        self,
        provider,
        ioc_type: str,
        ioc_value: str
    ) -> Dict[str, Any]:
        """Run a single IOC enrichment test"""
        start_time = datetime.utcnow()

        try:
            if ioc_type == 'ip' and hasattr(provider, 'enrich_ip'):
                data = await provider.enrich_ip(ioc_value)
            elif ioc_type == 'domain' and hasattr(provider, 'enrich_domain'):
                data = await provider.enrich_domain(ioc_value)
            elif ioc_type == 'hash' and hasattr(provider, 'enrich_file_hash'):
                data = await provider.enrich_file_hash(ioc_value)
            elif ioc_type == 'url' and hasattr(provider, 'enrich_url'):
                data = await provider.enrich_url(ioc_value)
            else:
                return {
                    'ioc_type': ioc_type,
                    'ioc_value': ioc_value,
                    'success': False,
                    'error': f"Enrichment method not available for {ioc_type}"
                }

            end_time = datetime.utcnow()
            response_time_ms = (end_time - start_time).total_seconds() * 1000

            if data.get('error'):
                return {
                    'ioc_type': ioc_type,
                    'ioc_value': ioc_value,
                    'success': False,
                    'response_time_ms': response_time_ms,
                    'error': data.get('error')
                }

            return {
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'success': True,
                'response_time_ms': round(response_time_ms, 2),
                'data_preview': self._preview_data(data)
            }

        except Exception as e:
            end_time = datetime.utcnow()
            response_time_ms = (end_time - start_time).total_seconds() * 1000

            return {
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'success': False,
                'response_time_ms': round(response_time_ms, 2),
                'error': str(e)
            }

    def _preview_data(self, data: Dict[str, Any], max_len: int = 500) -> Dict[str, Any]:
        """Create a preview of enrichment data (truncated for display)"""
        preview = {}
        for key, value in data.items():
            if isinstance(value, str) and len(value) > max_len:
                preview[key] = value[:max_len] + '...'
            elif isinstance(value, (list, dict)):
                preview[key] = f"[{type(value).__name__} with {len(value)} items]"
            else:
                preview[key] = value
        return preview

    # =========================================================================
    # RESPONSE NORMALIZATION
    # =========================================================================

    def normalize_response(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """
        Normalize provider response to standard format.

        This enables consistent handling across different providers.
        """
        if raw_data.get('error'):
            return NormalizedResponse(
                success=False,
                provider=provider,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                error=raw_data.get('error'),
                raw_data=raw_data
            )

        # Provider-specific normalization
        normalizers = {
            'virustotal': self._normalize_virustotal,
            'abuseipdb': self._normalize_abuseipdb,
            'shodan': self._normalize_shodan,
            'greynoise': self._normalize_greynoise,
            'otx': self._normalize_otx,
            'urlhaus': self._normalize_urlhaus,
        }

        normalizer = normalizers.get(provider, self._normalize_generic)
        return normalizer(provider, ioc_type, ioc_value, raw_data)

    def _normalize_virustotal(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Normalize VirusTotal response"""
        malicious = raw_data.get('malicious', 0)
        suspicious = raw_data.get('suspicious', 0)
        total = raw_data.get('total', 1)

        # Calculate threat score (0-100)
        threat_score = ((malicious * 2 + suspicious) / (total * 2)) * 100 if total > 0 else 0

        # Determine verdict
        if malicious > 5 or threat_score > 50:
            verdict = 'malicious'
        elif malicious > 0 or suspicious > 0:
            verdict = 'suspicious'
        else:
            verdict = 'benign'

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=min(100, threat_score + 20) if verdict != 'benign' else 80,
            threat_score=threat_score,
            categories=raw_data.get('categories', []),
            tags=raw_data.get('tags', []),
            raw_data=raw_data
        )

    def _normalize_abuseipdb(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Normalize AbuseIPDB response"""
        abuse_score = raw_data.get('abuseConfidenceScore', 0)
        total_reports = raw_data.get('totalReports', 0)

        if abuse_score > 80:
            verdict = 'malicious'
        elif abuse_score > 30:
            verdict = 'suspicious'
        else:
            verdict = 'benign'

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=abuse_score,
            threat_score=abuse_score,
            categories=raw_data.get('usageType', []) if isinstance(raw_data.get('usageType'), list) else [],
            raw_data=raw_data
        )

    def _normalize_shodan(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Normalize Shodan response"""
        vulns = raw_data.get('vulns', [])
        tags = raw_data.get('tags', [])

        if len(vulns) > 5:
            verdict = 'suspicious'
            threat_score = min(100, len(vulns) * 10)
        elif len(vulns) > 0:
            verdict = 'suspicious'
            threat_score = min(50, len(vulns) * 10)
        else:
            verdict = 'benign'
            threat_score = 0

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=70 if vulns else 60,
            threat_score=threat_score,
            tags=tags + [f"CVE: {v}" for v in vulns[:5]],
            raw_data=raw_data
        )

    def _normalize_greynoise(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Normalize GreyNoise response"""
        classification = raw_data.get('classification', 'unknown')
        noise = raw_data.get('noise', False)

        verdict_map = {
            'malicious': 'malicious',
            'benign': 'benign',
            'unknown': 'unknown'
        }
        verdict = verdict_map.get(classification, 'unknown')

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=85 if classification != 'unknown' else 50,
            threat_score=90 if classification == 'malicious' else 10 if classification == 'benign' else 50,
            tags=['noise'] if noise else [],
            raw_data=raw_data
        )

    def _normalize_otx(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Normalize AlienVault OTX response"""
        pulse_count = raw_data.get('pulse_count', 0)

        if pulse_count > 10:
            verdict = 'malicious'
            threat_score = min(100, pulse_count * 5)
        elif pulse_count > 0:
            verdict = 'suspicious'
            threat_score = min(50, pulse_count * 10)
        else:
            verdict = 'benign'
            threat_score = 0

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=70 if pulse_count > 0 else 50,
            threat_score=threat_score,
            tags=[f"pulses:{pulse_count}"],
            raw_data=raw_data
        )

    def _normalize_urlhaus(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Normalize URLhaus response"""
        url_status = raw_data.get('url_status', 'unknown')
        threat = raw_data.get('threat', '')

        if url_status == 'online' and threat:
            verdict = 'malicious'
            threat_score = 95
        elif threat:
            verdict = 'suspicious'
            threat_score = 70
        else:
            verdict = 'benign'
            threat_score = 0

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=90 if threat else 60,
            threat_score=threat_score,
            categories=[threat] if threat else [],
            raw_data=raw_data
        )

    def _normalize_generic(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        raw_data: Dict[str, Any]
    ) -> NormalizedResponse:
        """Generic normalizer for unknown providers"""
        # Try to extract common fields
        is_malicious = raw_data.get('is_malicious', raw_data.get('malicious', False))
        threat_score = raw_data.get('threat_score', raw_data.get('score', 0))

        if is_malicious:
            verdict = 'malicious'
        elif threat_score > 50:
            verdict = 'suspicious'
        else:
            verdict = 'unknown'

        return NormalizedResponse(
            success=True,
            provider=provider,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            confidence=50,  # Low confidence for unknown providers
            threat_score=threat_score,
            raw_data=raw_data
        )


# Singleton instance (will be initialized in app.py)
integration_manager = None
