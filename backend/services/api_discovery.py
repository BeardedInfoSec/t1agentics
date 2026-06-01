# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
API Discovery Service

Discover and import integrations from:
1. APIs.guru catalog (thousands of OpenAPI specs)
2. SwaggerHub public APIs
3. Direct OpenAPI URL input
4. GitHub OpenAPI repositories
5. RapidAPI marketplace

Enables no-code integration creation by searching for vendor APIs.
"""

import os
import httpx
import asyncio
import json
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from datetime import datetime
from enum import Enum


class DiscoverySource(str, Enum):
    """Sources for API discovery"""
    APIS_GURU = "apis_guru"
    SWAGGERHUB = "swaggerhub"
    POSTMAN = "postman"
    GITHUB = "github"
    RAPIDAPI = "rapidapi"
    DIRECT = "direct"


class DiscoveredAPI(BaseModel):
    """Represents a discovered API from any source"""
    id: str
    name: str
    description: Optional[str] = None
    provider: str
    version: str
    category: Optional[str] = None
    tags: List[str] = []
    openapi_url: str
    documentation_url: Optional[str] = None
    logo_url: Optional[str] = None
    source: DiscoverySource
    popularity_score: Optional[int] = None
    last_updated: Optional[datetime] = None


class APIDiscoveryService:
    """
    Service for discovering APIs from various catalogs.

    Search by name, category, or specific vendor to find OpenAPI specs
    that can be automatically imported as integrations.
    """

    APIS_GURU_CATALOG_URL = "https://api.apis.guru/v2/list.json"
    SWAGGERHUB_SEARCH_URL = "https://api.swaggerhub.com/apis"
    POSTMAN_API_URL = "https://api.getpostman.com"

    def __init__(self):
        self._apis_guru_cache: Optional[Dict[str, Any]] = None
        self._postman_cache: Optional[Dict[str, Any]] = None
        self._cache_time: Optional[datetime] = None
        self._postman_cache_time: Optional[datetime] = None
        self._cache_ttl_hours = 24
        # Postman API key for authenticated access to the Public API Network.
        # Optional: set POSTMAN_API_KEY to enable Postman-sourced discovery.
        self._postman_api_key = os.environ.get("POSTMAN_API_KEY", "")

    async def search(
        self,
        query: str,
        sources: Optional[List[DiscoverySource]] = None,
        category: Optional[str] = None,
        limit: int = 50
    ) -> List[DiscoveredAPI]:
        """
        Search for APIs across all discovery sources.

        Args:
            query: Search term (vendor name, API name, etc.)
            sources: Specific sources to search (default: all)
            category: Filter by category
            limit: Maximum results

        Returns:
            List of discovered APIs matching the query
        """
        if sources is None:
            sources = [DiscoverySource.APIS_GURU, DiscoverySource.POSTMAN]  # Search multiple sources

        results = []
        search_tasks = []

        for source in sources:
            if source == DiscoverySource.APIS_GURU:
                search_tasks.append(self._search_apis_guru(query, category, limit))
            elif source == DiscoverySource.SWAGGERHUB:
                search_tasks.append(self._search_swaggerhub(query, limit))
            elif source == DiscoverySource.POSTMAN:
                search_tasks.append(self._search_postman(query, limit))

        # Run searches in parallel
        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        for result in search_results:
            if isinstance(result, list):
                results.extend(result)
            elif isinstance(result, Exception):
                print(f"Search error: {result}")

        # Sort by relevance (name match score)
        query_lower = query.lower()
        results.sort(key=lambda api: (
            0 if query_lower in api.name.lower() else 1,
            0 if query_lower in api.provider.lower() else 1,
            -1 * (api.popularity_score or 0)
        ))

        return results[:limit]

    async def _search_apis_guru(
        self,
        query: str,
        category: Optional[str],
        limit: int
    ) -> List[DiscoveredAPI]:
        """Search APIs.guru catalog"""

        # Refresh cache if needed
        await self._refresh_apis_guru_cache()

        if not self._apis_guru_cache:
            return []

        query_lower = query.lower()
        results = []

        for api_id, api_info in self._apis_guru_cache.items():
            # Get the preferred version
            preferred = api_info.get('preferred', '')
            versions = api_info.get('versions', {})

            if not preferred or preferred not in versions:
                continue

            version_info = versions[preferred]

            # Build searchable text
            title = version_info.get('info', {}).get('title', '')
            description = version_info.get('info', {}).get('description', '')
            provider = api_id.split(':')[0] if ':' in api_id else api_id

            searchable = f"{title} {description} {provider} {api_id}".lower()

            # Check if query matches
            if query_lower not in searchable:
                continue

            # Get OpenAPI URL
            openapi_url = version_info.get('swaggerUrl') or version_info.get('openapiUrl')
            if not openapi_url:
                continue

            # Category filter
            api_categories = version_info.get('info', {}).get('x-apisguru-categories', [])
            if category and category.lower() not in [c.lower() for c in api_categories]:
                continue

            # Create discovered API
            discovered = DiscoveredAPI(
                id=f"apis_guru:{api_id}:{preferred}",
                name=title or api_id,
                description=description[:500] if description else None,
                provider=provider,
                version=preferred,
                category=api_categories[0] if api_categories else None,
                tags=api_categories,
                openapi_url=openapi_url,
                documentation_url=version_info.get('info', {}).get('x-origin', [{}])[0].get('url'),
                logo_url=version_info.get('info', {}).get('x-logo', {}).get('url'),
                source=DiscoverySource.APIS_GURU,
                popularity_score=self._calculate_popularity(version_info),
                last_updated=datetime.fromisoformat(version_info.get('updated', '2020-01-01').replace('Z', '+00:00')) if version_info.get('updated') else None
            )

            results.append(discovered)

            if len(results) >= limit:
                break

        return results

    async def _search_swaggerhub(self, query: str, limit: int) -> List[DiscoveredAPI]:
        """Search SwaggerHub public APIs"""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.SWAGGERHUB_SEARCH_URL,
                    params={
                        'query': query,
                        'limit': limit,
                        'page': 0,
                        'sort': 'BEST_MATCH',
                        'order': 'DESC'
                    },
                    headers={
                        'Accept': 'application/json'
                    },
                    timeout=30.0
                )

                if response.status_code != 200:
                    return []

                data = response.json()
                results = []

                for api in data.get('apis', []):
                    properties = api.get('properties', [])

                    # Extract properties
                    props_dict = {p['type']: p.get('value') or p.get('url') for p in properties}

                    discovered = DiscoveredAPI(
                        id=f"swaggerhub:{api.get('name', '')}",
                        name=api.get('name', ''),
                        description=api.get('description'),
                        provider=api.get('owner', ''),
                        version=props_dict.get('X-Version', '1.0.0'),
                        openapi_url=props_dict.get('Swagger', '') or f"https://api.swaggerhub.com/apis/{api.get('owner')}/{api.get('name')}",
                        source=DiscoverySource.SWAGGERHUB,
                        tags=[],
                        last_updated=datetime.fromisoformat(props_dict.get('X-Updated', '2020-01-01').replace('Z', '+00:00')) if props_dict.get('X-Updated') else None
                    )

                    results.append(discovered)

                return results

        except Exception as e:
            print(f"SwaggerHub search error: {e}")
            return []

    async def _search_postman(self, query: str, limit: int) -> List[DiscoveredAPI]:
        """
        Search Postman Public API Network using the official Postman API.

        Uses authenticated API access to search collections and APIs.
        Falls back to curated list if API fails.
        """
        results = []

        try:
            async with httpx.AsyncClient() as client:
                # Search Postman collections using the official API
                # The /collections endpoint lists user's collections
                # We'll use the workspace APIs endpoint for public API discovery

                # First try to get APIs from the Public API Network
                response = await client.get(
                    f"{self.POSTMAN_API_URL}/apis",
                    headers={
                        'X-API-Key': self._postman_api_key,
                        'Accept': 'application/json'
                    },
                    timeout=30.0
                )

                if response.status_code == 200:
                    data = response.json()
                    apis = data.get('apis', [])
                    print(f"Postman API returned {len(apis)} APIs")

                    query_lower = query.lower()
                    for api in apis:
                        name = api.get('name', '')
                        description = api.get('description', '')

                        # Filter by query
                        if query_lower not in name.lower() and query_lower not in (description or '').lower():
                            continue

                        discovered = DiscoveredAPI(
                            id=f"postman:api:{api.get('id', '')}",
                            name=name,
                            description=description[:500] if description else None,
                            provider="Postman",
                            version='1.0.0',
                            category=None,
                            tags=[],
                            openapi_url=f"https://api.getpostman.com/apis/{api.get('id')}",
                            documentation_url=f"https://www.postman.com/api/{api.get('id')}",
                            source=DiscoverySource.POSTMAN,
                            popularity_score=50
                        )
                        results.append(discovered)

                        if len(results) >= limit:
                            break

                # Also search collections
                collections_response = await client.get(
                    f"{self.POSTMAN_API_URL}/collections",
                    headers={
                        'X-API-Key': self._postman_api_key,
                        'Accept': 'application/json'
                    },
                    timeout=30.0
                )

                if collections_response.status_code == 200:
                    data = collections_response.json()
                    collections = data.get('collections', [])
                    print(f"Postman API returned {len(collections)} collections")

                    query_lower = query.lower()
                    for col in collections:
                        name = col.get('name', '')

                        # Filter by query
                        if query_lower not in name.lower():
                            continue

                        discovered = DiscoveredAPI(
                            id=f"postman:collection:{col.get('id', col.get('uid', ''))}",
                            name=name,
                            description=None,
                            provider=col.get('owner', 'Postman'),
                            version='1.0.0',
                            category=None,
                            tags=[],
                            openapi_url=f"https://api.getpostman.com/collections/{col.get('uid', col.get('id'))}",
                            documentation_url=f"https://www.postman.com/collection/{col.get('uid', col.get('id'))}",
                            source=DiscoverySource.POSTMAN,
                            popularity_score=40
                        )
                        results.append(discovered)

                        if len(results) >= limit:
                            break

                if results:
                    return results[:limit]

        except Exception as e:
            print(f"Postman API error: {e}")

        # Fallback: Search curated Postman collections we know about
        curated = self._get_curated_postman_collections(query, limit - len(results))
        results.extend(curated)

        return results[:limit]

    def _get_curated_postman_collections(self, query: str, limit: int) -> List[DiscoveredAPI]:
        """
        Return curated list of known high-quality Postman collections.
        These are popular security and infrastructure APIs on Postman.

        Note: Postman's API only provides access to your own workspace, not the
        Public API Network. This curated list serves as a fallback for common
        security-focused APIs.
        """

        # Curated list of popular Postman collections (security-focused)
        curated_collections = [
            # ===== Security / EDR =====
            {
                "id": "12959542-crowdstrike-falcon",
                "name": "CrowdStrike Falcon API",
                "description": "CrowdStrike Falcon platform APIs for endpoint detection and response",
                "provider": "CrowdStrike",
                "category": "security",
                "tags": ["edr", "security", "threat-intel", "endpoint"],
                "documentation_url": "https://www.postman.com/crowdstrike"
            },
            {
                "id": "12959542-sentinelone",
                "name": "SentinelOne API",
                "description": "SentinelOne autonomous endpoint protection platform API",
                "provider": "SentinelOne",
                "category": "security",
                "tags": ["edr", "security", "endpoint", "autonomous"],
                "documentation_url": "https://www.postman.com/sentinelone"
            },
            {
                "id": "12959542-carbon-black",
                "name": "VMware Carbon Black API",
                "description": "Carbon Black Cloud endpoint security and EDR API",
                "provider": "VMware",
                "category": "security",
                "tags": ["edr", "security", "endpoint", "vmware"],
                "documentation_url": "https://www.postman.com/carbonblack"
            },
            {
                "id": "12959542-microsoft-defender",
                "name": "Microsoft Defender for Endpoint API",
                "description": "Microsoft Defender ATP endpoint detection and response API",
                "provider": "Microsoft",
                "category": "security",
                "tags": ["edr", "security", "microsoft", "endpoint"],
                "documentation_url": "https://www.postman.com/microsoft"
            },

            # ===== Threat Intelligence =====
            {
                "id": "12959542-virustotal",
                "name": "VirusTotal API v3",
                "description": "VirusTotal file, URL, domain, and IP analysis API",
                "provider": "VirusTotal",
                "category": "security",
                "tags": ["malware", "threat-intel", "file-analysis", "ioc"],
                "documentation_url": "https://www.postman.com/virustotal"
            },
            {
                "id": "12959542-shodan",
                "name": "Shodan API",
                "description": "Shodan internet-wide scanning and reconnaissance API",
                "provider": "Shodan",
                "category": "security",
                "tags": ["reconnaissance", "threat-intel", "vulnerability", "osint"],
                "documentation_url": "https://www.postman.com/shodan-io"
            },
            {
                "id": "12959542-greynoise",
                "name": "GreyNoise API",
                "description": "GreyNoise internet scanner and noise intelligence API",
                "provider": "GreyNoise",
                "category": "security",
                "tags": ["threat-intel", "noise", "scanner", "ip-reputation"],
                "documentation_url": "https://www.postman.com/greynoise"
            },
            {
                "id": "12959542-abuseipdb",
                "name": "AbuseIPDB API",
                "description": "AbuseIPDB IP address reputation and blacklist API",
                "provider": "AbuseIPDB",
                "category": "security",
                "tags": ["threat-intel", "ip-reputation", "blacklist", "abuse"],
                "documentation_url": "https://www.postman.com/abuseipdb"
            },
            {
                "id": "12959542-alienvault-otx",
                "name": "AlienVault OTX API",
                "description": "Open Threat Exchange threat intelligence platform API",
                "provider": "AlienVault",
                "category": "security",
                "tags": ["threat-intel", "otx", "ioc", "pulses"],
                "documentation_url": "https://www.postman.com/alienvault"
            },
            {
                "id": "12959542-urlscan",
                "name": "urlscan.io API",
                "description": "Website scanning and threat analysis API",
                "provider": "urlscan.io",
                "category": "security",
                "tags": ["threat-intel", "url-scanning", "phishing", "web-analysis"],
                "documentation_url": "https://www.postman.com/urlscan"
            },
            {
                "id": "12959542-ipinfo",
                "name": "IPinfo API",
                "description": "IP address geolocation and network intelligence API",
                "provider": "IPinfo",
                "category": "security",
                "tags": ["ip-geolocation", "network", "asn", "vpn-detection"],
                "documentation_url": "https://www.postman.com/ipinfo"
            },

            # ===== SIEM / Logging =====
            {
                "id": "12959542-splunk",
                "name": "Splunk REST API",
                "description": "Splunk SIEM and log management API",
                "provider": "Splunk",
                "category": "siem",
                "tags": ["siem", "logging", "search", "analytics"],
                "documentation_url": "https://www.postman.com/splunk"
            },
            {
                "id": "12959542-elastic",
                "name": "Elasticsearch API",
                "description": "Elastic stack search and SIEM API",
                "provider": "Elastic",
                "category": "siem",
                "tags": ["siem", "search", "logging", "elk"],
                "documentation_url": "https://www.postman.com/elastic"
            },
            {
                "id": "12959542-datadog",
                "name": "Datadog API",
                "description": "Datadog monitoring and security API",
                "provider": "Datadog",
                "category": "monitoring",
                "tags": ["monitoring", "security", "logs", "metrics"],
                "documentation_url": "https://www.postman.com/datadog"
            },

            # ===== Incident Response / Ticketing =====
            {
                "id": "12959542-pagerduty",
                "name": "PagerDuty API",
                "description": "PagerDuty incident management and on-call scheduling API",
                "provider": "PagerDuty",
                "category": "incident-response",
                "tags": ["alerting", "incident-management", "on-call", "escalation"],
                "documentation_url": "https://www.postman.com/pagerduty"
            },
            {
                "id": "12959542-opsgenie",
                "name": "Opsgenie API",
                "description": "Opsgenie alerting and incident management API",
                "provider": "Atlassian",
                "category": "incident-response",
                "tags": ["alerting", "incident-management", "on-call"],
                "documentation_url": "https://www.postman.com/opsgenie"
            },
            {
                "id": "12959542-servicenow",
                "name": "ServiceNow API",
                "description": "ServiceNow IT service management and security operations API",
                "provider": "ServiceNow",
                "category": "ticketing",
                "tags": ["itsm", "ticketing", "security-operations", "cmdb"],
                "documentation_url": "https://www.postman.com/servicenow"
            },
            {
                "id": "12959542-jira",
                "name": "Jira Cloud REST API",
                "description": "Atlassian Jira project and issue tracking API",
                "provider": "Atlassian",
                "category": "ticketing",
                "tags": ["ticketing", "project-management", "issues"],
                "documentation_url": "https://www.postman.com/atlassian"
            },
            {
                "id": "12959542-thehive",
                "name": "TheHive API",
                "description": "TheHive security incident response platform API",
                "provider": "TheHive Project",
                "category": "incident-response",
                "tags": ["incident-response", "case-management", "soar"],
                "documentation_url": "https://www.postman.com/thehive-project"
            },

            # ===== Identity / IAM =====
            {
                "id": "12959542-okta",
                "name": "Okta API",
                "description": "Okta identity and access management API",
                "provider": "Okta",
                "category": "identity",
                "tags": ["identity", "authentication", "sso", "iam"],
                "documentation_url": "https://www.postman.com/okta"
            },
            {
                "id": "12959542-duo",
                "name": "Duo Security API",
                "description": "Cisco Duo multi-factor authentication API",
                "provider": "Cisco",
                "category": "identity",
                "tags": ["mfa", "authentication", "security", "2fa"],
                "documentation_url": "https://www.postman.com/duo-security"
            },
            {
                "id": "12959542-auth0",
                "name": "Auth0 Management API",
                "description": "Auth0 identity platform management API",
                "provider": "Auth0",
                "category": "identity",
                "tags": ["identity", "authentication", "iam", "oauth"],
                "documentation_url": "https://www.postman.com/auth0"
            },
            {
                "id": "12959542-azure-ad",
                "name": "Microsoft Entra ID (Azure AD) API",
                "description": "Microsoft Entra identity and directory services API",
                "provider": "Microsoft",
                "category": "identity",
                "tags": ["identity", "azure", "directory", "iam"],
                "documentation_url": "https://www.postman.com/microsoft"
            },

            # ===== Communication =====
            {
                "id": "12959542-slack",
                "name": "Slack Web API",
                "description": "Slack messaging and workspace management API",
                "provider": "Slack",
                "category": "communication",
                "tags": ["messaging", "communication", "notifications", "chat"],
                "documentation_url": "https://www.postman.com/slackapi"
            },
            {
                "id": "12959542-teams",
                "name": "Microsoft Teams API",
                "description": "Microsoft Teams messaging and collaboration API",
                "provider": "Microsoft",
                "category": "communication",
                "tags": ["messaging", "teams", "collaboration", "microsoft"],
                "documentation_url": "https://www.postman.com/microsoft"
            },
            {
                "id": "12959542-discord",
                "name": "Discord API",
                "description": "Discord messaging platform API",
                "provider": "Discord",
                "category": "communication",
                "tags": ["messaging", "chat", "webhooks", "bots"],
                "documentation_url": "https://www.postman.com/discord"
            },

            # ===== Cloud Providers =====
            {
                "id": "12959542-aws",
                "name": "AWS APIs",
                "description": "Amazon Web Services API collection",
                "provider": "Amazon",
                "category": "cloud",
                "tags": ["cloud", "infrastructure", "aws", "amazon"],
                "documentation_url": "https://www.postman.com/amazon"
            },
            {
                "id": "12959542-azure",
                "name": "Microsoft Azure APIs",
                "description": "Microsoft Azure cloud services API collection",
                "provider": "Microsoft",
                "category": "cloud",
                "tags": ["cloud", "infrastructure", "azure", "microsoft"],
                "documentation_url": "https://www.postman.com/microsoft"
            },
            {
                "id": "12959542-gcp",
                "name": "Google Cloud APIs",
                "description": "Google Cloud Platform API collection",
                "provider": "Google",
                "category": "cloud",
                "tags": ["cloud", "infrastructure", "gcp", "google"],
                "documentation_url": "https://www.postman.com/google"
            },

            # ===== DevOps / CI-CD =====
            {
                "id": "12959542-github",
                "name": "GitHub REST API",
                "description": "GitHub repositories, issues, and actions API",
                "provider": "GitHub",
                "category": "devops",
                "tags": ["git", "repositories", "ci-cd", "actions"],
                "documentation_url": "https://www.postman.com/github"
            },
            {
                "id": "12959542-gitlab",
                "name": "GitLab API",
                "description": "GitLab DevOps platform API",
                "provider": "GitLab",
                "category": "devops",
                "tags": ["git", "repositories", "ci-cd", "devops"],
                "documentation_url": "https://www.postman.com/gitlab"
            },
            {
                "id": "12959542-jenkins",
                "name": "Jenkins API",
                "description": "Jenkins CI/CD automation server API",
                "provider": "Jenkins",
                "category": "devops",
                "tags": ["ci-cd", "automation", "builds", "pipelines"],
                "documentation_url": "https://www.postman.com/jenkins"
            },

            # ===== Email Security =====
            {
                "id": "12959542-proofpoint",
                "name": "Proofpoint API",
                "description": "Proofpoint email security and threat protection API",
                "provider": "Proofpoint",
                "category": "security",
                "tags": ["email-security", "threat-protection", "phishing"],
                "documentation_url": "https://www.postman.com/proofpoint"
            },
            {
                "id": "12959542-mimecast",
                "name": "Mimecast API",
                "description": "Mimecast email security and archiving API",
                "provider": "Mimecast",
                "category": "security",
                "tags": ["email-security", "archiving", "threat-protection"],
                "documentation_url": "https://www.postman.com/mimecast"
            },

            # ===== Vulnerability Management =====
            {
                "id": "12959542-tenable",
                "name": "Tenable.io API",
                "description": "Tenable vulnerability management and assessment API",
                "provider": "Tenable",
                "category": "security",
                "tags": ["vulnerability", "scanning", "assessment", "nessus"],
                "documentation_url": "https://www.postman.com/tenable"
            },
            {
                "id": "12959542-qualys",
                "name": "Qualys API",
                "description": "Qualys cloud security and compliance API",
                "provider": "Qualys",
                "category": "security",
                "tags": ["vulnerability", "compliance", "scanning", "security"],
                "documentation_url": "https://www.postman.com/qualys"
            },
            {
                "id": "12959542-rapid7",
                "name": "Rapid7 InsightVM API",
                "description": "Rapid7 vulnerability management and penetration testing API",
                "provider": "Rapid7",
                "category": "security",
                "tags": ["vulnerability", "scanning", "nexpose", "insightvm"],
                "documentation_url": "https://www.postman.com/rapid7"
            }
        ]

        query_lower = query.lower()
        results = []

        for col in curated_collections:
            # Check if query matches
            searchable = f"{col['name']} {col['description']} {col['provider']} {' '.join(col['tags'])}".lower()
            if query_lower in searchable:
                discovered = DiscoveredAPI(
                    id=f"postman:{col['id']}",
                    name=col['name'],
                    description=col['description'],
                    provider=col['provider'],
                    version='1.0.0',
                    category=col['category'],
                    tags=col['tags'],
                    openapi_url=col['documentation_url'],
                    documentation_url=col['documentation_url'],
                    source=DiscoverySource.POSTMAN,
                    popularity_score=50  # Curated = high quality
                )
                results.append(discovered)

        return results[:limit]

    async def _refresh_apis_guru_cache(self):
        """Refresh the APIs.guru cache if needed"""

        # Check if cache is still valid
        if self._apis_guru_cache and self._cache_time:
            age = datetime.utcnow() - self._cache_time
            if age.total_seconds() < self._cache_ttl_hours * 3600:
                return

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.APIS_GURU_CATALOG_URL,
                    timeout=60.0
                )
                response.raise_for_status()

                self._apis_guru_cache = response.json()
                self._cache_time = datetime.utcnow()
                print(f"Refreshed APIs.guru cache: {len(self._apis_guru_cache)} APIs")

        except Exception as e:
            print(f"Failed to refresh APIs.guru cache: {e}")

    def _calculate_popularity(self, version_info: Dict[str, Any]) -> int:
        """Calculate a popularity score for ranking"""
        score = 0

        # Has logo
        if version_info.get('info', {}).get('x-logo'):
            score += 10

        # Has good description
        desc = version_info.get('info', {}).get('description', '')
        if len(desc) > 100:
            score += 5

        # Has contact info
        if version_info.get('info', {}).get('contact'):
            score += 5

        # Recently updated
        updated = version_info.get('updated')
        if updated:
            try:
                update_date = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                days_old = (datetime.utcnow().replace(tzinfo=update_date.tzinfo) - update_date).days
                if days_old < 365:
                    score += 10
                elif days_old < 730:
                    score += 5
            except:
                pass

        return score

    async def get_api_details(self, api_id: str) -> Optional[Dict[str, Any]]:
        """
        Get full details for a discovered API including the full OpenAPI spec.

        Args:
            api_id: The discovered API ID (e.g., "apis_guru:crowdstrike.com:1.0.0")

        Returns:
            Full API details including spec
        """
        parts = api_id.split(':')
        source = parts[0]

        if source == 'apis_guru':
            await self._refresh_apis_guru_cache()
            if not self._apis_guru_cache:
                return None

            # Reconstruct original API ID
            original_id = ':'.join(parts[1:-1])
            version = parts[-1]

            api_info = self._apis_guru_cache.get(original_id)
            if not api_info:
                return None

            version_info = api_info.get('versions', {}).get(version)
            if not version_info:
                return None

            return {
                'id': api_id,
                'info': version_info.get('info', {}),
                'openapi_url': version_info.get('swaggerUrl') or version_info.get('openapiUrl'),
                'source': 'apis_guru'
            }

        return None

    async def get_categories(self) -> List[str]:
        """Get list of available API categories from APIs.guru"""
        await self._refresh_apis_guru_cache()

        if not self._apis_guru_cache:
            return []

        categories = set()

        for api_info in self._apis_guru_cache.values():
            preferred = api_info.get('preferred', '')
            versions = api_info.get('versions', {})

            if preferred and preferred in versions:
                version_info = versions[preferred]
                api_categories = version_info.get('info', {}).get('x-apisguru-categories', [])
                categories.update(api_categories)

        return sorted(list(categories))

    async def get_popular_apis(self, category: Optional[str] = None, limit: int = 20) -> List[DiscoveredAPI]:
        """Get popular APIs, optionally filtered by category"""

        await self._refresh_apis_guru_cache()

        if not self._apis_guru_cache:
            return []

        results = []

        for api_id, api_info in self._apis_guru_cache.items():
            preferred = api_info.get('preferred', '')
            versions = api_info.get('versions', {})

            if not preferred or preferred not in versions:
                continue

            version_info = versions[preferred]

            # Category filter
            api_categories = version_info.get('info', {}).get('x-apisguru-categories', [])
            if category and category.lower() not in [c.lower() for c in api_categories]:
                continue

            openapi_url = version_info.get('swaggerUrl') or version_info.get('openapiUrl')
            if not openapi_url:
                continue

            title = version_info.get('info', {}).get('title', '')
            description = version_info.get('info', {}).get('description', '')
            provider = api_id.split(':')[0] if ':' in api_id else api_id

            discovered = DiscoveredAPI(
                id=f"apis_guru:{api_id}:{preferred}",
                name=title or api_id,
                description=description[:500] if description else None,
                provider=provider,
                version=preferred,
                category=api_categories[0] if api_categories else None,
                tags=api_categories,
                openapi_url=openapi_url,
                documentation_url=version_info.get('info', {}).get('x-origin', [{}])[0].get('url') if version_info.get('info', {}).get('x-origin') else None,
                logo_url=version_info.get('info', {}).get('x-logo', {}).get('url'),
                source=DiscoverySource.APIS_GURU,
                popularity_score=self._calculate_popularity(version_info)
            )

            results.append(discovered)

        # Sort by popularity
        results.sort(key=lambda api: -1 * (api.popularity_score or 0))

        return results[:limit]


# Security-focused API catalog - curated list of common security tools
SECURITY_API_CATALOG = {
    "crowdstrike": {
        "name": "CrowdStrike Falcon",
        "category": "edr",
        "description": "CrowdStrike Falcon EDR and threat intelligence platform",
        "documentation_url": "https://falcon.crowdstrike.com/documentation",
        "known_specs": [
            "https://assets.falcon.crowdstrike.com/support/api/swagger.json"
        ]
    },
    "sentinelone": {
        "name": "SentinelOne",
        "category": "edr",
        "description": "SentinelOne autonomous endpoint protection",
        "documentation_url": "https://usea1-partners.sentinelone.net/docs/en/api-reference.html"
    },
    "microsoft_defender": {
        "name": "Microsoft Defender for Endpoint",
        "category": "edr",
        "description": "Microsoft Defender for Endpoint security platform",
        "documentation_url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro",
        "known_specs": []
    },
    "palo_alto": {
        "name": "Palo Alto Networks",
        "category": "firewall",
        "description": "Palo Alto Networks NGFW and security services",
        "documentation_url": "https://pan.dev/"
    },
    "splunk": {
        "name": "Splunk",
        "category": "siem",
        "description": "Splunk SIEM and log management platform",
        "documentation_url": "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog"
    },
    "elastic": {
        "name": "Elastic Security",
        "category": "siem",
        "description": "Elastic Security (formerly Elastic SIEM)",
        "documentation_url": "https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html"
    },
    "servicenow": {
        "name": "ServiceNow",
        "category": "ticketing",
        "description": "ServiceNow IT service management and security operations",
        "documentation_url": "https://developer.servicenow.com/dev.do#!/reference/api/rome/rest"
    },
    "shodan": {
        "name": "Shodan",
        "category": "threat_intel",
        "description": "Shodan internet-wide scanning and threat intelligence",
        "documentation_url": "https://developer.shodan.io/api"
    },
    "greynoise": {
        "name": "GreyNoise",
        "category": "threat_intel",
        "description": "GreyNoise internet scanner and noise intelligence",
        "documentation_url": "https://docs.greynoise.io/reference"
    },
    "alienvault_otx": {
        "name": "AlienVault OTX",
        "category": "threat_intel",
        "description": "Open Threat Exchange threat intelligence platform",
        "documentation_url": "https://otx.alienvault.com/api"
    },
    "hybrid_analysis": {
        "name": "Hybrid Analysis",
        "category": "sandbox",
        "description": "Falcon Sandbox malware analysis service",
        "documentation_url": "https://www.hybrid-analysis.com/docs/api/v2"
    },
    "any_run": {
        "name": "ANY.RUN",
        "category": "sandbox",
        "description": "Interactive malware analysis sandbox",
        "documentation_url": "https://any.run/api-documentation/"
    },
    "urlscan": {
        "name": "urlscan.io",
        "category": "threat_intel",
        "description": "Website scanning and threat analysis",
        "documentation_url": "https://urlscan.io/docs/api/"
    },
    "misp": {
        "name": "MISP",
        "category": "threat_intel",
        "description": "Malware Information Sharing Platform",
        "documentation_url": "https://www.misp-project.org/openapi/"
    },
    "thehive": {
        "name": "TheHive",
        "category": "case_management",
        "description": "Security incident response platform",
        "documentation_url": "https://docs.thehive-project.org/thehive/api-docs/"
    },
    "cortex_xsoar": {
        "name": "Cortex XSOAR",
        "category": "soar",
        "description": "Palo Alto Cortex XSOAR security orchestration",
        "documentation_url": "https://xsoar.pan.dev/"
    }
}


# Singleton instance
_discovery_service: Optional[APIDiscoveryService] = None


def get_discovery_service() -> APIDiscoveryService:
    """Get the global API discovery service instance"""
    global _discovery_service
    if _discovery_service is None:
        _discovery_service = APIDiscoveryService()
    return _discovery_service
