# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Pre-Built Integrations

DEPRECATED: This module is deprecated and will be removed in a future release.
Pre-built integrations are now loaded from JSON files in backend/integration-store-output/integrations/
See services/integration_loader.py for the new loading mechanism.

This file is kept temporarily for backward compatibility only.
"""

import warnings

# Issue deprecation warning
warnings.warn(
    "prebuilt.py is deprecated and will be removed in a future release. "
    "Integrations are now loaded from JSON files in backend/integration-store-output/integrations/",
    DeprecationWarning,
    stacklevel=2
)

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


def register_virustotal() -> Integration:
    """Register VirusTotal integration"""
    
    integration = Integration(
        id="virustotal",
        name="VirusTotal",
        type=IntegrationType.THREAT_INTEL,
        description="VirusTotal is a free service that analyzes suspicious files and URLs to detect malware",
        version="3.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "x-apikey",
            "key_location": "header",
            "key_value": ""  # User must configure
        },
        base_url="https://www.virustotal.com/api/v3",
        enabled=False,  # Disabled by default
        vendor="VirusTotal",
        documentation_url="https://developers.virustotal.com/reference/overview",
        tags=["threat_intel", "malware", "file_analysis"],
        actions=[
            # File hash enrichment
            ActionSchema(
                id="enrich_file_hash",
                name="Get File Report",
                description="Get detailed report for a file hash",
                observable_type=ObservableType.FILE_HASH,
                http_method="GET",
                endpoint="/files/{hash}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=30,
                input_schema={
                    "type": "object",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "MD5, SHA1, or SHA256 hash"
                        }
                    },
                    "required": ["hash"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "object",
                            "properties": {
                                "attributes": {
                                    "type": "object",
                                    "properties": {
                                        "last_analysis_stats": {"type": "object"},
                                        "reputation": {"type": "integer"}
                                    }
                                }
                            }
                        }
                    }
                }
            ),
            
            # IP address enrichment
            ActionSchema(
                id="enrich_ip",
                name="Get IP Address Report",
                description="Get detailed report for an IP address",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/ip_addresses/{ip}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,  # Shorter TTL for IPs
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address (IPv4 or IPv6)"
                        }
                    },
                    "required": ["ip"]
                }
            ),
            
            # Domain enrichment
            ActionSchema(
                id="enrich_domain",
                name="Get Domain Report",
                description="Get detailed report for a domain",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/domains/{domain}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain name"
                        }
                    },
                    "required": ["domain"]
                }
            ),
            
            # URL enrichment - VT API v3 requires base64-encoded URL as the ID
            # The execution engine handles this via the url_id parameter
            ActionSchema(
                id="enrich_url",
                name="Get URL Report",
                description="Get detailed report for a URL",
                observable_type=ObservableType.URL,
                http_method="GET",
                endpoint="/urls/{url_id}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL to check"
                        },
                        "url_id": {
                            "type": "string",
                            "description": "Base64-encoded URL identifier (auto-generated)"
                        }
                    },
                    "required": ["url"]
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration


def register_jira() -> Integration:
    """Register Jira integration"""
    
    integration = Integration(
        id="jira",
        name="Jira",
        type=IntegrationType.TICKETING,
        description="Jira is a project management and issue tracking tool",
        version="1.0.0",
        auth_type=AuthType.BASIC_AUTH,
        auth_config={
            "username": "",  # User email
            "password": ""   # API token
        },
        base_url="",  # User must configure (e.g., https://company.atlassian.net)
        enabled=False,
        vendor="Atlassian",
        documentation_url="https://developer.atlassian.com/cloud/jira/platform/rest/v3/",
        tags=["ticketing", "case_management"],
        actions=[
            # Create issue
            ActionSchema(
                id="create_issue",
                name="Create Jira Issue",
                description="Create a new Jira issue/ticket",
                observable_type=ObservableType.INVESTIGATION,
                http_method="POST",
                endpoint="/rest/api/3/issue",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "project_key": {"type": "string", "description": "Project key (e.g., SEC)"},
                        "summary": {"type": "string"},
                        "description": {"type": "string"},
                        "issue_type": {"type": "string", "default": "Task"},
                        "priority": {"type": "string"}
                    },
                    "required": ["project_key", "summary"]
                }
            ),
            
            # Update issue
            ActionSchema(
                id="update_issue",
                name="Update Jira Issue",
                description="Update an existing Jira issue",
                http_method="PUT",
                endpoint="/rest/api/3/issue/{issue_key}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "issue_key": {"type": "string"},
                        "summary": {"type": "string"},
                        "description": {"type": "string"},
                        "status": {"type": "string"}
                    },
                    "required": ["issue_key"]
                }
            ),
            
            # Add comment
            ActionSchema(
                id="add_comment",
                name="Add Comment to Issue",
                description="Add a comment to a Jira issue",
                http_method="POST",
                endpoint="/rest/api/3/issue/{issue_key}/comment",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "issue_key": {"type": "string"},
                        "comment": {"type": "string"}
                    },
                    "required": ["issue_key", "comment"]
                }
            ),
            
            # Get issue
            ActionSchema(
                id="get_issue",
                name="Get Jira Issue",
                description="Get details of a Jira issue",
                http_method="GET",
                endpoint="/rest/api/3/issue/{issue_key}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "issue_key": {"type": "string"}
                    },
                    "required": ["issue_key"]
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration


def register_slack() -> Integration:
    """Register Slack integration"""
    
    integration = Integration(
        id="slack",
        name="Slack",
        type=IntegrationType.COMMUNICATION,
        description="Send messages and notifications to Slack channels",
        version="1.0.0",
        auth_type=AuthType.BEARER_TOKEN,
        auth_config={
            "token": ""  # Bot token (xoxb-...)
        },
        base_url="https://slack.com/api",
        enabled=False,
        vendor="Slack Technologies",
        documentation_url="https://api.slack.com/",
        tags=["communication", "notifications"],
        actions=[
            # Post message
            ActionSchema(
                id="post_message",
                name="Post Message",
                description="Post a message to a Slack channel",
                http_method="POST",
                endpoint="/chat.postMessage",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel ID or name"},
                        "text": {"type": "string", "description": "Message text"},
                        "blocks": {"type": "array", "description": "Rich message blocks"}
                    },
                    "required": ["channel", "text"]
                }
            ),
            
            # Post alert notification
            ActionSchema(
                id="post_alert",
                name="Post Alert Notification",
                description="Post a formatted alert notification",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/chat.postMessage",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"},
                        "alert_title": {"type": "string"},
                        "alert_severity": {"type": "string"},
                        "alert_description": {"type": "string"}
                    },
                    "required": ["channel", "alert_title"]
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration


def register_abuseipdb() -> Integration:
    """Register AbuseIPDB integration"""

    integration = Integration(
        id="abuseipdb",
        name="AbuseIPDB",
        type=IntegrationType.THREAT_INTEL,
        description="Check IP addresses against AbuseIPDB threat database",
        version="2.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "Key",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://api.abuseipdb.com/api/v2",
        enabled=False,
        vendor="AbuseIPDB",
        documentation_url="https://docs.abuseipdb.com/",
        tags=["threat_intel", "ip_reputation"],
        actions=[
            ActionSchema(
                id="check_ip",
                name="Check IP Address",
                description="Check if an IP address has been reported for abuse",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/check",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                query_params={"verbose": "true"},
                input_schema={
                    "type": "object",
                    "properties": {
                        "ipAddress": {"type": "string", "description": "IP to check"},
                        "maxAgeInDays": {"type": "integer", "default": 90}
                    },
                    "required": ["ipAddress"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_shodan() -> Integration:
    """Register Shodan integration"""

    integration = Integration(
        id="shodan",
        name="Shodan",
        type=IntegrationType.THREAT_INTEL,
        description="Search engine for Internet-connected devices - find open ports, vulnerabilities, and device info",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "key",
            "key_location": "query",
            "key_value": ""
        },
        base_url="https://api.shodan.io",
        enabled=False,
        vendor="Shodan",
        documentation_url="https://developer.shodan.io/api",
        tags=["threat_intel", "reconnaissance", "vulnerability"],
        actions=[
            ActionSchema(
                id="lookup_ip",
                name="IP Lookup",
                description="Get all available information on an IP including open ports, vulnerabilities, and services",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/shodan/host/{ip}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address to lookup"}
                    },
                    "required": ["ip"]
                }
            ),
            ActionSchema(
                id="search_domain",
                name="DNS Lookup",
                description="Get DNS records for a domain",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/dns/domain/{domain}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain to lookup"}
                    },
                    "required": ["domain"]
                }
            ),
            # New endpoints
            ActionSchema(
                id="api_info",
                name="API Info",
                description="Get API plan information and remaining query credits",
                observable_type=None,
                http_method="GET",
                endpoint="/api-info",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={"type": "object", "properties": {}}
            ),
            ActionSchema(
                id="search",
                name="Shodan Search",
                description="Search Shodan using filters like 'port:22 country:US org:Google'",
                observable_type=None,
                http_method="GET",
                endpoint="/shodan/host/search",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                query_params={"query": "{query}", "facets": "{facets}", "page": "{page}"},
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Shodan search query"},
                        "facets": {"type": "string", "description": "Comma-separated facets"},
                        "page": {"type": "integer", "description": "Page number", "default": 1}
                    },
                    "required": ["query"]
                }
            ),
            ActionSchema(
                id="search_count",
                name="Search Count",
                description="Get number of results for a query without using query credits",
                observable_type=None,
                http_method="GET",
                endpoint="/shodan/host/count",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                query_params={"query": "{query}", "facets": "{facets}"},
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Shodan search query"},
                        "facets": {"type": "string", "description": "Comma-separated facets"}
                    },
                    "required": ["query"]
                }
            ),
            ActionSchema(
                id="dns_resolve",
                name="DNS Resolve",
                description="Resolve hostnames to IP addresses",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/dns/resolve",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                query_params={"hostnames": "{hostnames}"},
                input_schema={
                    "type": "object",
                    "properties": {
                        "hostnames": {"type": "string", "description": "Comma-separated hostnames"}
                    },
                    "required": ["hostnames"]
                }
            ),
            ActionSchema(
                id="dns_reverse",
                name="Reverse DNS",
                description="Reverse DNS lookup - find hostnames for IP addresses",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/dns/reverse",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                query_params={"ips": "{ips}"},
                input_schema={
                    "type": "object",
                    "properties": {
                        "ips": {"type": "string", "description": "Comma-separated IP addresses"}
                    },
                    "required": ["ips"]
                }
            ),
            ActionSchema(
                id="protocols",
                name="List Protocols",
                description="List all protocols Shodan can filter by in searches",
                observable_type=None,
                http_method="GET",
                endpoint="/shodan/protocols",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={"type": "object", "properties": {}}
            ),
            ActionSchema(
                id="ports",
                name="List Ports",
                description="List all ports that Shodan crawls on the Internet",
                observable_type=None,
                http_method="GET",
                endpoint="/shodan/ports",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={"type": "object", "properties": {}}
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_greynoise() -> Integration:
    """Register GreyNoise integration"""

    integration = Integration(
        id="greynoise",
        name="GreyNoise",
        type=IntegrationType.THREAT_INTEL,
        description="Identify internet scanners and background noise vs targeted attacks",
        version="3.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "key",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://api.greynoise.io/v3",
        enabled=False,
        vendor="GreyNoise Intelligence",
        documentation_url="https://docs.greynoise.io/",
        tags=["threat_intel", "ip_reputation", "noise_detection"],
        actions=[
            ActionSchema(
                id="check_ip",
                name="IP Context",
                description="Get context about an IP - is it scanning the internet or targeting you specifically?",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/community/{ip}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address to check"}
                    },
                    "required": ["ip"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_urlhaus() -> Integration:
    """Register URLhaus integration"""

    integration = Integration(
        id="urlhaus",
        name="URLhaus",
        type=IntegrationType.THREAT_INTEL,
        description="Database of malicious URLs used for malware distribution (abuse.ch project). Requires free API key from abuse.ch",
        version="1.0.1",
        auth_type=AuthType.API_KEY,
        auth_config={
            "header_name": "Auth-Key",
            "header_prefix": "",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://urlhaus-api.abuse.ch/v1",
        enabled=False,  # Now requires API key
        vendor="abuse.ch",
        documentation_url="https://urlhaus-api.abuse.ch/",
        tags=["threat_intel", "malware", "url_analysis"],
        actions=[
            ActionSchema(
                id="check_url",
                name="Check URL",
                description="Check if a URL is associated with malware distribution",
                observable_type=ObservableType.URL,
                http_method="POST",
                endpoint="/url/",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                content_type="application/x-www-form-urlencoded",
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to check"}
                    },
                    "required": ["url"]
                }
            ),
            ActionSchema(
                id="check_host",
                name="Check Host",
                description="Check if a domain/IP is hosting malware",
                observable_type=ObservableType.DOMAIN,
                http_method="POST",
                endpoint="/host/",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                content_type="application/x-www-form-urlencoded",
                input_schema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Domain or IP to check"}
                    },
                    "required": ["host"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_malwarebazaar() -> Integration:
    """Register MalwareBazaar integration"""

    integration = Integration(
        id="malwarebazaar",
        name="MalwareBazaar",
        type=IntegrationType.THREAT_INTEL,
        description="Malware sample database with file hash lookups (abuse.ch project)",
        version="1.0.0",
        auth_type=AuthType.NONE,
        auth_config={},
        base_url="https://mb-api.abuse.ch/api/v1",
        enabled=True,  # Free public API - enabled by default
        vendor="abuse.ch",
        documentation_url="https://bazaar.abuse.ch/api/",
        tags=["threat_intel", "malware", "file_analysis"],
        actions=[
            ActionSchema(
                id="check_hash",
                name="Check File Hash",
                description="Check if a file hash is associated with known malware",
                observable_type=ObservableType.FILE_HASH,
                http_method="POST",
                endpoint="/",
                requires_auth=False,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=30,
                input_schema={
                    "type": "object",
                    "properties": {
                        "hash": {"type": "string", "description": "MD5, SHA1, or SHA256 hash"}
                    },
                    "required": ["hash"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration



def register_urlscan() -> Integration:
    """Register URLScan.io integration for URL and domain analysis"""

    integration = Integration(
        id="urlscan",
        name="URLScan.io",
        type=IntegrationType.THREAT_INTEL,
        description="URL and website scanner that provides detailed analysis of web pages including screenshots, DOM content, and threat detection",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "header_name": "API-Key",
            "header_prefix": "",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://urlscan.io/api/v1",
        enabled=False,
        vendor="URLScan",
        documentation_url="https://urlscan.io/docs/api/",
        tags=["threat_intel", "url_analysis", "phishing", "web_scanner"],
        actions=[
            ActionSchema(
                id="search_url",
                name="Search URL",
                description="Search for existing scans of a URL",
                observable_type=ObservableType.URL,
                http_method="GET",
                # NOTE: Use page.url:"<url>" format - quotes required for URLs with special chars
                # The URL needs to be URL-encoded AND quoted in the ElasticSearch query
                endpoint="/search/?q=page.url:\"{url_encoded}\"&size=1",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to search for (used internally, not sent to API)"},
                        "url_encoded": {"type": "string", "description": "URL-encoded version (auto-generated, substituted in endpoint)"}
                    },
                    "required": ["url"]
                },
                # Mark url as excluded from query params - it's only used to generate url_encoded
                parameters=[
                    {"name": "url", "type": "string", "in": "path"},
                    {"name": "url_encoded", "type": "string", "in": "path"}
                ]
            ),
            ActionSchema(
                id="search_domain",
                name="Search Domain",
                description="Search for scans of a domain",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/search/?q=domain:{domain}&size=5",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain to search for"}
                    },
                    "required": ["domain"]
                }
            ),
            ActionSchema(
                id="search_ip",
                name="Search IP",
                description="Search for scans associated with an IP address",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/search/?q=page.ip:{ip}&size=5",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address to search for"}
                    },
                    "required": ["ip"]
                }
            ),
            ActionSchema(
                id="submit_scan",
                name="Submit URL for Scan",
                description="Submit a URL for live scanning (requires API key)",
                observable_type=ObservableType.URL,
                http_method="POST",
                endpoint="/scan/",
                requires_auth=True,
                policy_enforced=True,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to scan"},
                        "visibility": {"type": "string", "enum": ["public", "unlisted", "private"], "default": "public"}
                    },
                    "required": ["url"]
                }
            ),
            ActionSchema(
                id="get_result",
                name="Get Scan Result",
                description="Get the result of a previous scan by UUID",
                observable_type=None,
                http_method="GET",
                endpoint="/result/{uuid}/",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "uuid": {"type": "string", "description": "Scan UUID"}
                    },
                    "required": ["uuid"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_otx() -> Integration:
    """Register AlienVault OTX integration"""

    integration = Integration(
        id="otx",
        name="AlienVault OTX",
        type=IntegrationType.THREAT_INTEL,
        description="Open Threat Exchange - community threat intelligence platform",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "X-OTX-API-KEY",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://otx.alienvault.com/api/v1",
        enabled=False,
        vendor="AT&T Cybersecurity",
        documentation_url="https://otx.alienvault.com/api",
        tags=["threat_intel", "ioc", "community"],
        actions=[
            ActionSchema(
                id="check_ip",
                name="IP Reputation",
                description="Get threat intelligence for an IP address",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/indicators/IPv4/{ip}/general",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address"}
                    },
                    "required": ["ip"]
                }
            ),
            ActionSchema(
                id="check_domain",
                name="Domain Reputation",
                description="Get threat intelligence for a domain",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/indicators/domain/{domain}/general",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain name"}
                    },
                    "required": ["domain"]
                }
            ),
            ActionSchema(
                id="check_hash",
                name="File Hash Reputation",
                description="Get threat intelligence for a file hash",
                observable_type=ObservableType.FILE_HASH,
                http_method="GET",
                endpoint="/indicators/file/{hash}/general",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=30,
                input_schema={
                    "type": "object",
                    "properties": {
                        "hash": {"type": "string", "description": "File hash (MD5, SHA1, SHA256)"}
                    },
                    "required": ["hash"]
                }
            ),
            ActionSchema(
                id="check_url",
                name="URL Reputation",
                description="Get threat intelligence for a URL",
                observable_type=ObservableType.URL,
                http_method="GET",
                endpoint="/indicators/url/{url_encoded}/general",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to check"},
                        "url_encoded": {"type": "string", "description": "URL-encoded URL"}
                    },
                    "required": ["url"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_ipinfo() -> Integration:
    """Register IPinfo integration"""

    integration = Integration(
        id="ipinfo",
        name="IPinfo",
        type=IntegrationType.ENRICHMENT,
        description="IP geolocation, ASN, and company data enrichment",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "token",       # IPinfo uses ?token=xxx
            "key_value": "",           # Will be populated from credentials vault
            "key_location": "query"    # Query parameter, not header
        },
        base_url="https://ipinfo.io",
        enabled=False,
        vendor="IPinfo",
        documentation_url="https://ipinfo.io/developers",
        tags=["enrichment", "geolocation", "asn"],
        actions=[
            ActionSchema(
                id="enrich_ip",
                name="IP Geolocation",
                description="Get geolocation, ASN, and company info for an IP",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/{ip}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=30,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address"}
                    },
                    "required": ["ip"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_crowdstrike() -> Integration:
    """Register CrowdStrike Falcon integration"""

    integration = Integration(
        id="crowdstrike",
        name="CrowdStrike Falcon",
        type=IntegrationType.EDR,
        description="Endpoint Detection and Response - query hosts, detections, and IOCs",
        version="1.0.0",
        auth_type=AuthType.OAUTH2,
        auth_config={
            "client_id": "",
            "client_secret": "",
            "token_url": "https://api.crowdstrike.com/oauth2/token"
        },
        base_url="https://api.crowdstrike.com",
        enabled=False,
        vendor="CrowdStrike",
        documentation_url="https://falcon.crowdstrike.com/documentation/",
        tags=["edr", "endpoint", "detection"],
        actions=[
            ActionSchema(
                id="search_detections",
                name="Search Detections",
                description="Search for detections by various criteria",
                http_method="GET",
                endpoint="/detects/queries/detects/v1",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filter": {"type": "string", "description": "FQL filter expression"},
                        "limit": {"type": "integer", "default": 100}
                    }
                }
            ),
            ActionSchema(
                id="get_host_info",
                name="Get Host Info",
                description="Get detailed information about a host",
                http_method="GET",
                endpoint="/devices/entities/devices/v2",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "ids": {"type": "array", "description": "Host IDs"}
                    },
                    "required": ["ids"]
                }
            ),
            ActionSchema(
                id="contain_host",
                name="Contain Host",
                description="Network contain a compromised host",
                http_method="POST",
                endpoint="/devices/entities/devices-actions/v2",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "action_name": {"type": "string", "enum": ["contain", "lift_containment"]},
                        "ids": {"type": "array", "description": "Host IDs to contain"}
                    },
                    "required": ["action_name", "ids"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_microsoft_defender() -> Integration:
    """Register Microsoft Defender for Endpoint integration"""

    integration = Integration(
        id="microsoft_defender",
        name="Microsoft Defender",
        type=IntegrationType.EDR,
        description="Microsoft Defender for Endpoint - query alerts, machines, and take response actions",
        version="1.0.0",
        auth_type=AuthType.OAUTH2,
        auth_config={
            "client_id": "",
            "client_secret": "",
            "tenant_id": "",
            "token_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        },
        base_url="https://api.securitycenter.microsoft.com/api",
        enabled=False,
        vendor="Microsoft",
        documentation_url="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/",
        tags=["edr", "endpoint", "microsoft"],
        actions=[
            ActionSchema(
                id="list_alerts",
                name="List Alerts",
                description="Get security alerts from Defender",
                http_method="GET",
                endpoint="/alerts",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "$filter": {"type": "string", "description": "OData filter"},
                        "$top": {"type": "integer", "default": 100}
                    }
                }
            ),
            ActionSchema(
                id="get_machine",
                name="Get Machine Info",
                description="Get information about a machine",
                http_method="GET",
                endpoint="/machines/{machine_id}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "machine_id": {"type": "string", "description": "Machine ID"}
                    },
                    "required": ["machine_id"]
                }
            ),
            ActionSchema(
                id="isolate_machine",
                name="Isolate Machine",
                description="Isolate a machine from the network",
                http_method="POST",
                endpoint="/machines/{machine_id}/isolate",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "machine_id": {"type": "string"},
                        "comment": {"type": "string"},
                        "isolationType": {"type": "string", "enum": ["Full", "Selective"]}
                    },
                    "required": ["machine_id", "comment"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_sentinel_one() -> Integration:
    """Register SentinelOne integration"""

    integration = Integration(
        id="sentinelone",
        name="SentinelOne",
        type=IntegrationType.EDR,
        description="SentinelOne EDR - autonomous endpoint protection and response",
        version="2.1.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "Authorization",
            "key_location": "header",
            "key_prefix": "ApiToken ",
            "key_value": ""
        },
        base_url="",  # User must configure their console URL
        enabled=False,
        vendor="SentinelOne",
        documentation_url="https://usea1-partners.sentinelone.net/api-doc/overview",
        tags=["edr", "endpoint", "autonomous"],
        actions=[
            ActionSchema(
                id="get_threats",
                name="Get Threats",
                description="Query threats detected by SentinelOne",
                http_method="GET",
                endpoint="/web/api/v2.1/threats",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 100},
                        "resolved": {"type": "boolean"}
                    }
                }
            ),
            ActionSchema(
                id="get_agents",
                name="Get Agents",
                description="Query endpoint agents",
                http_method="GET",
                endpoint="/web/api/v2.1/agents",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 100},
                        "computerName__contains": {"type": "string"}
                    }
                }
            ),
            ActionSchema(
                id="disconnect_agent",
                name="Disconnect Agent",
                description="Network disconnect an endpoint",
                http_method="POST",
                endpoint="/web/api/v2.1/agents/actions/disconnect",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filter": {"type": "object", "description": "Agent filter"},
                        "data": {"type": "object"}
                    }
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_splunk() -> Integration:
    """Register Splunk integration"""

    integration = Integration(
        id="splunk",
        name="Splunk",
        type=IntegrationType.SIEM,
        description="Splunk SIEM - search logs, run saved searches, and send events",
        version="1.0.0",
        auth_type=AuthType.BEARER_TOKEN,
        auth_config={
            "token": ""  # Splunk auth token
        },
        base_url="",  # User must configure (e.g., https://splunk.company.com:8089)
        enabled=False,
        vendor="Splunk",
        documentation_url="https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog",
        tags=["siem", "logging", "search"],
        actions=[
            ActionSchema(
                id="search",
                name="Run Search",
                description="Run a Splunk search query",
                http_method="POST",
                endpoint="/services/search/jobs",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "search": {"type": "string", "description": "SPL search query"},
                        "earliest_time": {"type": "string", "default": "-24h"},
                        "latest_time": {"type": "string", "default": "now"}
                    },
                    "required": ["search"]
                }
            ),
            ActionSchema(
                id="send_event",
                name="Send Event to HEC",
                description="Send an event to Splunk via HTTP Event Collector",
                http_method="POST",
                endpoint="/services/collector/event",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "event": {"type": "object", "description": "Event data"},
                        "index": {"type": "string"},
                        "source": {"type": "string"},
                        "sourcetype": {"type": "string"}
                    },
                    "required": ["event"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_elastic_security() -> Integration:
    """Register Elastic Security integration"""

    integration = Integration(
        id="elastic_security",
        name="Elastic Security",
        type=IntegrationType.SIEM,
        description="Elastic Security (SIEM) - search logs, query detections, and manage cases",
        version="8.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "Authorization",
            "key_location": "header",
            "key_prefix": "ApiKey ",
            "key_value": ""
        },
        base_url="",  # User must configure
        enabled=False,
        vendor="Elastic",
        documentation_url="https://www.elastic.co/guide/en/security/current/api-overview.html",
        tags=["siem", "logging", "elastic"],
        actions=[
            ActionSchema(
                id="search",
                name="Search Events",
                description="Search security events in Elasticsearch",
                http_method="POST",
                endpoint="/.logs-*/_search",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "object", "description": "Elasticsearch query DSL"},
                        "size": {"type": "integer", "default": 100}
                    },
                    "required": ["query"]
                }
            ),
            ActionSchema(
                id="get_alerts",
                name="Get Security Alerts",
                description="Get alerts from Elastic Security",
                http_method="POST",
                endpoint="/api/detection_engine/signals/search",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "object"},
                        "size": {"type": "integer", "default": 100}
                    }
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_have_i_been_pwned() -> Integration:
    """Register Have I Been Pwned integration"""

    integration = Integration(
        id="hibp",
        name="Have I Been Pwned",
        type=IntegrationType.THREAT_INTEL,
        description="Check if email addresses or domains have been in data breaches",
        version="3.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "hibp-api-key",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://haveibeenpwned.com/api/v3",
        enabled=False,
        vendor="Have I Been Pwned",
        documentation_url="https://haveibeenpwned.com/API/v3",
        tags=["threat_intel", "breach", "email"],
        actions=[
            ActionSchema(
                id="check_email",
                name="Check Email Breaches",
                description="Check if an email has been in known data breaches",
                observable_type=ObservableType.EMAIL,
                http_method="GET",
                endpoint="/breachedaccount/{email}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "description": "Email address to check"}
                    },
                    "required": ["email"]
                }
            ),
            ActionSchema(
                id="check_domain",
                name="Check Domain Breaches",
                description="Check if a domain has been in known data breaches",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/breaches?domain={domain}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain to check"}
                    },
                    "required": ["domain"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_pagerduty() -> Integration:
    """Register PagerDuty integration"""

    integration = Integration(
        id="pagerduty",
        name="PagerDuty",
        type=IntegrationType.COMMUNICATION,
        description="Incident management and alerting platform",
        version="2.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "Authorization",
            "key_location": "header",
            "key_prefix": "Token token=",
            "key_value": ""
        },
        base_url="https://api.pagerduty.com",
        enabled=False,
        vendor="PagerDuty",
        documentation_url="https://developer.pagerduty.com/api-reference/",
        tags=["communication", "incident", "alerting"],
        actions=[
            ActionSchema(
                id="create_incident",
                name="Create Incident",
                description="Create a new PagerDuty incident",
                http_method="POST",
                endpoint="/incidents",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "service_id": {"type": "string"},
                        "urgency": {"type": "string", "enum": ["high", "low"]},
                        "body": {"type": "string"}
                    },
                    "required": ["title", "service_id"]
                }
            ),
            ActionSchema(
                id="trigger_event",
                name="Trigger Event",
                description="Trigger an event via Events API v2",
                http_method="POST",
                endpoint="https://events.pagerduty.com/v2/enqueue",
                requires_auth=False,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "routing_key": {"type": "string", "description": "Integration key"},
                        "event_action": {"type": "string", "enum": ["trigger", "acknowledge", "resolve"]},
                        "payload": {"type": "object"}
                    },
                    "required": ["routing_key", "event_action", "payload"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_servicenow() -> Integration:
    """Register ServiceNow integration"""

    integration = Integration(
        id="servicenow",
        name="ServiceNow",
        type=IntegrationType.TICKETING,
        description="IT service management and security incident response",
        version="1.0.0",
        auth_type=AuthType.BASIC_AUTH,
        auth_config={
            "username": "",
            "password": ""
        },
        base_url="",  # User must configure (e.g., https://instance.service-now.com)
        enabled=False,
        vendor="ServiceNow",
        documentation_url="https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/",
        tags=["ticketing", "itsm", "incident"],
        actions=[
            ActionSchema(
                id="create_incident",
                name="Create Incident",
                description="Create a new ServiceNow incident",
                http_method="POST",
                endpoint="/api/now/table/incident",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "short_description": {"type": "string"},
                        "description": {"type": "string"},
                        "urgency": {"type": "integer"},
                        "impact": {"type": "integer"},
                        "category": {"type": "string"}
                    },
                    "required": ["short_description"]
                }
            ),
            ActionSchema(
                id="create_security_incident",
                name="Create Security Incident",
                description="Create a security incident in ServiceNow SecOps",
                http_method="POST",
                endpoint="/api/now/table/sn_si_incident",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "short_description": {"type": "string"},
                        "description": {"type": "string"},
                        "priority": {"type": "integer"},
                        "category": {"type": "string"}
                    },
                    "required": ["short_description"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_microsoft_teams() -> Integration:
    """Register Microsoft Teams integration"""

    integration = Integration(
        id="microsoft_teams",
        name="Microsoft Teams",
        type=IntegrationType.COMMUNICATION,
        description="Send alerts and notifications to Microsoft Teams channels",
        version="1.0.0",
        auth_type=AuthType.NONE,  # Uses webhook URLs
        auth_config={
            "webhook_url": ""  # Incoming webhook URL
        },
        base_url="",  # Webhook URL configured per channel
        enabled=False,
        vendor="Microsoft",
        documentation_url="https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/",
        tags=["communication", "notifications", "microsoft"],
        actions=[
            ActionSchema(
                id="send_message",
                name="Send Message",
                description="Send a message to a Teams channel via webhook",
                http_method="POST",
                endpoint="",  # Uses configured webhook URL
                requires_auth=False,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Message text"},
                        "title": {"type": "string"},
                        "themeColor": {"type": "string", "description": "Hex color for card"}
                    },
                    "required": ["text"]
                }
            ),
            ActionSchema(
                id="send_alert_card",
                name="Send Alert Card",
                description="Send a formatted alert card to Teams",
                http_method="POST",
                endpoint="",
                requires_auth=False,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_title": {"type": "string"},
                        "alert_severity": {"type": "string"},
                        "alert_description": {"type": "string"},
                        "investigation_link": {"type": "string"}
                    },
                    "required": ["alert_title"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_datadog() -> Integration:
    """Register Datadog integration - Cloud monitoring and security"""

    integration = Integration(
        id="datadog",
        name="Datadog",
        type=IntegrationType.SIEM,
        description="Cloud monitoring, security monitoring, and log management platform",
        version="2.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "DD-API-KEY",
            "key_location": "header",
            "key_value": "",
            "extra_headers": {
                "DD-APPLICATION-KEY": ""  # Application key for most endpoints
            }
        },
        base_url="https://api.datadoghq.com",  # Can be changed for EU (api.datadoghq.eu)
        enabled=False,
        vendor="Datadog",
        documentation_url="https://docs.datadoghq.com/api/latest/",
        tags=["siem", "monitoring", "cloud_security", "logs"],
        actions=[
            # Security Monitoring - Get Signals
            ActionSchema(
                id="get_security_signals",
                name="Get Security Signals",
                description="Get security signals (alerts) from Datadog Security Monitoring",
                http_method="POST",
                endpoint="/api/v2/security_monitoring/signals/search",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filter": {
                            "type": "object",
                            "properties": {
                                "from": {"type": "string", "description": "Start time (ISO8601)"},
                                "to": {"type": "string", "description": "End time (ISO8601)"},
                                "query": {"type": "string", "description": "Filter query"}
                            }
                        },
                        "page": {
                            "type": "object",
                            "properties": {
                                "limit": {"type": "integer", "default": 100}
                            }
                        }
                    }
                }
            ),
            # Security Monitoring Rules
            ActionSchema(
                id="list_security_rules",
                name="List Security Rules",
                description="List all security monitoring rules",
                http_method="GET",
                endpoint="/api/v2/security_monitoring/rules",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "page[size]": {"type": "integer", "default": 100}
                    }
                }
            ),
            # Logs Search
            ActionSchema(
                id="search_logs",
                name="Search Logs",
                description="Search and filter logs in Datadog",
                http_method="POST",
                endpoint="/api/v2/logs/events/search",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filter": {
                            "type": "object",
                            "properties": {
                                "from": {"type": "string"},
                                "to": {"type": "string"},
                                "query": {"type": "string", "description": "Datadog query syntax"}
                            }
                        },
                        "page": {
                            "type": "object",
                            "properties": {
                                "limit": {"type": "integer", "default": 100}
                            }
                        }
                    },
                    "required": ["filter"]
                }
            ),
            # Cloud Security Management - Findings
            ActionSchema(
                id="get_csm_findings",
                name="Get CSM Findings",
                description="Get Cloud Security Management findings (misconfigurations)",
                http_method="GET",
                endpoint="/api/v2/posture_management/findings",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "page[limit]": {"type": "integer", "default": 100},
                        "filter[status]": {"type": "string", "enum": ["critical", "high", "medium", "low"]}
                    }
                }
            ),
            # Incidents
            ActionSchema(
                id="get_incidents",
                name="Get Incidents",
                description="List incidents from Datadog Incident Management",
                http_method="GET",
                endpoint="/api/v2/incidents",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "page[size]": {"type": "integer", "default": 100},
                        "include": {"type": "string", "default": "users"}
                    }
                }
            ),
            # Host Info
            ActionSchema(
                id="get_host_info",
                name="Get Host Info",
                description="Get information about monitored hosts",
                http_method="GET",
                endpoint="/api/v1/hosts",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filter": {"type": "string", "description": "Host name filter"},
                        "count": {"type": "integer", "default": 100}
                    }
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_microsoft_graph_security() -> Integration:
    """Register Microsoft Graph Security API integration"""

    integration = Integration(
        id="microsoft_graph_security",
        name="Microsoft Graph Security",
        type=IntegrationType.SIEM,
        description="Microsoft Graph Security API - unified security alerts, threat intelligence, and secure score",
        version="1.0.0",
        auth_type=AuthType.OAUTH2,
        auth_config={
            "client_id": "",
            "client_secret": "",
            "tenant_id": "",
            "token_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            "scope": "https://graph.microsoft.com/.default"
        },
        base_url="https://graph.microsoft.com/v1.0",
        enabled=False,
        vendor="Microsoft",
        documentation_url="https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview",
        tags=["siem", "security", "microsoft", "azure"],
        actions=[
            # Security Alerts
            ActionSchema(
                id="list_alerts",
                name="List Security Alerts",
                description="Get security alerts from Microsoft 365 Defender, Azure Defender, and other Microsoft security products",
                http_method="GET",
                endpoint="/security/alerts_v2",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "$filter": {"type": "string", "description": "OData filter"},
                        "$top": {"type": "integer", "default": 100},
                        "$orderby": {"type": "string", "default": "createdDateTime desc"}
                    }
                }
            ),
            # Get Alert Details
            ActionSchema(
                id="get_alert",
                name="Get Alert Details",
                description="Get detailed information about a security alert",
                http_method="GET",
                endpoint="/security/alerts_v2/{alert_id}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_id": {"type": "string", "description": "Alert ID"}
                    },
                    "required": ["alert_id"]
                }
            ),
            # Update Alert
            ActionSchema(
                id="update_alert",
                name="Update Alert",
                description="Update alert status, comments, or assigned user",
                http_method="PATCH",
                endpoint="/security/alerts_v2/{alert_id}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_id": {"type": "string"},
                        "status": {"type": "string", "enum": ["new", "inProgress", "resolved"]},
                        "classification": {"type": "string", "enum": ["unknown", "falsePositive", "truePositive"]},
                        "assignedTo": {"type": "string"}
                    },
                    "required": ["alert_id"]
                }
            ),
            # Secure Score
            ActionSchema(
                id="get_secure_score",
                name="Get Secure Score",
                description="Get the organization's Microsoft Secure Score",
                http_method="GET",
                endpoint="/security/secureScores",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "$top": {"type": "integer", "default": 1}
                    }
                }
            ),
            # Users - for identity enrichment
            ActionSchema(
                id="get_user",
                name="Get User Details",
                description="Get details about a user for identity enrichment",
                observable_type=ObservableType.EMAIL,
                http_method="GET",
                endpoint="/users/{user_principal_name}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "user_principal_name": {"type": "string", "description": "UPN or email address"}
                    },
                    "required": ["user_principal_name"]
                }
            ),
            # Sign-in logs
            ActionSchema(
                id="get_sign_ins",
                name="Get Sign-in Logs",
                description="Get Azure AD sign-in logs for a user",
                http_method="GET",
                endpoint="/auditLogs/signIns",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "$filter": {"type": "string", "description": "OData filter (e.g., userPrincipalName eq 'user@domain.com')"},
                        "$top": {"type": "integer", "default": 50}
                    }
                }
            ),
            # Threat Intelligence Indicators
            ActionSchema(
                id="list_ti_indicators",
                name="List Threat Indicators",
                description="List threat intelligence indicators",
                http_method="GET",
                endpoint="/security/tiIndicators",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "$filter": {"type": "string"},
                        "$top": {"type": "integer", "default": 100}
                    }
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_cisco_meraki() -> Integration:
    """Register Cisco Meraki integration for network security"""

    integration = Integration(
        id="cisco_meraki",
        name="Cisco Meraki",
        type=IntegrationType.NETWORK,
        description="Cisco Meraki cloud-managed network - security events, device management, and network visibility",
        version="1.65.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "X-Cisco-Meraki-API-Key",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://api.meraki.com/api/v1",
        enabled=False,
        vendor="Cisco",
        documentation_url="https://developer.cisco.com/meraki/api-latest/",
        tags=["network", "security", "cisco", "firewall"],
        actions=[
            # Get Security Events
            ActionSchema(
                id="get_security_events",
                name="Get Security Events",
                description="Get security events from Meraki MX appliances",
                http_method="GET",
                endpoint="/organizations/{organization_id}/appliance/security/events",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"},
                        "t0": {"type": "string", "description": "Start time (ISO8601)"},
                        "t1": {"type": "string", "description": "End time (ISO8601)"},
                        "perPage": {"type": "integer", "default": 100}
                    },
                    "required": ["organization_id"]
                }
            ),
            # Get IDS/IPS Alerts
            ActionSchema(
                id="get_intrusion_settings",
                name="Get Intrusion Settings",
                description="Get intrusion detection/prevention settings",
                http_method="GET",
                endpoint="/networks/{network_id}/appliance/security/intrusion",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "network_id": {"type": "string"}
                    },
                    "required": ["network_id"]
                }
            ),
            # List Devices
            ActionSchema(
                id="list_devices",
                name="List Network Devices",
                description="List all devices in the organization",
                http_method="GET",
                endpoint="/organizations/{organization_id}/devices",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"},
                        "perPage": {"type": "integer", "default": 100}
                    },
                    "required": ["organization_id"]
                }
            ),
            # Get Client Info
            ActionSchema(
                id="get_client",
                name="Get Client Info",
                description="Get information about a network client",
                http_method="GET",
                endpoint="/networks/{network_id}/clients/{client_id}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "network_id": {"type": "string"},
                        "client_id": {"type": "string"}
                    },
                    "required": ["network_id", "client_id"]
                }
            ),
            # Content Filtering - Blocked URLs
            ActionSchema(
                id="get_content_filtering",
                name="Get Content Filtering",
                description="Get content filtering settings including blocked URLs",
                http_method="GET",
                endpoint="/networks/{network_id}/appliance/contentFiltering",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "network_id": {"type": "string"}
                    },
                    "required": ["network_id"]
                }
            ),
            # VPN Status
            ActionSchema(
                id="get_vpn_status",
                name="Get VPN Status",
                description="Get VPN status for the organization",
                http_method="GET",
                endpoint="/organizations/{organization_id}/appliance/vpn/statuses",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"}
                    },
                    "required": ["organization_id"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_rapid7_insightvm() -> Integration:
    """Register Rapid7 InsightVM/Nexpose integration for vulnerability management"""

    integration = Integration(
        id="rapid7_insightvm",
        name="Rapid7 InsightVM",
        type=IntegrationType.VULNERABILITY,
        description="Vulnerability management - scan assets, track vulnerabilities, and prioritize remediation",
        version="3.0.0",
        auth_type=AuthType.BASIC_AUTH,
        auth_config={
            "username": "",
            "password": ""
        },
        base_url="",  # User must configure (e.g., https://insightvm.company.com:3780/api/3)
        enabled=False,
        vendor="Rapid7",
        documentation_url="https://help.rapid7.com/insightvm/en-us/api/index.html",
        tags=["vulnerability", "scanning", "remediation"],
        actions=[
            ActionSchema(
                id="get_asset",
                name="Get Asset Details",
                description="Get detailed information about an asset including vulnerabilities",
                http_method="GET",
                endpoint="/assets/{asset_id}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "asset_id": {"type": "integer"}
                    },
                    "required": ["asset_id"]
                }
            ),
            ActionSchema(
                id="search_assets",
                name="Search Assets",
                description="Search for assets by IP, hostname, or other criteria",
                observable_type=ObservableType.IP,
                http_method="POST",
                endpoint="/assets/search",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filters": {
                            "type": "array",
                            "description": "Search filters"
                        },
                        "match": {"type": "string", "enum": ["all", "any"], "default": "all"}
                    }
                }
            ),
            ActionSchema(
                id="get_vulnerabilities",
                name="Get Asset Vulnerabilities",
                description="Get vulnerabilities for a specific asset",
                http_method="GET",
                endpoint="/assets/{asset_id}/vulnerabilities",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "asset_id": {"type": "integer"},
                        "page": {"type": "integer", "default": 0},
                        "size": {"type": "integer", "default": 100}
                    },
                    "required": ["asset_id"]
                }
            ),
            ActionSchema(
                id="get_vulnerability_details",
                name="Get Vulnerability Details",
                description="Get detailed information about a specific vulnerability",
                http_method="GET",
                endpoint="/vulnerabilities/{vulnerability_id}",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=30,
                input_schema={
                    "type": "object",
                    "properties": {
                        "vulnerability_id": {"type": "string", "description": "CVE or vulnerability ID"}
                    },
                    "required": ["vulnerability_id"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_tenable() -> Integration:
    """Register Tenable.io/Nessus integration for vulnerability management"""

    integration = Integration(
        id="tenable",
        name="Tenable.io",
        type=IntegrationType.VULNERABILITY,
        description="Vulnerability management and exposure assessment",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "X-ApiKeys",
            "key_location": "header",
            "key_value": ""  # Format: accessKey=XXX; secretKey=YYY
        },
        base_url="https://cloud.tenable.com",
        enabled=False,
        vendor="Tenable",
        documentation_url="https://developer.tenable.com/reference/navigate",
        tags=["vulnerability", "scanning", "exposure"],
        actions=[
            ActionSchema(
                id="list_assets",
                name="List Assets",
                description="List all assets in Tenable.io",
                http_method="GET",
                endpoint="/assets",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {}
                }
            ),
            ActionSchema(
                id="get_asset_vulns",
                name="Get Asset Vulnerabilities",
                description="Get vulnerabilities for a specific asset",
                http_method="GET",
                endpoint="/workbenches/assets/{asset_id}/vulnerabilities",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "asset_id": {"type": "string"}
                    },
                    "required": ["asset_id"]
                }
            ),
            ActionSchema(
                id="export_vulns",
                name="Export Vulnerabilities",
                description="Export vulnerability data for analysis",
                http_method="POST",
                endpoint="/vulns/export",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "filters": {"type": "object"},
                        "num_assets": {"type": "integer", "default": 500}
                    }
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_okta() -> Integration:
    """Register Okta integration for identity and access management"""

    integration = Integration(
        id="okta",
        name="Okta",
        type=IntegrationType.IDENTITY,
        description="Identity and access management - user lookup, authentication logs, and security events",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "Authorization",
            "key_location": "header",
            "key_prefix": "SSWS ",
            "key_value": ""
        },
        base_url="",  # User must configure (e.g., https://company.okta.com)
        enabled=False,
        vendor="Okta",
        documentation_url="https://developer.okta.com/docs/reference/",
        tags=["identity", "iam", "sso", "authentication"],
        actions=[
            ActionSchema(
                id="get_user",
                name="Get User",
                description="Get user details by ID or email",
                observable_type=ObservableType.EMAIL,
                http_method="GET",
                endpoint="/api/v1/users/{user_id}",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string", "description": "User ID or email"}
                    },
                    "required": ["user_id"]
                }
            ),
            ActionSchema(
                id="list_user_factors",
                name="List User MFA Factors",
                description="List enrolled MFA factors for a user",
                http_method="GET",
                endpoint="/api/v1/users/{user_id}/factors",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"}
                    },
                    "required": ["user_id"]
                }
            ),
            ActionSchema(
                id="get_system_logs",
                name="Get System Logs",
                description="Get Okta system/audit logs",
                http_method="GET",
                endpoint="/api/v1/logs",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "since": {"type": "string", "description": "Start time (ISO8601)"},
                        "until": {"type": "string", "description": "End time (ISO8601)"},
                        "filter": {"type": "string", "description": "SCIM filter expression"},
                        "limit": {"type": "integer", "default": 100}
                    }
                }
            ),
            ActionSchema(
                id="suspend_user",
                name="Suspend User",
                description="Suspend a user account (response action)",
                http_method="POST",
                endpoint="/api/v1/users/{user_id}/lifecycle/suspend",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"}
                    },
                    "required": ["user_id"]
                }
            ),
            ActionSchema(
                id="clear_user_sessions",
                name="Clear User Sessions",
                description="Clear all active sessions for a user",
                http_method="DELETE",
                endpoint="/api/v1/users/{user_id}/sessions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"}
                    },
                    "required": ["user_id"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_hybrid_analysis() -> Integration:
    """Register Hybrid Analysis integration for malware sandboxing"""

    integration = Integration(
        id="hybrid_analysis",
        name="Hybrid Analysis",
        type=IntegrationType.SANDBOX,
        description="Free malware analysis sandbox - submit files and URLs for dynamic analysis and get detailed behavioral reports",
        version="2.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "api-key",
            "key_location": "header",
            "key_value": ""
        },
        base_url="https://hybrid-analysis.com/api/v2",
        enabled=False,
        vendor="CrowdStrike (Hybrid Analysis)",
        documentation_url="https://www.hybrid-analysis.com/docs/api/v2",
        tags=["sandbox", "malware", "file_analysis", "dynamic_analysis"],
        actions=[
            # Submit file for analysis
            ActionSchema(
                id="submit_file",
                name="Submit File for Analysis",
                description="Submit a file to the Hybrid Analysis sandbox for dynamic analysis",
                observable_type=ObservableType.FILE_HASH,
                http_method="POST",
                endpoint="/submit/file",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                read_only=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "format": "binary", "description": "File to analyze"},
                        "environment_id": {
                            "type": "integer",
                            "description": "Sandbox environment: 300=Linux, 100=Windows 7 32-bit, 110=Windows 7 64-bit, 120=Windows 10 64-bit",
                            "default": 120,
                            "enum": [100, 110, 120, 200, 300]
                        },
                        "no_share_third_party": {"type": "boolean", "default": False},
                        "allow_community_access": {"type": "boolean", "default": True},
                        "comment": {"type": "string", "description": "Comment for the submission"}
                    },
                    "required": ["file", "environment_id"]
                }
            ),
            # Submit URL for analysis - NOTE: This is a submission action, NOT a lookup
            # Set observable_type=None to prevent it from being used for enrichment
            # (enrichment should be read-only, this submits URLs for sandbox analysis)
            ActionSchema(
                id="submit_url",
                name="Submit URL for Analysis",
                description="Submit a URL to be analyzed in the sandbox (not for enrichment - triggers analysis)",
                observable_type=None,  # Don't use for enrichment - this submits, not looks up
                http_method="POST",
                endpoint="/submit/url-for-analysis",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                read_only=False,
                action_type="respond",  # Response action, not investigate/enrich
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to analyze"},
                        "environment_id": {
                            "type": "integer",
                            "description": "Sandbox environment",
                            "default": 120
                        },
                        "no_share_third_party": {"type": "boolean", "default": False}
                    },
                    "required": ["url", "environment_id"]
                }
            ),
            # Get analysis report by hash
            ActionSchema(
                id="get_report",
                name="Get Analysis Report",
                description="Get the analysis report for a file by its SHA256 hash",
                observable_type=ObservableType.FILE_HASH,
                http_method="GET",
                endpoint="/search/hash",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "hash": {"type": "string", "description": "SHA256, SHA1, or MD5 hash of the file"}
                    },
                    "required": ["hash"]
                }
            ),
            # Get summary report
            ActionSchema(
                id="get_summary",
                name="Get Report Summary",
                description="Get a summary of the analysis for a specific submission",
                http_method="GET",
                endpoint="/report/{id}/summary",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Job ID or SHA256 hash"}
                    },
                    "required": ["id"]
                }
            ),
            # Get job state (check if analysis is complete)
            ActionSchema(
                id="get_job_state",
                name="Get Job State",
                description="Check the status of an analysis job",
                http_method="GET",
                endpoint="/report/{id}/state",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Job ID"}
                    },
                    "required": ["id"]
                }
            ),
            # Quick scan (hash lookup without submission)
            ActionSchema(
                id="quick_scan",
                name="Quick Scan",
                description="Check if a file has been previously analyzed without submitting",
                observable_type=ObservableType.FILE_HASH,
                http_method="POST",
                endpoint="/quick-scan/file",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "hash": {"type": "string", "description": "SHA256 hash of the file"},
                        "scan_type": {"type": "string", "enum": ["all", "lookup"], "default": "lookup"}
                    },
                    "required": ["hash"]
                }
            ),
            # Get dropped files
            ActionSchema(
                id="get_dropped_files",
                name="Get Dropped Files",
                description="Get list of files dropped during sandbox analysis",
                http_method="GET",
                endpoint="/report/{id}/dropped-files",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Job ID"}
                    },
                    "required": ["id"]
                }
            ),
            # Get extracted strings/IOCs
            ActionSchema(
                id="get_extracted_strings",
                name="Get Extracted Strings",
                description="Get extracted strings and network indicators from analysis",
                http_method="GET",
                endpoint="/report/{id}/extracted-strings",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Job ID"}
                    },
                    "required": ["id"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_qualys() -> Integration:
    """Register Qualys integration for vulnerability management"""

    integration = Integration(
        id="qualys",
        name="Qualys",
        type=IntegrationType.VULNERABILITY,
        description="Cloud security and compliance platform - vulnerability management, policy compliance",
        version="2.0.0",
        auth_type=AuthType.BASIC_AUTH,
        auth_config={
            "username": "",
            "password": ""
        },
        base_url="https://qualysapi.qualys.com",  # Platform-specific URL
        enabled=False,
        vendor="Qualys",
        documentation_url="https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf",
        tags=["vulnerability", "compliance", "scanning"],
        actions=[
            ActionSchema(
                id="get_host_detection",
                name="Get Host Detections",
                description="Get vulnerability detections for hosts",
                http_method="POST",
                endpoint="/api/2.0/fo/asset/host/vm/detection/",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "default": "list"},
                        "ips": {"type": "string", "description": "IP range or list"},
                        "show_igs": {"type": "integer", "default": 1}
                    }
                }
            ),
            ActionSchema(
                id="search_assets",
                name="Search Assets",
                description="Search for assets by various criteria",
                observable_type=ObservableType.IP,
                http_method="POST",
                endpoint="/api/2.0/fo/asset/host/",
                requires_auth=True,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "default": "list"},
                        "ips": {"type": "string"},
                        "details": {"type": "string", "default": "All"}
                    }
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_rdap_arin() -> Integration:
    """Register ARIN RDAP integration for IP registration data"""

    integration = Integration(
        id="rdap_arin",
        name="ARIN RDAP",
        type=IntegrationType.ENRICHMENT,
        description="ARIN RDAP (Registration Data Access Protocol) - Get detailed IP registration, network range, organization, and abuse contact information",
        version="1.0.0",
        auth_type=AuthType.NONE,
        auth_config={},
        base_url="https://rdap.arin.net/registry",
        enabled=True,  # Free, no auth required
        vendor="ARIN",
        documentation_url="https://www.arin.net/resources/registry/whois/rdap/",
        tags=["enrichment", "whois", "rdap", "registration", "network"],
        actions=[
            ActionSchema(
                id="enrich_ip",
                name="IP Registration Data",
                description="Get RDAP registration data for an IP (network range, org, abuse contacts)",
                observable_type=ObservableType.IP,
                http_method="GET",
                endpoint="/ip/{ip}",
                requires_auth=False,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,  # Registration data is fairly stable
                input_schema={
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address"}
                    },
                    "required": ["ip"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


def register_rdap_verisign() -> Integration:
    """Register Verisign RDAP integration for domain registration data"""

    integration = Integration(
        id="rdap_verisign",
        name="Verisign RDAP",
        type=IntegrationType.ENRICHMENT,
        description="Verisign RDAP - Get detailed domain registration data for .com/.net domains",
        version="1.0.0",
        auth_type=AuthType.NONE,
        auth_config={},
        base_url="https://rdap.verisign.com/com/v1",
        enabled=True,  # Free, no auth required
        vendor="Verisign",
        documentation_url="https://www.verisign.com/en_US/channel-resources/domain-registry-products/rdap/index.xhtml",
        tags=["enrichment", "whois", "rdap", "registration", "domain"],
        actions=[
            ActionSchema(
                id="enrich_domain",
                name="Domain Registration Data",
                description="Get RDAP registration data for a .com/.net domain",
                observable_type=ObservableType.DOMAIN,
                http_method="GET",
                endpoint="/domain/{domain}",
                requires_auth=False,
                policy_enforced=True,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain name"}
                    },
                    "required": ["domain"]
                }
            )
        ]
    )

    registry = get_registry()
    registry.register(integration)
    return integration


_initialized = False

def initialize_integrations():
    """Initialize all pre-built integrations"""
    global _initialized
    if _initialized:
        return
    _initialized = True

    # Threat Intelligence
    register_virustotal()
    register_abuseipdb()
    register_shodan()
    register_greynoise()
    register_urlhaus()
    register_malwarebazaar()
    register_urlscan()
    register_otx()
    register_have_i_been_pwned()

    # Enrichment
    register_ipinfo()
    register_rdap_arin()
    register_rdap_verisign()

    # Sandbox
    register_hybrid_analysis()

    # EDR / Endpoint
    register_crowdstrike()
    register_microsoft_defender()
    register_sentinel_one()

    # SIEM / Security Monitoring
    register_splunk()
    register_elastic_security()
    register_datadog()
    register_microsoft_graph_security()

    # Network Security
    register_cisco_meraki()

    # Vulnerability Management
    register_rapid7_insightvm()
    register_tenable()
    register_qualys()

    # Identity & Access Management
    register_okta()

    # Ticketing
    register_jira()
    register_servicenow()

    # Communication
    register_slack()
    register_pagerduty()
    register_microsoft_teams()

    # AI Providers
    from integrations.connectors.ai_providers.openai import register_openai
    from integrations.connectors.ai_providers.gemini import register_gemini
    from integrations.connectors.ai_providers.ollama import register_ollama
    from integrations.connectors.ai_providers.lmstudio import register_lmstudio
    from integrations.connectors.ai_providers.azure_openai import register_azure_openai

    register_openai()
    register_gemini()
    register_ollama()
    register_lmstudio()
    register_azure_openai()

    print("[OK] Initialized 35 pre-built integrations (30 security + 5 AI providers)")
