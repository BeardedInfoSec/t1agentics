# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Asset Investigation Enrichment Service
Phase 9.4: Integrates CMDB assets with investigations and AI agents

Provides:
- Automatic asset lookup from alert IPs/hostnames
- Criticality-based priority boosting
- Asset context for AI agent analysis
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


# IP address regex pattern
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Hostname pattern (simplified)
HOSTNAME_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)


# Priority boost mapping based on asset criticality
CRITICALITY_PRIORITY_BOOST = {
    'tier1': 2,   # Critical assets get +2 priority boost (e.g., P3 -> P1)
    'tier2': 1,   # High importance assets get +1 boost (e.g., P3 -> P2)
    'tier3': 0,   # Standard assets - no change
    'tier4': 0,   # Low importance - no change
}


class AssetInvestigationEnrichment:
    """
    Enriches investigations with asset context from CMDB.
    Used during investigation creation and agent analysis.
    """

    def __init__(self):
        self.db = None
        self.asset_service = None

    def set_db(self, db):
        """Set the database connection"""
        self.db = db

    def set_asset_service(self, asset_service):
        """Set the asset service"""
        self.asset_service = asset_service

    def extract_indicators(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract IPs and hostnames from alert/event data.

        Args:
            data: Alert or event data dictionary

        Returns:
            Dict with 'ips' and 'hostnames' lists
        """
        ips = set()
        hostnames = set()

        def extract_from_value(value):
            """Recursively extract from any value type"""
            if isinstance(value, str):
                # Extract IPs
                found_ips = IP_PATTERN.findall(value)
                ips.update(found_ips)

                # Extract hostnames (exclude IPs)
                found_hosts = HOSTNAME_PATTERN.findall(value)
                for h in found_hosts:
                    # Skip if it looks like an IP or common TLDs we don't want
                    if not IP_PATTERN.match(h):
                        hostnames.add(h.lower())

            elif isinstance(value, dict):
                for v in value.values():
                    extract_from_value(v)
            elif isinstance(value, list):
                for item in value:
                    extract_from_value(item)

        # Common fields to check first (prioritized)
        priority_fields = [
            'src_ip', 'source_ip', 'srcip', 'src',
            'dst_ip', 'dest_ip', 'dstip', 'dst', 'destination_ip',
            'ip', 'ip_address', 'ipaddress',
            'hostname', 'host', 'computer_name', 'device_name',
            'src_host', 'dst_host', 'source_host', 'dest_host',
            'fqdn', 'dns_name', 'domain',
            'endpoint', 'machine', 'server', 'workstation',
            'actor_hostname', 'target_hostname',
            'local_ip', 'remote_ip', 'external_ip', 'internal_ip'
        ]

        # Check priority fields first
        for field in priority_fields:
            if field in data:
                extract_from_value(data[field])

        # Then extract from full data
        extract_from_value(data)

        # Filter out common non-asset hostnames
        excluded_domains = {
            'microsoft.com', 'windows.com', 'google.com', 'amazonaws.com',
            'cloudfront.net', 'azure.com', 'office365.com', 'outlook.com',
            'live.com', 'bing.com', 'msn.com'
        }
        hostnames = {h for h in hostnames if not any(h.endswith(d) for d in excluded_domains)}

        # Filter out localhost/loopback IPs
        excluded_ips = {'127.0.0.1', '0.0.0.0', '255.255.255.255'}
        ips = ips - excluded_ips

        return {
            'ips': list(ips),
            'hostnames': list(hostnames)
        }

    async def lookup_assets(
        self,
        ips: List[str],
        hostnames: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Lookup assets by IPs and hostnames.

        Args:
            ips: List of IP addresses
            hostnames: List of hostnames

        Returns:
            List of matched asset records
        """
        if not self.asset_service:
            logger.warning("Asset service not configured")
            return []

        matched_assets = []
        seen_ids = set()

        # Lookup by IP
        for ip in ips:
            try:
                asset = await self.asset_service.find_asset_by_ip(ip)
                if asset and asset['id'] not in seen_ids:
                    asset['_matched_by'] = f'ip:{ip}'
                    matched_assets.append(asset)
                    seen_ids.add(asset['id'])
            except Exception as e:
                logger.debug(f"IP lookup failed for {ip}: {e}")

        # Lookup by hostname
        for hostname in hostnames:
            try:
                asset = await self.asset_service.find_asset_by_hostname(hostname)
                if asset and asset['id'] not in seen_ids:
                    asset['_matched_by'] = f'hostname:{hostname}'
                    matched_assets.append(asset)
                    seen_ids.add(asset['id'])
            except Exception as e:
                logger.debug(f"Hostname lookup failed for {hostname}: {e}")

        return matched_assets

    def calculate_priority_boost(self, assets: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Calculate priority boost based on asset criticality.
        Uses the highest criticality among matched assets.

        Args:
            assets: List of matched assets

        Returns:
            Tuple of (boost_value, reason_string)
        """
        if not assets:
            return (0, None)

        # Find highest criticality
        highest_boost = 0
        critical_asset = None

        for asset in assets:
            criticality = asset.get('criticality', 'tier4')
            boost = CRITICALITY_PRIORITY_BOOST.get(criticality, 0)
            if boost > highest_boost:
                highest_boost = boost
                critical_asset = asset

        if highest_boost > 0 and critical_asset:
            reason = (
                f"Asset {critical_asset.get('display_name') or critical_asset.get('hostname')} "
                f"is {critical_asset.get('criticality')} criticality"
            )
            return (highest_boost, reason)

        return (0, None)

    def apply_priority_boost(self, current_priority: str, boost: int) -> str:
        """
        Apply priority boost to current priority.

        Args:
            current_priority: Current priority (P1-P4)
            boost: Number of levels to boost

        Returns:
            New priority string
        """
        priority_levels = ['P1', 'P2', 'P3', 'P4']

        try:
            current_idx = priority_levels.index(current_priority)
            new_idx = max(0, current_idx - boost)  # Lower index = higher priority
            return priority_levels[new_idx]
        except ValueError:
            return current_priority

    def build_asset_context(self, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build asset context for AI agent consumption.

        Args:
            assets: List of matched assets

        Returns:
            Structured asset context for agents
        """
        if not assets:
            return {
                'has_assets': False,
                'asset_count': 0,
                'assets': [],
                'summary': 'No matching assets found in CMDB'
            }

        # Build summary of assets
        asset_summaries = []
        for asset in assets:
            summary = {
                'id': str(asset.get('id')),
                'hostname': asset.get('hostname'),
                'display_name': asset.get('display_name'),
                'asset_type': asset.get('asset_type'),
                'criticality': asset.get('criticality'),
                'environment': asset.get('environment'),
                'owner': asset.get('owner'),
                'owner_team': asset.get('owner_team'),
                'department': asset.get('department'),
                'os_family': asset.get('os_family'),
                'os_name': asset.get('os_name'),
                'ip_addresses': asset.get('ip_addresses', []),
                'status': asset.get('status'),
                'compliance_tags': asset.get('compliance_tags', []),
                'matched_by': asset.get('_matched_by')
            }
            asset_summaries.append(summary)

        # Count by criticality
        criticality_counts = {}
        for asset in assets:
            crit = asset.get('criticality', 'unknown')
            criticality_counts[crit] = criticality_counts.get(crit, 0) + 1

        # Build text summary for agents
        text_parts = []
        for asset in asset_summaries[:5]:  # Top 5 assets
            name = asset.get('display_name') or asset.get('hostname') or 'Unknown'
            crit = asset.get('criticality', 'unknown')
            owner = asset.get('owner') or asset.get('owner_team') or 'Unknown'
            text_parts.append(f"- {name} ({crit}, owned by {owner})")

        text_summary = '\n'.join(text_parts)
        if len(assets) > 5:
            text_summary += f"\n... and {len(assets) - 5} more assets"

        return {
            'has_assets': True,
            'asset_count': len(assets),
            'criticality_breakdown': criticality_counts,
            'highest_criticality': min(
                (a.get('criticality', 'tier4') for a in assets),
                key=lambda x: ['tier1', 'tier2', 'tier3', 'tier4'].index(x) if x in ['tier1', 'tier2', 'tier3', 'tier4'] else 99
            ),
            'assets': asset_summaries,
            'summary': text_summary
        }

    async def enrich_alert(
        self,
        alert_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich an alert with asset information.

        Args:
            alert_data: Raw alert data

        Returns:
            Enrichment result with assets and priority boost
        """
        # Extract indicators from alert
        indicators = self.extract_indicators(alert_data)
        logger.debug(f"Extracted indicators: {len(indicators['ips'])} IPs, {len(indicators['hostnames'])} hostnames")

        # Lookup assets
        assets = await self.lookup_assets(
            indicators['ips'],
            indicators['hostnames']
        )
        logger.debug(f"Found {len(assets)} matching assets")

        # Calculate priority boost
        boost, boost_reason = self.calculate_priority_boost(assets)

        # Build context
        context = self.build_asset_context(assets)

        return {
            'extracted_indicators': indicators,
            'matched_assets': assets,
            'asset_context': context,
            'priority_boost': boost,
            'priority_boost_reason': boost_reason
        }

    async def enrich_investigation(
        self,
        investigation_id: str,
        alert_data: Dict[str, Any],
        current_priority: str = 'P3'
    ) -> Dict[str, Any]:
        """
        Enrich an investigation with asset data and update priority.

        Args:
            investigation_id: Investigation UUID
            alert_data: Alert data to extract indicators from
            current_priority: Current investigation priority

        Returns:
            Enrichment result
        """
        if not self.db:
            logger.warning("Database not configured")
            return {'success': False, 'error': 'Database not configured'}

        try:
            # Get asset enrichment
            enrichment = await self.enrich_alert(alert_data)

            # Calculate new priority
            new_priority = current_priority
            if enrichment['priority_boost'] > 0:
                new_priority = self.apply_priority_boost(
                    current_priority,
                    enrichment['priority_boost']
                )
                logger.info(
                    f"Investigation {investigation_id}: Priority boosted from {current_priority} to {new_priority} - "
                    f"{enrichment['priority_boost_reason']}"
                )

            # Update investigation with asset context
            import json
            import uuid as uuid_module

            # Convert investigation_id to UUID if needed
            if isinstance(investigation_id, str):
                try:
                    inv_uuid = uuid_module.UUID(investigation_id)
                except ValueError:
                    return {'success': False, 'error': f'Invalid investigation ID format: {investigation_id}'}
            else:
                inv_uuid = investigation_id

            async with self.db.tenant_acquire() as conn:
                # Get current investigation_data
                row = await conn.fetchrow(
                    'SELECT investigation_data FROM investigations WHERE id = $1',
                    inv_uuid
                )

                if not row:
                    return {'success': False, 'error': 'Investigation not found'}

                inv_data = row['investigation_data']
                if isinstance(inv_data, str):
                    inv_data = json.loads(inv_data)
                if inv_data is None:
                    inv_data = {}

                # Add asset enrichment to investigation data
                inv_data['asset_enrichment'] = {
                    'enriched_at': datetime.utcnow().isoformat(),
                    'asset_count': enrichment['asset_context']['asset_count'],
                    'assets': enrichment['asset_context']['assets'][:10],  # Top 10
                    'criticality_breakdown': enrichment['asset_context'].get('criticality_breakdown', {}),
                    'highest_criticality': enrichment['asset_context'].get('highest_criticality'),
                    'priority_boost': enrichment['priority_boost'],
                    'priority_boost_reason': enrichment['priority_boost_reason']
                }

                # Update investigation
                await conn.execute('''
                    UPDATE investigations
                    SET investigation_data = $1::jsonb,
                        priority = $2,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $3
                ''',
                    json.dumps(inv_data),
                    new_priority,
                    inv_uuid
                )

            return {
                'success': True,
                'investigation_id': str(inv_uuid),
                'assets_found': enrichment['asset_context']['asset_count'],
                'priority_changed': new_priority != current_priority,
                'old_priority': current_priority,
                'new_priority': new_priority,
                'asset_context': enrichment['asset_context']
            }

        except Exception as e:
            logger.error(f"Failed to enrich investigation {investigation_id}: {e}")
            return {'success': False, 'error': str(e)}

    def get_agent_asset_context(self, assets: List[Dict[str, Any]]) -> str:
        """
        Generate a text prompt addition for AI agents with asset context.

        Args:
            assets: List of matched assets

        Returns:
            Text to append to agent prompt
        """
        if not assets:
            return ""

        lines = [
            "\n## Asset Context from CMDB\n",
            f"Found {len(assets)} asset(s) related to this investigation:\n"
        ]

        for i, asset in enumerate(assets[:5], 1):
            name = asset.get('display_name') or asset.get('hostname') or 'Unknown'
            crit = asset.get('criticality', 'unknown')
            owner = asset.get('owner') or asset.get('owner_team') or 'Unknown'
            env = asset.get('environment', 'unknown')
            os_info = asset.get('os_name') or asset.get('os_family') or 'Unknown OS'

            lines.append(f"\n### Asset {i}: {name}")
            lines.append(f"- **Criticality:** {crit}")
            lines.append(f"- **Owner:** {owner}")
            lines.append(f"- **Environment:** {env}")
            lines.append(f"- **OS:** {os_info}")
            lines.append(f"- **Department:** {asset.get('department', 'N/A')}")

            if asset.get('compliance_tags'):
                lines.append(f"- **Compliance Tags:** {', '.join(asset.get('compliance_tags', []))}")

            if asset.get('ip_addresses'):
                lines.append(f"- **IPs:** {', '.join(asset.get('ip_addresses', [])[:3])}")

        if len(assets) > 5:
            lines.append(f"\n*... and {len(assets) - 5} more assets*")

        # Add investigation guidance based on criticality
        highest_crit = min(
            (a.get('criticality', 'tier4') for a in assets),
            key=lambda x: ['tier1', 'tier2', 'tier3', 'tier4'].index(x) if x in ['tier1', 'tier2', 'tier3', 'tier4'] else 99
        )

        if highest_crit == 'tier1':
            lines.append("\n**CRITICAL ASSET INVOLVED** - This investigation involves a Tier 1 (critical) asset. "
                        "Prioritize thorough analysis and consider immediate escalation if threat is confirmed.")
        elif highest_crit == 'tier2':
            lines.append("\n**High-importance asset involved** - This investigation involves a Tier 2 asset. "
                        "Ensure comprehensive analysis before resolution.")

        return '\n'.join(lines)


# Singleton instance
_enrichment_service: Optional[AssetInvestigationEnrichment] = None


def get_asset_enrichment_service() -> AssetInvestigationEnrichment:
    """Get the global asset enrichment service instance"""
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = AssetInvestigationEnrichment()
    return _enrichment_service


async def enrich_investigation_with_assets(
    investigation_id: str,
    alert_data: Dict[str, Any],
    current_priority: str = 'P3'
) -> Dict[str, Any]:
    """
    Convenience function to enrich an investigation with asset data.

    Args:
        investigation_id: Investigation UUID
        alert_data: Alert data dictionary
        current_priority: Current priority string

    Returns:
        Enrichment result
    """
    from services.postgres_db import postgres_db
    from services.asset_service import get_asset_service

    service = get_asset_enrichment_service()
    service.set_db(postgres_db)

    asset_service = get_asset_service()
    asset_service.set_db(postgres_db)
    service.set_asset_service(asset_service)

    return await service.enrich_investigation(
        investigation_id,
        alert_data,
        current_priority
    )
