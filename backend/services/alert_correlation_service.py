# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Correlation Service

Automatically links related alerts to existing investigations based on:
- Shared IOCs (IPs, domains, hashes, emails)
- Similar patterns/signatures
- Same threat actors/campaigns

Also handles reopening closed investigations when new related alerts appear.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
import json

logger = logging.getLogger(__name__)


class AlertCorrelationService:
    def __init__(self, db):
        self.db = db
        self.lookback_days = 30  # Look back 30 days for related investigations

    async def correlate_alert(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
        iocs: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Correlate a new alert with existing investigations.

        Returns investigation_id if correlation found, None otherwise.
        """
        try:
            logger.info(f"Alert {alert_id}: Starting correlation analysis")

            # Extract IOCs from the alert
            alert_iocs = self._extract_iocs_from_alert(alert_data, iocs)
            if not alert_iocs['all_iocs']:
                logger.debug(f"Alert {alert_id}: No IOCs found for correlation")
                return None

            logger.info(f"Alert {alert_id}: Found {len(alert_iocs['all_iocs'])} IOCs for correlation")

            # Find matching investigations (including closed ones within 30 days)
            matches = await self._find_matching_investigations(alert_id, alert_iocs)

            if not matches:
                logger.debug(f"Alert {alert_id}: No matching investigations found")
                return None

            # Select best match (highest score)
            best_match = matches[0]
            investigation_id = best_match['investigation_id']
            match_score = best_match['score']
            shared_iocs = best_match['shared_iocs']

            logger.info(
                f"Alert {alert_id}: Matched investigation {investigation_id} "
                f"(score={match_score}, shared IOCs={len(shared_iocs)})"
            )

            # Link alert to investigation
            await self._link_alert_to_investigation(
                alert_id,
                alert_data,
                investigation_id,
                match_score,
                shared_iocs,
                best_match
            )

            return investigation_id

        except Exception as e:
            logger.error(f"Alert {alert_id}: Correlation failed - {e}")
            return None

    def _extract_iocs_from_alert(
        self,
        alert_data: Dict[str, Any],
        iocs: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Extract and normalize IOCs from alert data."""
        ips = set()
        domains = set()
        hashes = set()
        emails = set()

        # From enrichment IOCs
        if iocs:
            ips.update(iocs.get('ips', []))
            domains.update(iocs.get('domains', []))
            hashes.update(iocs.get('hashes', []))
            emails.update(iocs.get('emails', []))

        # From raw_event
        raw_event = alert_data.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        if raw_event:
            # Extract from common fields
            if raw_event.get('source_ip'):
                ips.add(raw_event['source_ip'])
            if raw_event.get('destination_ip'):
                ips.add(raw_event['destination_ip'])
            if raw_event.get('domain'):
                domains.add(raw_event['domain'])
            if raw_event.get('file_hash'):
                hashes.add(raw_event['file_hash'])
            if raw_event.get('sender'):
                emails.add(raw_event['sender'])

            # Also extract from _extracted.iocs if present
            extracted = raw_event.get('_extracted', {})
            if extracted:
                iocs_obj = extracted.get('iocs', {})
                if iocs_obj:
                    ips.update(iocs_obj.get('ips', []))
                    domains.update(iocs_obj.get('domains', []))
                    hashes.update(iocs_obj.get('file_hashes', []))
                    hashes.update(iocs_obj.get('hashes', []))
                    emails.update(iocs_obj.get('emails', []))

        all_iocs = list(ips) + list(domains) + list(hashes) + list(emails)

        return {
            'ips': list(ips),
            'domains': list(domains),
            'hashes': list(hashes),
            'emails': list(emails),
            'all_iocs': all_iocs
        }

    async def _find_matching_investigations(
        self,
        alert_id: str,
        alert_iocs: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Find investigations with matching IOCs.

        Looks back 30 days, includes closed investigations.
        """
        if not self.db or not self.db.pool:
            return []

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)

        async with self.db.tenant_acquire() as conn:
            # Get all investigations from the last 30 days with their IOCs
            investigations = await conn.fetch("""
                SELECT
                    i.id,
                    i.investigation_id,
                    i.state,
                    i.disposition,
                    i.created_at,
                    i.completed_at,
                    i.investigation_data
                FROM investigations i
                WHERE i.created_at >= $1
                ORDER BY i.created_at DESC
            """, cutoff_date)

            matches = []

            for inv_row in investigations:
                inv_id = inv_row['investigation_id']
                inv_uuid = inv_row['id']
                inv_state = inv_row['state']

                # Get IOCs for this investigation (from linked alerts)
                inv_iocs = await self._get_investigation_iocs(conn, inv_uuid)

                # Calculate match score
                shared_iocs = self._find_shared_iocs(alert_iocs, inv_iocs)

                if not shared_iocs:
                    continue

                # Calculate correlation score
                # - 10 points per shared IOC
                # - Bonus for hash matches (more specific)
                # - Bonus for multiple IOC types matching
                score = len(shared_iocs) * 10

                ioc_types_matched = set()
                hash_matches = 0

                for ioc in shared_iocs:
                    if ioc in alert_iocs['hashes']:
                        hash_matches += 1
                        score += 20  # Hash match bonus
                        ioc_types_matched.add('hash')
                    elif ioc in alert_iocs['ips']:
                        ioc_types_matched.add('ip')
                    elif ioc in alert_iocs['domains']:
                        ioc_types_matched.add('domain')
                    elif ioc in alert_iocs['emails']:
                        ioc_types_matched.add('email')

                # Multi-type match bonus (e.g., same IP AND domain)
                if len(ioc_types_matched) > 1:
                    score += 30

                # Boost recent investigations
                age_days = (datetime.now(timezone.utc) - inv_row['created_at']).days
                if age_days < 7:
                    score += 20
                elif age_days < 14:
                    score += 10

                matches.append({
                    'investigation_id': inv_id,
                    'investigation_uuid': inv_uuid,
                    'state': inv_state,
                    'disposition': inv_row['disposition'],
                    'score': score,
                    'shared_iocs': list(shared_iocs),
                    'hash_matches': hash_matches,
                    'ioc_types_matched': list(ioc_types_matched),
                    'age_days': age_days,
                    'was_closed': inv_state in ['RESOLVED', 'CLOSED', 'FALSE_POSITIVE']
                })

            # Sort by score (highest first)
            matches.sort(key=lambda x: x['score'], reverse=True)

            # Only return matches with meaningful evidence:
            # - Score >= 50 (raised from 30 to reduce false correlations)
            # - Domain-only matches are NOT sufficient (marketing/tracking domains cause false links)
            # - Must have at least one hash, IP, or email match, OR 5+ domain matches
            significant_matches = []
            for m in matches:
                if m['score'] < 50:
                    continue
                types = set(m['ioc_types_matched'])
                # Reject domain-only correlations with fewer than 5 shared domains
                if types == {'domain'} and len(m['shared_iocs']) < 5:
                    logger.info(
                        f"Alert correlation: Skipping investigation {m['investigation_id']} "
                        f"- domain-only match ({len(m['shared_iocs'])} domains) insufficient"
                    )
                    continue
                significant_matches.append(m)

            return significant_matches

    async def _get_investigation_iocs(
        self,
        conn,
        investigation_uuid
    ) -> Dict[str, Set[str]]:
        """Get all IOCs from alerts linked to this investigation."""
        ips = set()
        domains = set()
        hashes = set()
        emails = set()

        # Get all alerts linked to this investigation
        alerts = await conn.fetch("""
            SELECT raw_event
            FROM alerts
            WHERE investigation_id = $1
        """, investigation_uuid)

        for alert_row in alerts:
            raw_event = alert_row['raw_event']
            if isinstance(raw_event, str):
                try:
                    raw_event = json.loads(raw_event)
                except:
                    continue

            if not raw_event:
                continue

            # Extract IOCs from enrichment data
            extracted = raw_event.get('_extracted', {})
            if extracted:
                # IOCs can be in two places:
                # 1. _extracted.iocs.* (from field_extraction)
                # 2. _extracted.* (legacy format)
                iocs_obj = extracted.get('iocs', {})
                if iocs_obj:
                    # New format: _extracted.iocs.ips
                    ips.update(iocs_obj.get('ips', []))
                    domains.update(iocs_obj.get('domains', []))
                    hashes.update(iocs_obj.get('file_hashes', []))
                    hashes.update(iocs_obj.get('hashes', []))
                    emails.update(iocs_obj.get('emails', []))
                else:
                    # Legacy format: _extracted.ips
                    ips.update(extracted.get('ips', []))
                    domains.update(extracted.get('domains', []))
                    hashes.update(extracted.get('file_hashes', []))
                    hashes.update(extracted.get('hashes', []))
                    emails.update(extracted.get('emails', []))

        return {
            'ips': ips,
            'domains': domains,
            'hashes': hashes,
            'emails': emails
        }

    def _find_shared_iocs(
        self,
        alert_iocs: Dict[str, Any],
        inv_iocs: Dict[str, Set[str]]
    ) -> Set[str]:
        """Find IOCs that appear in both alert and investigation."""
        shared = set()

        # Compare each IOC type
        alert_ips = set(alert_iocs['ips'])
        alert_domains = set(alert_iocs['domains'])
        alert_hashes = set(alert_iocs['hashes'])
        alert_emails = set(alert_iocs['emails'])

        shared.update(alert_ips & inv_iocs['ips'])
        shared.update(alert_domains & inv_iocs['domains'])
        shared.update(alert_hashes & inv_iocs['hashes'])
        shared.update(alert_emails & inv_iocs['emails'])

        return shared

    async def _link_alert_to_investigation(
        self,
        alert_id: str,
        alert_data: Dict[str, Any],
        investigation_id: str,
        match_score: int,
        shared_iocs: List[str],
        match_details: Dict[str, Any]
    ):
        """Link alert to investigation and reopen if necessary."""
        if not self.db or not self.db.pool:
            return

        async with self.db.tenant_acquire() as conn:
            # Get investigation details
            inv_row = await conn.fetchrow("""
                SELECT id, investigation_id, state, disposition, investigation_data
                FROM investigations
                WHERE investigation_id = $1
            """, investigation_id)

            if not inv_row:
                logger.warning(f"Investigation {investigation_id} not found")
                return

            inv_uuid = inv_row['id']
            inv_state = inv_row['state']
            was_closed = inv_state in ['RESOLVED', 'CLOSED', 'FALSE_POSITIVE']

            # Link alert to investigation
            await conn.execute("""
                UPDATE alerts
                SET
                    investigation_id = $1,
                    status = 'triaged',
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = $2
            """, inv_uuid, alert_id)

            logger.info(f"Alert {alert_id}: Linked to investigation {investigation_id}")

            # Update investigation data with correlation info
            investigation_data = inv_row['investigation_data']
            if isinstance(investigation_data, str):
                investigation_data = json.loads(investigation_data)

            if 'correlated_alerts' not in investigation_data:
                investigation_data['correlated_alerts'] = []

            investigation_data['correlated_alerts'].append({
                'alert_id': alert_id,
                'alert_title': alert_data.get('title', 'Unknown'),
                'correlation_score': match_score,
                'shared_iocs': shared_iocs,
                'correlation_timestamp': datetime.now(timezone.utc).isoformat(),
                'ioc_types_matched': match_details['ioc_types_matched'],
                'hash_matches': match_details['hash_matches']
            })

            # Reopen investigation if it was closed — UNLESS the analyst already
            # marked it BENIGN / FALSE_POSITIVE. Recurring patterns (same sender,
            # same IOCs) shouldn't keep flipping a closed case back open; that
            # makes the queue impossible to clear. Attach the new alert and add
            # a note, but leave the investigation closed.
            prior_disposition = (inv_row['disposition'] or '').upper()
            benign_dispositions = ('BENIGN', 'FALSE_POSITIVE', 'BENIGN_POSITIVE')
            if was_closed and prior_disposition not in benign_dispositions:
                new_state = 'ANALYZING'  # Reopen for Riggs to re-analyze

                await conn.execute("""
                    UPDATE investigations
                    SET
                        state = $1,
                        investigation_data = $2,
                        updated_at = CURRENT_TIMESTAMP,
                        completed_at = NULL
                    WHERE id = $3
                """, new_state, json.dumps(investigation_data), inv_uuid)

                logger.warning(
                    f"Investigation {investigation_id}: REOPENED due to new correlated alert {alert_id} "
                    f"(was {inv_state}, now {new_state}, score={match_score})"
                )

                # Create a note about the reopening
                await conn.execute("""
                    INSERT INTO investigation_notes (
                        investigation_id,
                        note_type,
                        content,
                        author,
                        author_type,
                        created_at
                    ) VALUES ($1, 'SYSTEM_NOTE', $2, 'alert_correlation_service', 'SYSTEM', CURRENT_TIMESTAMP)
                """, investigation_id,
                    f"Investigation reopened due to new correlated alert {alert_id}. "
                    f"Shared {len(shared_iocs)} IOCs (score: {match_score}). "
                    f"IOC types matched: {', '.join(match_details['ioc_types_matched'])}"
                )
            elif was_closed:
                # Closed with a benign-class disposition — keep it closed,
                # just record the recurrence so analysts can still see history.
                await conn.execute("""
                    UPDATE investigations
                    SET
                        investigation_data = $1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $2
                """, json.dumps(investigation_data), inv_uuid)

                await conn.execute("""
                    INSERT INTO investigation_notes (
                        investigation_id,
                        note_type,
                        content,
                        author,
                        author_type,
                        created_at
                    ) VALUES ($1, 'SYSTEM_NOTE', $2, 'alert_correlation_service', 'SYSTEM', CURRENT_TIMESTAMP)
                """, investigation_id,
                    f"Recurring alert {alert_id} correlated to this CLOSED investigation "
                    f"(prior disposition: {prior_disposition}). Staying closed. "
                    f"Shared {len(shared_iocs)} IOCs (score: {match_score})."
                )

                logger.info(
                    f"Investigation {investigation_id}: recurring alert {alert_id} attached, "
                    f"staying CLOSED (prior disposition: {prior_disposition})"
                )
            else:
                # Just update investigation data (already active)
                await conn.execute("""
                    UPDATE investigations
                    SET
                        investigation_data = $1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $2
                """, json.dumps(investigation_data), inv_uuid)

                logger.info(
                    f"Investigation {investigation_id}: Added correlated alert {alert_id} "
                    f"(already active, score={match_score})"
                )


# Singleton
_correlation_service = None

def get_correlation_service():
    """Get singleton correlation service instance."""
    global _correlation_service
    if _correlation_service is None:
        from services.postgres_db import postgres_db
        _correlation_service = AlertCorrelationService(postgres_db)
    return _correlation_service
