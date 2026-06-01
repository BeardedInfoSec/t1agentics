#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""Quick script to re-run RIGGS analysis on a specific investigation"""
import asyncio
import sys
import json
import os
import httpx

sys.path.insert(0, '/app')

os.environ.setdefault('POSTGRES_HOST', 'postgres')
os.environ.setdefault('POSTGRES_PORT', '5432')
os.environ.setdefault('POSTGRES_DB', 'agentcore')
os.environ.setdefault('POSTGRES_USER', 'agentcore')
os.environ.setdefault('POSTGRES_PASSWORD', 'agentcore_dev_password')

ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
CLAUDE_MODEL = os.getenv('CLAUDE_DEFAULT_MODEL', 'claude-sonnet-4-5-20250929')

async def call_llm(prompt: str) -> str:
    """Direct call to Claude API"""
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    payload = {
        "model": CLAUDE_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4000,
        "temperature": 0.2
    }

    async with httpx.AsyncClient(timeout=300) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        return data['content'][0]['text']

async def reanalyze(investigation_id: str):
    from services.postgres_db import postgres_db
    from services.field_extraction import FieldExtractor

    # Initialize DB
    print(f'[REANALYZE] Initializing DB...', flush=True)
    if not postgres_db.connected:
        await postgres_db.connect()
    print(f'[REANALYZE] DB initialized', flush=True)

    async with postgres_db.pool.acquire() as conn:
        # Get investigation with alert data
        inv = await conn.fetchrow("""
            SELECT i.*, a.raw_event, a.title as alert_title,
                   a.description as alert_desc, a.severity as alert_severity
            FROM investigations i
            LEFT JOIN alerts a ON i.alert_id::text = a.alert_id OR i.alert_id::text = a.id::text
            WHERE i.investigation_id = $1
        """, investigation_id)

        if not inv:
            print(f'[REANALYZE] Investigation {investigation_id} not found!', flush=True)
            return None

        print(f'[REANALYZE] Found investigation {investigation_id}', flush=True)

        # Parse raw_event
        raw_event = inv['raw_event']
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}
        raw_event = raw_event or {}

        # Get existing investigation_data
        inv_data = inv['investigation_data']
        if isinstance(inv_data, str):
            try:
                inv_data = json.loads(inv_data)
            except:
                inv_data = {}
        inv_data = inv_data or {}

        # Run field extraction
        print(f'[REANALYZE] Running field extraction...', flush=True)
        field_extractor = FieldExtractor()
        riggs_extraction = field_extractor.extract_all(raw_event)

        iocs = riggs_extraction.get('iocs', {})
        print(f'[REANALYZE] Extracted {len(iocs.get("ips", []))} IPs, '
              f'{len(iocs.get("domains", []))} domains', flush=True)

        # Build a focused analysis prompt
        title = inv.get('title') or inv.get('alert_title') or 'Unknown Alert'
        severity = inv.get('alert_severity') or 'medium'
        enrichment = inv_data.get('_extracted', {}).get('enrichment', {})

        # Truncate raw_event for context limit
        raw_event_str = json.dumps(raw_event, default=str)[:4000]
        enrichment_str = json.dumps(enrichment, default=str)[:2000]
        iocs_str = json.dumps(iocs, default=str)[:1000]

        prompt = f"""You are Riggs, a senior SOC analyst with 15 years of experience. Analyze this security alert thoroughly and provide a comprehensive assessment that would help a junior analyst understand exactly what happened.

ALERT: {title}
SEVERITY: {severity}

RAW EVENT DATA:
{raw_event_str}

ENRICHMENT DATA:
{enrichment_str}

EXTRACTED IOCs:
{iocs_str}

Provide a DETAILED analysis as JSON. Be specific and thorough - don't give generic responses. Reference actual data from the alert:

{{
    "verdict": "malicious|suspicious|benign|needs_review",
    "verdict_title": "Short 2-4 word title like 'Credential Theft Attempt' or 'Cryptominer Infection' or 'Phishing Campaign'",
    "confidence": 0.0-1.0,
    "threat_type": "malware|phishing|credential_theft|lateral_movement|data_exfiltration|cryptomining|ransomware|botnet|apt|unknown",
    "threat_category": "More specific category like 'Banking Trojan', 'Spearphishing', 'Coinminer', 'Ransomware Precursor'",
    "summary": "4-6 sentence detailed summary explaining WHAT happened, HOW it happened, WHO/WHAT is affected, and WHY this is concerning. Be specific - mention actual hostnames, IPs, techniques observed.",
    "attack_narrative": "A paragraph describing the attack flow from initial access through current state. Written like a story: 'The attacker first... then... this led to...'",
    "key_findings": ["Be specific - reference actual data", "Include severity context", "Mention specific IOCs or behaviors observed", "At least 4-6 findings"],
    "timeline": [{{"timestamp": "ISO timestamp", "event": "Detailed description of what happened", "phase": "reconnaissance|initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_control|exfiltration|impact"}}],
    "mitre_techniques": [{{"id": "T1234", "name": "Technique Name", "tactic": "The tactic phase", "confidence": 0.8, "evidence": "What in the alert supports this technique"}}],
    "affected_entities": [{{"type": "host|user|ip|service|application", "value": "the entity", "role": "target|source|c2|compromised", "risk_level": "critical|high|medium|low", "notes": "Brief context"}}],
    "recommendations": [{{"action": "Specific actionable step", "priority": 1, "category": "immediate|short_term|long_term", "rationale": "Why this action matters"}}],
    "iocs": [{{"type": "ip|domain|hash|url|email", "value": "the ioc", "verdict": "malicious|suspicious|unknown", "context": "What this IOC was doing"}}],
    "evidence_weighting": [{{"signal": "Specific evidence from the alert", "weight": "high|medium|low", "explanation": "Why this evidence matters"}}],
    "confidence_explanation": {{
        "supporting_evidence": ["List specific evidence that supports the verdict"],
        "confidence_limiters": ["What's missing or uncertain that limits confidence"],
        "inference_notes": ["Any assumptions or inferences made"]
    }},
    "threat_type_justification": "Detailed explanation of why this threat type was chosen, referencing specific indicators",
    "what_would_change_verdict": ["Specific information that would change the analysis"],
    "business_impact": "Assessment of potential business impact - data at risk, service disruption, compliance implications",
    "related_threats": ["Similar threat campaigns or malware families this resembles"]
}}

IMPORTANT:
- verdict_title MUST be filled in (e.g., "Malware Delivery via Certutil", "Credential Theft Attack")
- summary MUST be 4-6 sentences with specific details from the alert
- attack_narrative MUST tell the story of the attack
- business_impact MUST assess what's at risk

Example of a GOOD summary: "A privileged user account (jwright) on LNX-WEB01 executed certutil.exe to download a malicious payload from evil.com/mal.exe. The command was used to fetch and execute malware, indicating a likely compromise through credential theft or social engineering. The malicious domain evil.com and associated URL are known malware distribution points. Immediate isolation and forensic analysis is required."

Example of a BAD summary: "The event indicates a potential malware infection on LNX-WEB01."

Be thorough and specific. Respond ONLY with the JSON object."""

        print(f'[REANALYZE] Calling Claude API ({CLAUDE_MODEL})...', flush=True)
        try:
            response = await call_llm(prompt)
            print(f'[REANALYZE] Got response ({len(response)} chars)', flush=True)
        except Exception as e:
            print(f'[REANALYZE] LLM call failed: {e}', flush=True)
            return None

        # Parse LLM response
        riggs_analysis = None
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                riggs_analysis = json.loads(response[json_start:json_end])
                print(f'[REANALYZE] Parsed analysis: verdict={riggs_analysis.get("verdict")}, '
                      f'confidence={riggs_analysis.get("confidence")}', flush=True)
        except Exception as e:
            print(f'[REANALYZE] Failed to parse response: {e}', flush=True)
            print(f'[REANALYZE] Raw response: {response[:500]}...', flush=True)

        if riggs_analysis:
            # Enrich analysis with specific details from raw_event if LLM was too brief
            print(f'[REANALYZE] raw_event keys: {list(raw_event.keys())[:10]}', flush=True)
            hostname = raw_event.get('host', {}).get('hostname', '')
            username = raw_event.get('user', {}).get('username', '')
            print(f'[REANALYZE] Enrichment - hostname={hostname}, username={username}', flush=True)
            process_name = raw_event.get('process', {}).get('name', '')
            command_line = raw_event.get('process', {}).get('command_line', '')
            mitre_tech = raw_event.get('mitre', {}).get('technique', '')
            mitre_id = raw_event.get('mitre', {}).get('technique_id', '')
            source_ip = raw_event.get('network', {}).get('source_ip', '')
            domain = raw_event.get('network', {}).get('domain', '')

            # Build verdict_title if not provided
            if not riggs_analysis.get('verdict_title'):
                if 'certutil' in command_line.lower():
                    riggs_analysis['verdict_title'] = 'Malware Delivery via Certutil'
                elif mitre_tech:
                    riggs_analysis['verdict_title'] = f'{mitre_tech} Attack'
                else:
                    riggs_analysis['verdict_title'] = 'Suspicious Activity Detected'

            # Build detailed summary if too short
            current_summary = riggs_analysis.get('summary', '')
            if len(current_summary) < 100:
                parts = []
                if hostname and username:
                    parts.append(f"On host {hostname}, user {username}")
                if command_line:
                    parts.append(f"executed suspicious command: {command_line}")
                if source_ip:
                    parts.append(f"External IP {source_ip} was involved")
                if domain:
                    parts.append(f"Communication with {domain} detected")
                if mitre_tech:
                    parts.append(f"This maps to MITRE ATT&CK technique {mitre_id} ({mitre_tech})")
                parts.append("Immediate investigation and potential containment recommended.")
                riggs_analysis['summary'] = '. '.join(parts) + '.'

            # Build attack_narrative if not provided
            if not riggs_analysis.get('attack_narrative'):
                narrative_parts = []
                if username:
                    narrative_parts.append(f"The attack began with the {username} account")
                    if raw_event.get('user', {}).get('privileged'):
                        narrative_parts.append("(a privileged account)")
                if hostname:
                    narrative_parts.append(f"on {hostname}")
                if command_line:
                    narrative_parts.append(f". The user executed {process_name or 'a command'}: '{command_line}'")
                if 'certutil' in command_line.lower() and 'http' in command_line.lower():
                    narrative_parts.append(". This is a known technique (LOLBin) for downloading malware while evading detection")
                if domain:
                    narrative_parts.append(f". The malicious domain {domain} was contacted")
                narrative_parts.append(". Further investigation is needed to determine if additional systems are compromised.")
                riggs_analysis['attack_narrative'] = ''.join(narrative_parts)

            # Build business_impact if not provided
            if not riggs_analysis.get('business_impact'):
                impacts = []
                if raw_event.get('user', {}).get('privileged'):
                    impacts.append("Privileged account compromise could lead to widespread system access")
                if 'web' in hostname.lower():
                    impacts.append("Web server compromise may expose customer data or enable further attacks")
                if domain:
                    impacts.append("External C2 communication indicates active threat actor control")
                impacts.append("Potential for data exfiltration and lateral movement")
                riggs_analysis['business_impact'] = '. '.join(impacts) + '.'

            # Ensure threat_category is set
            if not riggs_analysis.get('threat_category'):
                if 'certutil' in command_line.lower():
                    riggs_analysis['threat_category'] = 'Living Off The Land (LOLBin)'
                elif 'mining' in str(raw_event).lower() or 'miner' in str(raw_event).lower():
                    riggs_analysis['threat_category'] = 'Cryptomining'
                elif mitre_tech:
                    riggs_analysis['threat_category'] = mitre_tech

            inv_data['riggs_analysis'] = riggs_analysis
            new_confidence = riggs_analysis.get('confidence', 0.65)
            new_verdict = riggs_analysis.get('verdict', 'needs_review')

            disposition_map = {
                'malicious': 'MALICIOUS',
                'suspicious': 'SUSPICIOUS',
                'benign': 'BENIGN',
                'needs_review': 'UNKNOWN'
            }
            new_disposition = disposition_map.get(new_verdict, 'UNKNOWN')
            new_state = 'NEEDS_REVIEW' if new_verdict != 'benign' else 'CLOSED'

            print(f'[REANALYZE] Updating: confidence={new_confidence}, disposition={new_disposition}', flush=True)

            await conn.execute("""
                UPDATE investigations
                SET investigation_data = $1,
                    confidence = $2,
                    disposition = $3,
                    state = $4,
                    updated_at = NOW()
                WHERE investigation_id = $5
            """, json.dumps(inv_data), new_confidence, new_disposition, new_state, investigation_id)

            print(f'[REANALYZE] Success! Investigation updated.', flush=True)
            return riggs_analysis

        return None

if __name__ == '__main__':
    inv_id = sys.argv[1] if len(sys.argv) > 1 else 'INV-BF1CD98F'
    result = asyncio.run(reanalyze(inv_id))
    if result:
        print(f'\nFinal: verdict={result.get("verdict")}, confidence={result.get("confidence")}', flush=True)
