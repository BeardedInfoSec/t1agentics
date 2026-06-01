# Entity-Based Alert Correlation System

## Technical Design Document

**Version:** 1.0
**Author:** T1 Agentics Engineering
**Status:** Implementation Ready

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Architecture Overview](#architecture-overview)
4. [Entity Extraction](#entity-extraction)
5. [Correlation Scoring Model](#correlation-scoring-model)
6. [Guardrails & Safety](#guardrails--safety)
7. [Database Schema](#database-schema)
8. [Correlation Flow](#correlation-flow)
9. [API Reference](#api-reference)
10. [Examples & Scenarios](#examples--scenarios)
11. [Troubleshooting](#troubleshooting)

---

## Executive Summary

The Entity-Based Correlation System replaces T1 Agentics' IOC-only correlation with a SOC-analyst-inspired approach that groups alerts by **ownership** (users, hosts, campaigns) rather than weak IOC signals.

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Entity-Centric Grouping** | Users and hosts are primary anchors, not IOCs |
| **Scored Correlation** | Every match contributes to a confidence score |
| **Guardrails** | Prevents investigation collapse and unrelated merging |
| **Explainability** | Every decision is justified and logged |
| **Decay Model** | Entity confidence decays over time |

### Expected Outcomes

| Metric | Before | After |
|--------|--------|-------|
| Alerts per Investigation (avg) | 576 | 15-30 |
| Max Alerts per Investigation | 14,560 | ~200 (capped) |
| Investigation Count (15k alerts) | 27 | 200-500 |
| Analyst Trust | Low | High |

---

## Problem Statement

### The Over-Correlation Problem

In stress testing, 15,649 alerts collapsed into only 27 investigations because:

1. **IOC-based correlation is too weak** - External IPs/domains are shared across unrelated attacks
2. **No entity awareness** - System doesn't understand that `jsmith@corp.local` owns their alerts
3. **No guardrails** - One investigation absorbed 14,560 alerts
4. **No decay** - Old investigations kept absorbing new alerts indefinitely

### Real SOC Analyst Behavior

When a SOC analyst sees alerts, they ask:

1. "Who is affected?" → **User**
2. "What system is compromised?" → **Host**
3. "What type of attack is this?" → **MITRE Technique**
4. "Is this the same malware?" → **Threat Object**
5. "Is this related to an ongoing incident?" → **Time + Context**

This system encodes that reasoning.

---

## Architecture Overview

```

 ALERT INGESTION PIPELINE 

 
 

 ENTITY EXTRACTION LAYER 
 
 User Host MITRE Threat 
 Extractor Extractor Extractor Extractor 
 

 
 

 CORRELATION SCORING ENGINE 
 
 For each open investigation: 
 1. Calculate entity match scores 
 2. Apply time proximity bonus 
 3. Apply attack-type compatibility check 
 4. Sum weighted scores 
 5. Return ranked candidates 
 

 
 

 GUARDRAIL ENFORCEMENT 
 
 Max Users Max Hosts Attack Type Entity 
 (≤5) (≤10) Lock Decay 
 

 
 

 DECISION & LINKING 
 
 Score ≥ 100 → Auto-link to investigation 
 Score 60-99 → Soft-link (flag for analyst review) 
 Score < 60 → Create new investigation 
 

 
 

 EXPLAINABILITY & AUDIT LOG 
 "Alert ABC linked to Investigation 42 because: 
 - User match (jsmith@corp.local): +100 
 - Host match (WORKSTATION-123): +80 
 - Time proximity (<15min): +20 
 - Total Score: 200 (threshold: 100)" 

```

---

## Entity Extraction

### Supported Entity Types

| Entity Type | Priority | Fields Searched | Normalization |
|-------------|----------|-----------------|---------------|
| `user` | 1 (Highest) | `user`, `username`, `account_name`, `user_name`, `src_user`, `dst_user`, `email`, `reporter` | Lowercase, strip domain prefix |
| `host` | 2 | `hostname`, `computer_name`, `device_name`, `host`, `src_host`, `dst_host`, `workstation` | Lowercase, strip FQDN suffix |
| `mitre_technique` | 3 | `technique_id`, `mitre_technique`, keyword inference | Uppercase (T1234.001 format) |
| `threat_object` | 4 | `file_hash`, `sha256`, `md5`, `malware_family`, `threat_name`, `detection_name` | Lowercase hashes, original case for names |
| `internal_ip` | 5 | `src_ip`, `source_ip` (RFC1918 only) | Dotted notation |
| `external_ioc` | 6 (Lowest) | `dst_ip`, `domain`, `url` (external only) | Lowercase |

### Entity Normalization Rules

#### User Normalization

```python
def normalize_user(raw_value: str) -> str:
 """
 Normalize username to canonical form.

 Examples:
 "CORP\\jsmith" → "jsmith"
 "jsmith@corp.local" → "jsmith"
 "JSMITH" → "jsmith"
 "John Smith" → "john smith" (display name, lower priority)
 """
 value = raw_value.strip()

 # Handle DOMAIN\user format
 if '\\' in value:
 value = value.split('\\')[-1]

 # Handle email format
 if '@' in value:
 value = value.split('@')[0]

 return value.lower()
```

#### Host Normalization

```python
def normalize_host(raw_value: str) -> str:
 """
 Normalize hostname to canonical form.

 Examples:
 "WORKSTATION-123.corp.local" → "workstation-123"
 "SERVER01.DOMAIN.COM" → "server01"
 "workstation-123" → "workstation-123"
 """
 value = raw_value.strip().lower()

 # Strip common FQDN suffixes
 for suffix in ['.corp.local', '.local', '.domain.com', '.internal']:
 if value.endswith(suffix):
 value = value[:-len(suffix)]
 break

 return value
```

#### MITRE Technique Extraction

```python
def extract_mitre_techniques(alert: dict) -> List[str]:
 """
 Extract MITRE ATT&CK technique IDs from alert.

 Sources:
 1. Explicit technique_id field
 2. Keyword-based inference from title/description
 """
 techniques = set()

 # Direct extraction
 if alert.get('technique_id'):
 techniques.add(normalize_technique(alert['technique_id']))

 # Keyword inference
 text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()

 KEYWORD_MAP = {
 'phishing': ['T1566', 'T1566.001', 'T1566.002'],
 'powershell': ['T1059.001'],
 'brute force': ['T1110'],
 'credential dump': ['T1003'],
 'lateral movement': ['T1021'],
 'ransomware': ['T1486'],
 'exfiltration': ['T1041'],
 'command and control': ['T1071'],
 'c2': ['T1071'],
 }

 for keyword, techs in KEYWORD_MAP.items():
 if keyword in text:
 techniques.update(techs)

 return list(techniques)
```

### Extraction Priority

When multiple values exist for the same entity type, use this priority:

1. **Explicit fields** (e.g., `username`) > Nested fields (e.g., `event.user.name`)
2. **Source entity** (e.g., `src_user`) > Destination entity (e.g., `dst_user`)
3. **First occurrence** > Subsequent occurrences

---

## Correlation Scoring Model

### Base Scores

| Match Type | Score | Rationale |
|------------|-------|-----------|
| **Exact user match** | +100 | User owns their alerts |
| **Exact host match** | +80 | Host-specific incidents |
| **User + Host combo** | +150 | Strong ownership signal (bonus, not additive) |
| **MITRE technique overlap** | +40 | Same attack pattern |
| **Same threat object** | +60 | Same malware/hash |
| **Same internal IP** | +30 | Same internal asset |
| **External IOC only** | +10 | Weak signal, many false positives |

### Time Proximity Bonuses

| Time Delta | Bonus | Rationale |
|------------|-------|-----------|
| < 15 minutes | +20 | Likely same attack wave |
| < 1 hour | +10 | Possibly related |
| < 4 hours | +5 | Weak temporal signal |
| > 4 hours | +0 | No bonus |

### Score Modifiers (Penalties)

| Condition | Modifier | Rationale |
|-----------|----------|-----------|
| **Attack type mismatch** | -30 | Don't merge phishing with ransomware |
| **Entity confidence decay** | -10 to -50 | Old entities less reliable |
| **Investigation near capacity** | -20 | Discourage overcrowding |

### Decision Thresholds

| Score Range | Action | Description |
|-------------|--------|-------------|
| **≥ 100** | Auto-link | High confidence, link automatically |
| **60-99** | Soft-link | Flag for analyst review (T2) |
| **< 60** | Create new | Insufficient confidence, new investigation |

### Scoring Formula

```python
def calculate_correlation_score(
 alert_entities: Dict[str, List[str]],
 investigation: Investigation,
 investigation_entities: List[InvestigationEntity]
) -> CorrelationScore:
 """
 Calculate correlation score between alert and investigation.
 """
 score = 0
 reasons = []

 # Build entity lookup for investigation
 inv_entities = {
 (e.entity_type, e.entity_value): e
 for e in investigation_entities
 }

 # Track matched entity types for combo detection
 matched_types = set()

 # === ENTITY MATCHING ===

 # User matching (+100)
 for user in alert_entities.get('user', []):
 if ('user', user) in inv_entities:
 entity = inv_entities[('user', user)]
 decay_penalty = calculate_decay_penalty(entity.last_seen)
 user_score = 100 - decay_penalty
 score += user_score
 matched_types.add('user')
 reasons.append(f"User match ({user}): +{user_score}")

 # Host matching (+80)
 for host in alert_entities.get('host', []):
 if ('host', host) in inv_entities:
 entity = inv_entities[('host', host)]
 decay_penalty = calculate_decay_penalty(entity.last_seen)
 host_score = 80 - decay_penalty
 score += host_score
 matched_types.add('host')
 reasons.append(f"Host match ({host}): +{host_score}")

 # User + Host combo bonus (+150 total, replace individual scores)
 if 'user' in matched_types and 'host' in matched_types:
 # Replace individual scores with combo score
 combo_bonus = 150 - score # Adjust to reach 150 total
 if combo_bonus > 0:
 score += combo_bonus
 reasons.append(f"User+Host combo bonus: +{combo_bonus}")

 # MITRE technique overlap (+40)
 for technique in alert_entities.get('mitre_technique', []):
 if ('mitre_technique', technique) in inv_entities:
 score += 40
 reasons.append(f"MITRE technique match ({technique}): +40")
 break # Only count once

 # Threat object match (+60)
 for threat in alert_entities.get('threat_object', []):
 if ('threat_object', threat) in inv_entities:
 score += 60
 reasons.append(f"Threat object match ({threat}): +60")
 break # Only count once

 # Internal IP match (+30)
 for ip in alert_entities.get('internal_ip', []):
 if ('internal_ip', ip) in inv_entities:
 score += 30
 reasons.append(f"Internal IP match ({ip}): +30")
 break # Only count once

 # External IOC match (+10)
 for ioc in alert_entities.get('external_ioc', []):
 if ('external_ioc', ioc) in inv_entities:
 score += 10
 reasons.append(f"External IOC match ({ioc}): +10")
 break # Only count once

 # === TIME PROXIMITY ===

 time_delta = datetime.utcnow() - investigation.updated_at
 if time_delta < timedelta(minutes=15):
 score += 20
 reasons.append("Time proximity (<15min): +20")
 elif time_delta < timedelta(hours=1):
 score += 10
 reasons.append("Time proximity (<1hr): +10")
 elif time_delta < timedelta(hours=4):
 score += 5
 reasons.append("Time proximity (<4hr): +5")

 # === PENALTIES ===

 # Attack type mismatch penalty
 alert_tactics = get_mitre_tactics(alert_entities.get('mitre_technique', []))
 inv_tactics = get_investigation_tactics(investigation)
 if alert_tactics and inv_tactics and not alert_tactics.intersection(inv_tactics):
 score -= 30
 reasons.append("Attack type mismatch: -30")

 # Near-capacity penalty
 if investigation.alert_count > 150:
 score -= 20
 reasons.append("Investigation near capacity: -20")

 return CorrelationScore(
 score=max(0, score), # Floor at 0
 reasons=reasons,
 matched_entities=list(matched_types)
 )
```

### Decay Calculation

```python
def calculate_decay_penalty(last_seen: datetime) -> int:
 """
 Calculate confidence decay penalty based on time since last seen.

 Decay Schedule:
 0-24 hours: 0 penalty
 24-48 hours: 10 penalty
 48-72 hours: 25 penalty
 72+ hours: 50 penalty (max)
 """
 hours_since = (datetime.utcnow() - last_seen).total_seconds() / 3600

 if hours_since <= 24:
 return 0
 elif hours_since <= 48:
 return 10
 elif hours_since <= 72:
 return 25
 else:
 return 50
```

---

## Guardrails & Safety

### 1. Max Entity Fan-Out

Prevents a single investigation from becoming a catch-all.

| Entity Type | Max Count | Action When Exceeded |
|-------------|-----------|---------------------|
| Users | 5 | Force investigation split |
| Hosts | 10 | Force investigation split |
| Total Alerts | 200 | Soft cap, penalize score |

```python
def check_fanout_guardrail(
 investigation: Investigation,
 alert_entities: Dict[str, List[str]]
) -> GuardrailResult:
 """
 Check if adding this alert would exceed entity fan-out limits.
 """
 current_users = get_entity_count(investigation.id, 'user')
 current_hosts = get_entity_count(investigation.id, 'host')

 new_users = len([u for u in alert_entities.get('user', [])
 if not entity_exists(investigation.id, 'user', u)])
 new_hosts = len([h for h in alert_entities.get('host', [])
 if not entity_exists(investigation.id, 'host', h)])

 if current_users + new_users > MAX_USERS_PER_INVESTIGATION:
 return GuardrailResult(
 blocked=True,
 reason=f"Would exceed max users ({MAX_USERS_PER_INVESTIGATION})",
 action="split_investigation"
 )

 if current_hosts + new_hosts > MAX_HOSTS_PER_INVESTIGATION:
 return GuardrailResult(
 blocked=True,
 reason=f"Would exceed max hosts ({MAX_HOSTS_PER_INVESTIGATION})",
 action="split_investigation"
 )

 return GuardrailResult(blocked=False)
```

### 2. Attack Type Lock

Prevents merging incompatible attack types.

```python
# MITRE Tactic Compatibility Matrix
# Tactics in the same group CAN be merged
COMPATIBLE_TACTIC_GROUPS = [
 # Initial Access + Execution + Persistence (early-stage attacks)
 {'TA0001', 'TA0002', 'TA0003'},

 # Privilege Escalation + Defense Evasion + Credential Access
 {'TA0004', 'TA0005', 'TA0006'},

 # Discovery + Lateral Movement + Collection
 {'TA0007', 'TA0008', 'TA0009'},

 # Command & Control + Exfiltration + Impact (late-stage)
 {'TA0011', 'TA0010', 'TA0040'},
]

def check_attack_type_compatibility(
 alert_techniques: List[str],
 investigation_techniques: List[str]
) -> Tuple[bool, int]:
 """
 Check if alert's attack type is compatible with investigation.

 Returns:
 (is_compatible, score_penalty)
 """
 alert_tactics = get_tactics_for_techniques(alert_techniques)
 inv_tactics = get_tactics_for_techniques(investigation_techniques)

 if not alert_tactics or not inv_tactics:
 return (True, 0) # No data, allow merge

 # Check if any tactic overlaps
 if alert_tactics.intersection(inv_tactics):
 return (True, 0) # Direct overlap

 # Check compatibility groups
 for group in COMPATIBLE_TACTIC_GROUPS:
 if alert_tactics.intersection(group) and inv_tactics.intersection(group):
 return (True, 0) # Same phase of attack

 # Incompatible - apply penalty
 return (False, -30)
```

### 3. Entity Confidence Decay

Prevents old investigations from absorbing unrelated alerts.

```python
# Decay schedule
DECAY_SCHEDULE = {
 24: 0, # 0-24 hours: no decay
 48: 10, # 24-48 hours: 10% decay
 72: 25, # 48-72 hours: 25% decay
 168: 50, # 72+ hours: 50% decay (max)
}

def apply_entity_decay(investigation_id: int) -> None:
 """
 Apply confidence decay to all entities in an investigation.
 Run periodically (e.g., every hour).
 """
 entities = get_investigation_entities(investigation_id)

 for entity in entities:
 hours_since = (datetime.utcnow() - entity.last_seen).total_seconds() / 3600

 new_confidence = entity.confidence
 for threshold_hours, decay_amount in sorted(DECAY_SCHEDULE.items()):
 if hours_since >= threshold_hours:
 new_confidence = max(50, 100 - decay_amount) # Floor at 50

 if new_confidence != entity.confidence:
 update_entity_confidence(entity.id, new_confidence)
```

### 4. Investigation Lifecycle Guardrails

```python
# Investigation states that allow correlation
LINKABLE_STATES = {'NEW', 'ANALYZING', 'INVESTIGATING', 'ENRICHING'}

# Maximum investigation age for auto-linking
MAX_INVESTIGATION_AGE_HOURS = 72

def is_investigation_linkable(investigation: Investigation) -> bool:
 """
 Check if investigation can accept new alerts.
 """
 # State check
 if investigation.state not in LINKABLE_STATES:
 return False

 # Age check
 age_hours = (datetime.utcnow() - investigation.created_at).total_seconds() / 3600
 if age_hours > MAX_INVESTIGATION_AGE_HOURS:
 return False

 # Alert count check (soft limit)
 if investigation.alert_count >= MAX_ALERTS_PER_INVESTIGATION:
 return False

 return True
```

---

## Database Schema

### New Tables

```sql
-- ============================================================
-- ENTITY CORRELATION TABLES
-- ============================================================

-- Investigation Entities: Links entities to investigations
CREATE TABLE investigation_entities (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
 entity_type VARCHAR(50) NOT NULL,
 entity_value VARCHAR(500) NOT NULL,
 confidence INTEGER DEFAULT 100 CHECK (confidence >= 0 AND confidence <= 100),
 alert_count INTEGER DEFAULT 1,
 first_seen TIMESTAMPTZ DEFAULT NOW(),
 last_seen TIMESTAMPTZ DEFAULT NOW(),
 source_alert_id UUID,
 metadata JSONB DEFAULT '{}',

 UNIQUE(investigation_id, entity_type, entity_value)
);

-- Indexes for fast lookup
CREATE INDEX idx_inv_entity_lookup ON investigation_entities(entity_type, entity_value);
CREATE INDEX idx_inv_entity_investigation ON investigation_entities(investigation_id);
CREATE INDEX idx_inv_entity_confidence ON investigation_entities(confidence DESC);
CREATE INDEX idx_inv_entity_last_seen ON investigation_entities(last_seen DESC);

-- Correlation Decisions: Audit log for all correlation decisions
CREATE TABLE correlation_decisions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 alert_id UUID NOT NULL,
 decision_type VARCHAR(20) NOT NULL CHECK (decision_type IN ('auto_link', 'soft_link', 'create_new')),
 investigation_id INTEGER REFERENCES investigations(id),
 score INTEGER NOT NULL,
 threshold INTEGER NOT NULL,
 reasons JSONB NOT NULL DEFAULT '[]',
 matched_entities JSONB NOT NULL DEFAULT '[]',
 guardrails_applied JSONB DEFAULT '[]',
 created_at TIMESTAMPTZ DEFAULT NOW(),

 -- Ensure every alert has a decision
 UNIQUE(alert_id)
);

CREATE INDEX idx_corr_decision_alert ON correlation_decisions(alert_id);
CREATE INDEX idx_corr_decision_investigation ON correlation_decisions(investigation_id);
CREATE INDEX idx_corr_decision_type ON correlation_decisions(decision_type);

-- Entity Type Reference (for validation)
CREATE TABLE entity_types (
 type_code VARCHAR(50) PRIMARY KEY,
 display_name VARCHAR(100) NOT NULL,
 priority INTEGER NOT NULL,
 base_score INTEGER NOT NULL,
 description TEXT
);

-- Seed entity types
INSERT INTO entity_types (type_code, display_name, priority, base_score, description) VALUES
 ('user', 'User Account', 1, 100, 'User/account identifier'),
 ('host', 'Host/System', 2, 80, 'Hostname or computer name'),
 ('mitre_technique', 'MITRE Technique', 3, 40, 'MITRE ATT&CK technique ID'),
 ('threat_object', 'Threat Object', 4, 60, 'Malware hash or family'),
 ('internal_ip', 'Internal IP', 5, 30, 'RFC1918 private IP address'),
 ('external_ioc', 'External IOC', 6, 10, 'External IP, domain, or URL');
```

### Modifications to Existing Tables

```sql
-- Add entity tracking to investigations
ALTER TABLE investigations
ADD COLUMN IF NOT EXISTS entity_summary JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS correlation_locked BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS primary_entity_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS primary_entity_value VARCHAR(500);

-- Add correlation metadata to alerts
ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS extracted_entities JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS correlation_score INTEGER,
ADD COLUMN IF NOT EXISTS correlation_reason TEXT;
```

---

## Correlation Flow

### Complete Flow Diagram

```

 STEP 1: ALERT ARRIVES 
 Input: Raw alert from webhook/SIEM 

 
 

 STEP 2: ENTITY EXTRACTION 
 
 extract_entities(alert) → { 
 'user': ['jsmith'], 
 'host': ['workstation-123'], 
 'mitre_technique': ['T1566.001'], 
 'threat_object': [], 
 'internal_ip': ['192.168.1.50'], 
 'external_ioc': ['evil.com'] 
 } 

 
 

 STEP 3: FIND CANDIDATE INVESTIGATIONS 
 
 SELECT DISTINCT investigation_id FROM investigation_entities 
 WHERE (entity_type, entity_value) IN ( 
 ('user', 'jsmith'), 
 ('host', 'workstation-123'), 
 ... 
 ) 
 AND investigation_id IN ( 
 SELECT id FROM investigations 
 WHERE state IN ('NEW', 'ANALYZING', 'INVESTIGATING') 
 AND created_at > NOW() - INTERVAL '72 hours' 
 ) 

 
 

 STEP 4: SCORE EACH CANDIDATE 
 
 Investigation #42: 
 - User 'jsmith' match: +100 
 - Host 'workstation-123' match: +80 
 - User+Host combo bonus: -30 (already counted) → Total: +150 
 - Time proximity: +20 
 - Total: 170 
 
 Investigation #55: 
 - External IOC 'evil.com' match: +10 
 - Total: 10 

 
 

 STEP 5: APPLY GUARDRAILS 
 
 Investigation #42: 
 User count (3) < max (5) 
 Host count (5) < max (10) 
 Attack type compatible 
 Entity confidence above threshold 
 → PASSED 

 
 

 STEP 6: MAKE DECISION 
 
 Best match: Investigation #42 with score 170 
 Threshold: 100 
 Decision: AUTO_LINK 

 
 

 STEP 7: EXECUTE DECISION 
 
 1. UPDATE alerts SET investigation_id = 42 WHERE id = $alert_id 
 2. INSERT INTO investigation_entities (new entities from alert) 
 3. UPDATE investigation_entities SET last_seen = NOW() (existing matches) 
 4. UPDATE investigations SET alert_count = alert_count + 1 

 
 

 STEP 8: LOG DECISION (EXPLAINABILITY) 
 
 INSERT INTO correlation_decisions ( 
 alert_id: 'abc-123', 
 decision_type: 'auto_link', 
 investigation_id: 42, 
 score: 170, 
 threshold: 100, 
 reasons: [ 
 "User match (jsmith): +100", 
 "Host match (workstation-123): +80", 
 "User+Host combo bonus: adjusted to +150", 
 "Time proximity (<15min): +20" 
 ], 
 matched_entities: ['user', 'host'] 
 ) 

```

---

## API Reference

### EntityCorrelationService

```python
class EntityCorrelationService:
 """
 Central correlation engine for entity-based alert grouping.
 """

 async def correlate_alert(
 self,
 alert_id: str,
 alert_data: Dict[str, Any]
 ) -> CorrelationResult:
 """
 Main entry point for correlating an alert.

 Args:
 alert_id: Unique alert identifier
 alert_data: Full alert data dictionary

 Returns:
 CorrelationResult with decision, score, and reasons
 """

 async def extract_entities(
 self,
 alert_data: Dict[str, Any]
 ) -> Dict[str, List[str]]:
 """
 Extract and normalize entities from alert.

 Returns:
 Dict mapping entity_type to list of normalized values
 """

 async def find_candidate_investigations(
 self,
 entities: Dict[str, List[str]]
 ) -> List[Investigation]:
 """
 Find open investigations that share any extracted entities.
 """

 async def score_investigation(
 self,
 alert_entities: Dict[str, List[str]],
 investigation: Investigation
 ) -> CorrelationScore:
 """
 Calculate correlation score between alert and investigation.
 """

 async def apply_guardrails(
 self,
 investigation: Investigation,
 alert_entities: Dict[str, List[str]],
 score: CorrelationScore
 ) -> GuardrailResult:
 """
 Apply all guardrails and return result.
 """
```

### Data Classes

```python
@dataclass
class CorrelationResult:
 """Result of correlation decision."""
 decision: str # 'auto_link', 'soft_link', 'create_new'
 investigation_id: Optional[int]
 score: int
 threshold: int
 reasons: List[str]
 matched_entities: List[str]
 guardrails_applied: List[str]

@dataclass
class CorrelationScore:
 """Detailed scoring breakdown."""
 score: int
 reasons: List[str]
 matched_entities: List[str]
 time_bonus: int
 penalties: List[str]

@dataclass
class GuardrailResult:
 """Result of guardrail checks."""
 blocked: bool
 reason: Optional[str]
 action: Optional[str] # 'split_investigation', 'create_new', etc.
```

---

## Examples & Scenarios

### Scenario 1: Same User, Same Host (Auto-Link)

**Alert:**
```json
{
 "title": "Suspicious PowerShell execution",
 "user": "jsmith",
 "hostname": "WORKSTATION-123",
 "technique_id": "T1059.001"
}
```

**Existing Investigation #42:**
- Entities: `user:jsmith`, `host:workstation-123`, `mitre_technique:T1566.001`
- Created: 30 minutes ago

**Scoring:**
| Match | Score |
|-------|-------|
| User match (jsmith) | +100 |
| Host match (workstation-123) | +80 |
| User+Host combo | (adjusted to +150 total) |
| Time proximity (<1hr) | +10 |
| **Total** | **160** |

**Decision:** `AUTO_LINK` (160 ≥ 100)

**Explainability Output:**
```
Alert linked to Investigation #42 because:
- User match (jsmith): +100
- Host match (workstation-123): +80
- User+Host combo bonus: adjusted to +150
- Time proximity (<1hr): +10
- Total Score: 160 (threshold: 100)
```

---

### Scenario 2: IOC-Only Match (Create New)

**Alert:**
```json
{
 "title": "C2 beacon detected",
 "src_ip": "10.0.0.50",
 "dst_ip": "185.234.72.10",
 "user": "admin_svc"
}
```

**Existing Investigation #55:**
- Entities: `external_ioc:185.234.72.10` (from a different user/host)
- Different user: `marketing_user`
- Different host: `laptop-456`

**Scoring:**
| Match | Score |
|-------|-------|
| External IOC match | +10 |
| No user match | +0 |
| No host match | +0 |
| **Total** | **10** |

**Decision:** `CREATE_NEW` (10 < 60)

**Explainability Output:**
```
New investigation created for alert because:
- Best match score: 10 (Investigation #55)
- External IOC match (185.234.72.10): +10
- No user/host match - IOC alone insufficient
- Score 10 below threshold 60
- New investigation created with primary entity: user:admin_svc
```

---

### Scenario 3: Guardrail Triggered (Split Required)

**Alert:**
```json
{
 "title": "Brute force attempt",
 "user": "new_victim",
 "hostname": "server-prod-01"
}
```

**Existing Investigation #30:**
- Already has 5 users: `user1`, `user2`, `user3`, `user4`, `user5`
- Score would be 80 (host match only)

**Guardrail Check:**
```
Current users: 5
New users to add: 1 (new_victim)
Total would be: 6
Max allowed: 5
GUARDRAIL TRIGGERED
```

**Decision:** `CREATE_NEW` (guardrail override)

**Explainability Output:**
```
New investigation created for alert because:
- Would link to Investigation #30 (score: 80)
- GUARDRAIL: Max users exceeded (5/5, adding new_victim would be 6)
- Action: Created new investigation to prevent over-correlation
- New investigation #67 created with entities: user:new_victim, host:server-prod-01
```

---

### Scenario 4: Attack Type Mismatch (Penalty Applied)

**Alert:**
```json
{
 "title": "Ransomware detected",
 "user": "jsmith",
 "technique_id": "T1486"
}
```

**Existing Investigation #42:**
- Entities: `user:jsmith`, `mitre_technique:T1566.001` (phishing)
- Attack phase: Initial Access (TA0001)

**Alert Attack Phase:** Impact (TA0040)

**Scoring:**
| Match | Score |
|-------|-------|
| User match (jsmith) | +100 |
| Attack type mismatch | -30 |
| **Total** | **70** |

**Decision:** `SOFT_LINK` (60 ≤ 70 < 100)

**Explainability Output:**
```
Alert soft-linked to Investigation #42 (requires analyst review):
- User match (jsmith): +100
- Attack type mismatch (Impact vs Initial Access): -30
- Total Score: 70 (soft-link threshold: 60-99)
- Reason for review: Different attack phases detected
```

---

## Troubleshooting

### Common Issues

#### 1. Too Many Investigations Created

**Symptom:** Each alert creates a new investigation.

**Causes:**
- Entity extraction not working (check `extracted_entities` column)
- No open investigations in linkable state
- Entities not normalized correctly

**Debug:**
```sql
-- Check entity extraction
SELECT id, extracted_entities FROM alerts ORDER BY created_at DESC LIMIT 10;

-- Check investigation states
SELECT state, COUNT(*) FROM investigations GROUP BY state;

-- Check entity matches
SELECT * FROM investigation_entities WHERE entity_value = 'jsmith';
```

#### 2. Too Few Investigations (Over-Correlation)

**Symptom:** Alerts collapsing into few investigations.

**Causes:**
- Guardrails not enforced
- Entity too generic (e.g., `SYSTEM` user)
- Decay not applied

**Debug:**
```sql
-- Check entity distribution
SELECT investigation_id, entity_type, COUNT(DISTINCT entity_value)
FROM investigation_entities
GROUP BY investigation_id, entity_type
ORDER BY COUNT(DISTINCT entity_value) DESC;

-- Check for generic entities
SELECT entity_value, COUNT(*)
FROM investigation_entities
WHERE entity_type = 'user'
GROUP BY entity_value
ORDER BY COUNT(*) DESC;
```

#### 3. Decay Not Working

**Symptom:** Old investigations keep absorbing alerts.

**Check:**
```sql
-- Check entity confidence levels
SELECT entity_value, confidence, last_seen,
 EXTRACT(EPOCH FROM (NOW() - last_seen))/3600 as hours_since
FROM investigation_entities
ORDER BY last_seen ASC;
```

**Fix:** Ensure decay job is running:
```bash
# Check if decay job is scheduled
docker logs t1agentics-backend | grep "entity_decay"
```

---

## Configuration

### Environment Variables

```bash
# Correlation thresholds
CORRELATION_AUTO_LINK_THRESHOLD=100
CORRELATION_SOFT_LINK_THRESHOLD=60

# Guardrail limits
MAX_USERS_PER_INVESTIGATION=5
MAX_HOSTS_PER_INVESTIGATION=10
MAX_ALERTS_PER_INVESTIGATION=200

# Decay settings
ENTITY_DECAY_ENABLED=true
ENTITY_DECAY_24H_PENALTY=10
ENTITY_DECAY_48H_PENALTY=25
ENTITY_DECAY_72H_PENALTY=50

# Investigation age limit
MAX_INVESTIGATION_AGE_HOURS=72
```

### Scoring Weights (Tunable)

```python
# In entity_correlation_service.py
SCORING_WEIGHTS = {
 'user': 100,
 'host': 80,
 'user_host_combo': 150,
 'mitre_technique': 40,
 'threat_object': 60,
 'internal_ip': 30,
 'external_ioc': 10,
 'time_15m': 20,
 'time_1h': 10,
 'time_4h': 5,
 'attack_mismatch_penalty': -30,
 'near_capacity_penalty': -20,
}
```

---

## Appendix: MITRE Tactic Mapping

```python
TECHNIQUE_TO_TACTIC = {
 # Initial Access (TA0001)
 'T1566': 'TA0001', 'T1566.001': 'TA0001', 'T1566.002': 'TA0001',
 'T1190': 'TA0001', 'T1078': 'TA0001',

 # Execution (TA0002)
 'T1059': 'TA0002', 'T1059.001': 'TA0002', 'T1059.003': 'TA0002',
 'T1204': 'TA0002',

 # Persistence (TA0003)
 'T1547': 'TA0003', 'T1547.001': 'TA0003',
 'T1053': 'TA0003', 'T1053.005': 'TA0003',

 # Privilege Escalation (TA0004)
 'T1548': 'TA0004', 'T1134': 'TA0004',

 # Defense Evasion (TA0005)
 'T1027': 'TA0005', 'T1562': 'TA0005',

 # Credential Access (TA0006)
 'T1003': 'TA0006', 'T1110': 'TA0006',

 # Discovery (TA0007)
 'T1046': 'TA0007', 'T1057': 'TA0007', 'T1082': 'TA0007',

 # Lateral Movement (TA0008)
 'T1021': 'TA0008', 'T1021.001': 'TA0008', 'T1021.004': 'TA0008',

 # Collection (TA0009)
 'T1113': 'TA0009', 'T1074': 'TA0009',

 # Exfiltration (TA0010)
 'T1041': 'TA0010', 'T1048': 'TA0010',

 # Command and Control (TA0011)
 'T1071': 'TA0011',

 # Impact (TA0040)
 'T1486': 'TA0040', 'T1485': 'TA0040',
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-01-16*
*Author: T1 Agentics Engineering*
