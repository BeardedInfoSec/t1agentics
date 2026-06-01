# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Intake Forms Service

Validation and alert-pipeline handoff for form submissions. Form CRUD itself
is handled inline in routes/intake_forms.py (matches the playbooks convention).

Design (2026-05-05):
- Forms are tenant-scoped, authenticated. No anonymous submissions.
- A submission renders the form's `alert_template` against the submitted
  payload, then hands the resulting Alert to the existing alert ingestion
  function so Riggs/triage/enrichment all run as they do for any source.
- Template rendering uses simple {{field_key}} substitution. No expressions,
  no code execution.
"""

import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

VALID_FIELD_TYPES = {
    "text", "textarea", "email", "url",
    "select", "multiselect", "file", "datetime",
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Form slug: 16 url-safe chars, ~96 bits of entropy. Not guessable.
SLUG_BYTES = 12

_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def _slugify(text: str) -> str:
    """
    Turn an arbitrary string into a url-safe slug.

    - Lowercase
    - Spaces -> hyphens
    - Strip anything that isn't a-z, 0-9, hyphen
    - Collapse repeated hyphens and trim leading/trailing
    - Cap at 60 chars so the URL stays sane
    """
    s = (text or "").lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:60]


def generate_slug(name: Optional[str] = None) -> str:
    """
    URL slug for a form. Prefers a slugified version of the form name
    (e.g. "Phishing Report" -> "phishing-report"); appends a short
    random suffix for collision resistance + so the slug isn't trivially
    guessable across tenants. Falls back to fully random when no name
    is supplied (legacy callers).

    Examples:
        generate_slug("Phishing Report")     -> "phishing-report-a3k7"
        generate_slug("Suspicious File")     -> "suspicious-file-9m2x"
        generate_slug("")                    -> "8kQWD96jorOVoxi6"
    """
    if name:
        base = _slugify(name)
        if base:
            # 4-char random suffix gives ~1M combinations per slug base,
            # plenty to dodge same-name collisions and keep URLs short.
            suffix = secrets.token_urlsafe(3)[:4].lower().replace("_", "0").replace("-", "0")
            return f"{base}-{suffix}"
    return secrets.token_urlsafe(SLUG_BYTES)


def validate_field_schema(fields: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Light validation of a form's field schema. Returns (ok, error_message)."""
    if not isinstance(fields, list):
        return False, "fields must be a list"
    keys_seen = set()
    for idx, f in enumerate(fields):
        if not isinstance(f, dict):
            return False, f"field {idx} is not an object"
        key = f.get("key")
        if not key or not isinstance(key, str):
            return False, f"field {idx} missing string 'key'"
        if not re.match(r"^[a-z][a-z0-9_]*$", key):
            return False, f"field '{key}' must be snake_case (start with a letter)"
        if key in keys_seen:
            return False, f"duplicate field key: {key}"
        keys_seen.add(key)
        if not f.get("label"):
            return False, f"field '{key}' missing label"
        ftype = f.get("type")
        if ftype not in VALID_FIELD_TYPES:
            return False, f"field '{key}' has unsupported type: {ftype}"
        if ftype in ("select", "multiselect"):
            opts = f.get("options")
            if not isinstance(opts, list) or not opts:
                return False, f"field '{key}' (type {ftype}) needs non-empty 'options'"
    return True, None


def validate_payload(
    fields: List[Dict[str, Any]],
    payload: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Validate a submitted payload against a form's field schema.
    Returns (ok, error_message). Type-coerces nothing; expects the caller to
    have already deserialized JSON.
    """
    if not isinstance(payload, dict):
        return False, "payload must be an object"

    field_map = {f["key"]: f for f in fields}

    # Required-field check
    for key, fdef in field_map.items():
        if not fdef.get("required"):
            continue
        v = payload.get(key)
        if v is None or (isinstance(v, str) and not v.strip()) or (isinstance(v, list) and not v):
            return False, f"required field missing: {key}"

    # Per-field type check (lightweight; fuller validation is a P2)
    for key, value in payload.items():
        fdef = field_map.get(key)
        if not fdef:
            return False, f"unknown field: {key}"
        ftype = fdef["type"]
        if value is None:
            continue
        if ftype in ("text", "textarea", "email", "url", "datetime") and not isinstance(value, str):
            return False, f"field '{key}' must be a string"
        if ftype == "select" and not isinstance(value, str):
            return False, f"field '{key}' (select) must be a string"
        if ftype == "multiselect" and not (
            isinstance(value, list) and all(isinstance(v, str) for v in value)
        ):
            return False, f"field '{key}' (multiselect) must be an array of strings"
        if ftype == "file":
            # File fields hold an attachment id (string) once uploaded; bytes
            # never travel through the JSON payload.
            if not isinstance(value, str):
                return False, f"field '{key}' (file) must be an attachment id string"
        if ftype in ("select", "multiselect"):
            options = fdef.get("options", [])
            allowed = {o["value"] if isinstance(o, dict) else o for o in options}
            chosen = [value] if ftype == "select" else value
            for c in chosen:
                if c not in allowed:
                    return False, f"field '{key}': value '{c}' not in allowed options"

    return True, None


def render_template(template: str, payload: Dict[str, Any]) -> str:
    """
    Replace {{field_key}} tokens in `template` with values from `payload`.
    Missing keys render as empty string. No expression evaluation.
    """
    if not template:
        return ""

    def repl(m: re.Match) -> str:
        key = m.group(1)
        value = payload.get(key, "")
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        return str(value) if value is not None else ""

    return _TEMPLATE_PATTERN.sub(repl, template)


def build_alert_dict(
    *,
    form: Dict[str, Any],
    submission_id: str,
    payload: Dict[str, Any],
    submitted_by: str,
) -> Dict[str, Any]:
    """
    Produce the Alert payload for /api/v1/alerts/ingest based on the form's
    alert_template and the submitted data.

    The template fields supported (all optional):
      title, description, severity, source, category
    Every template field can use {{field_key}} substitution.
    """
    tpl = form.get("alert_template") or {}

    title = render_template(tpl.get("title", ""), payload).strip()
    if not title:
        title = f"Intake form submission: {form.get('name', 'untitled form')}"

    description = render_template(tpl.get("description", ""), payload).strip() or None

    severity = (tpl.get("severity") or "medium").lower()
    if severity not in VALID_SEVERITIES:
        severity = "medium"

    source = tpl.get("source") or "intake_form"
    category = render_template(tpl.get("category", ""), payload).strip() or None

    alert_dict: Dict[str, Any] = {
        "title": title,
        "severity": severity,
        "source": source,
        "metadata": {
            "intake_form_id": str(form["id"]),
            "intake_form_name": form.get("name"),
            "intake_form_slug": form.get("slug"),
            "form_submission_id": submission_id,
            "submitted_by": submitted_by,
        },
        # Stash the full submitted payload so analysts can see what the user
        # actually entered when they open the resulting case.
        "raw_event": {
            "form_submission": {
                "form_id": str(form["id"]),
                "form_name": form.get("name"),
                "submission_id": submission_id,
                "submitted_by": submitted_by,
                "payload": payload,
            },
        },
    }

    if description:
        alert_dict["description"] = description
    if category:
        alert_dict["category"] = category

    return alert_dict


def build_executive_summary(
    form: Dict[str, Any],
    payload: Dict[str, Any],
    submitted_by: str,
) -> str:
    """
    Deterministic executive summary for an investigation auto-created from
    an intake submission. No LLM — just structured field-by-field render so
    the analyst sees what was submitted without opening Raw Log.

    Skips empty values and file-type fields (those are surfaced as attachments
    elsewhere). Length-capped at 1500 chars so it fits the column nicely.
    """
    form_name = form.get('name') or form.get('title') or 'intake form'
    lines = [f"Submitted via {form_name} by {submitted_by}.", ""]

    field_specs = form.get('fields') or []
    for spec in field_specs:
        if not isinstance(spec, dict):
            continue
        key = spec.get('key')
        if not key or spec.get('type') == 'file':
            continue
        value = payload.get(key)
        if value is None or value == '' or (isinstance(value, list) and not value):
            continue
        label = spec.get('label') or key
        if isinstance(value, list):
            value_str = ', '.join(str(v) for v in value)
        else:
            value_str = str(value)
        # Trim absurdly long free-text textareas
        if len(value_str) > 400:
            value_str = value_str[:400].rstrip() + '…'
        lines.append(f"- **{label}**: {value_str}")

    summary = "\n".join(lines).strip()
    if len(summary) > 1500:
        summary = summary[:1497].rstrip() + '...'
    return summary
