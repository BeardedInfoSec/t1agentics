# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Web Forms Models
Define form schemas, field types, and submission structures
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


class FieldType(str, Enum):
    """Form field types"""
    TEXT = "text"
    TEXTAREA = "textarea"
    EMAIL = "email"
    NUMBER = "number"
    SELECT = "select"
    MULTISELECT = "multiselect"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    DATE = "date"
    DATETIME = "datetime"
    FILE = "file"
    HIDDEN = "hidden"


class FormFieldValidation(BaseModel):
    """Validation rules for form fields"""
    required: bool = False
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None  # Regex pattern
    custom_message: Optional[str] = None


class FormField(BaseModel):
    """Individual form field definition"""
    field_id: str
    field_type: FieldType
    label: str
    placeholder: Optional[str] = None
    default_value: Optional[Any] = None
    help_text: Optional[str] = None
    options: Optional[List[str]] = None  # For select, radio, checkbox
    validation: FormFieldValidation = Field(default_factory=FormFieldValidation)
    order: int = 0
    width: Literal["full", "half", "third"] = "full"
    conditional_logic: Optional[Dict[str, Any]] = None  # Show/hide based on other fields


class FormOutputConfig(BaseModel):
    """Configuration for form submission output"""
    create_alert: bool = True
    alert_title_template: Optional[str] = None
    alert_severity: Literal["low", "medium", "high", "critical"] = "medium"
    webhook_url: Optional[str] = None
    webhook_method: Literal["POST", "PUT"] = "POST"
    webhook_headers: Optional[Dict[str, str]] = None
    email_notification: Optional[str] = None
    custom_script: Optional[str] = None


class WebForm(BaseModel):
    """Complete web form definition"""
    form_id: str
    title: str
    description: Optional[str] = None
    fields: List[FormField]
    output_config: FormOutputConfig
    is_public: bool = False
    require_auth: bool = True
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    submission_count: int = 0
    is_active: bool = True
    theme: Literal["light", "dark", "auto"] = "dark"
    custom_css: Optional[str] = None
    success_message: str = "Form submitted successfully!"
    redirect_url: Optional[str] = None


class FormSubmission(BaseModel):
    """Form submission data"""
    submission_id: str
    form_id: str
    form_title: str
    data: Dict[str, Any]
    files: Optional[List[str]] = None  # File paths/URLs
    submitted_by: Optional[str] = None  # User if authenticated
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    alert_created: bool = False
    alert_id: Optional[str] = None
    webhook_sent: bool = False
    webhook_response: Optional[Dict[str, Any]] = None
    status: Literal["pending", "processed", "failed"] = "pending"
    processing_errors: Optional[List[str]] = None


class FormTemplate(BaseModel):
    """Pre-built form template"""
    template_id: str
    name: str
    description: str
    category: Literal["incident", "investigation", "threat_report", "vulnerability", "general"]
    icon: str
    form_config: Dict[str, Any]  # Serialized form configuration
    preview_image: Optional[str] = None


# Pre-built form templates
FORM_TEMPLATES = [
    {
        "template_id": "incident_report",
        "name": "Security Incident Report",
        "description": "Report a security incident with all necessary details",
        "category": "incident",
        "icon": "[INCIDENT]",
        "fields": [
            {
                "field_id": "incident_title",
                "field_type": "text",
                "label": "Incident Title",
                "placeholder": "Brief description of the incident",
                "validation": {"required": True, "max_length": 200},
                "order": 1,
                "width": "full"
            },
            {
                "field_id": "severity",
                "field_type": "select",
                "label": "Severity",
                "options": ["Low", "Medium", "High", "Critical"],
                "validation": {"required": True},
                "order": 2,
                "width": "half"
            },
            {
                "field_id": "incident_date",
                "field_type": "datetime",
                "label": "When did this occur?",
                "validation": {"required": True},
                "order": 3,
                "width": "half"
            },
            {
                "field_id": "description",
                "field_type": "textarea",
                "label": "Detailed Description",
                "placeholder": "Provide all relevant details about the incident...",
                "validation": {"required": True, "min_length": 50},
                "order": 4,
                "width": "full"
            },
            {
                "field_id": "affected_systems",
                "field_type": "textarea",
                "label": "Affected Systems/Users",
                "placeholder": "List impacted systems, servers, users, etc.",
                "order": 5,
                "width": "full"
            },
            {
                "field_id": "indicators",
                "field_type": "textarea",
                "label": "Indicators of Compromise (IOCs)",
                "placeholder": "IPs, domains, file hashes, URLs, etc.",
                "help_text": "One per line",
                "order": 6,
                "width": "full"
            },
            {
                "field_id": "evidence",
                "field_type": "file",
                "label": "Evidence Files",
                "help_text": "Screenshots, logs, malware samples (password protected)",
                "order": 7,
                "width": "full"
            },
            {
                "field_id": "reporter_name",
                "field_type": "text",
                "label": "Your Name",
                "validation": {"required": True},
                "order": 8,
                "width": "half"
            },
            {
                "field_id": "reporter_email",
                "field_type": "email",
                "label": "Your Email",
                "validation": {"required": True},
                "order": 9,
                "width": "half"
            }
        ]
    },
    {
        "template_id": "phishing_report",
        "name": "Phishing Email Report",
        "description": "Report suspicious emails and phishing attempts",
        "category": "threat_report",
        "icon": "🎣",
        "fields": [
            {
                "field_id": "email_subject",
                "field_type": "text",
                "label": "Email Subject",
                "validation": {"required": True},
                "order": 1,
                "width": "full"
            },
            {
                "field_id": "sender_email",
                "field_type": "email",
                "label": "Sender Email Address",
                "validation": {"required": True},
                "order": 2,
                "width": "half"
            },
            {
                "field_id": "received_date",
                "field_type": "datetime",
                "label": "When did you receive this?",
                "validation": {"required": True},
                "order": 3,
                "width": "half"
            },
            {
                "field_id": "email_body",
                "field_type": "textarea",
                "label": "Email Content",
                "placeholder": "Copy/paste the email content here",
                "order": 4,
                "width": "full"
            },
            {
                "field_id": "suspicious_links",
                "field_type": "textarea",
                "label": "Suspicious Links/URLs",
                "help_text": "One per line",
                "order": 5,
                "width": "full"
            },
            {
                "field_id": "clicked_link",
                "field_type": "radio",
                "label": "Did you click any links?",
                "options": ["No", "Yes"],
                "validation": {"required": True},
                "order": 6,
                "width": "full"
            },
            {
                "field_id": "provided_credentials",
                "field_type": "radio",
                "label": "Did you provide any credentials?",
                "options": ["No", "Yes"],
                "validation": {"required": True},
                "order": 7,
                "width": "full"
            },
            {
                "field_id": "screenshot",
                "field_type": "file",
                "label": "Screenshot (Optional)",
                "order": 8,
                "width": "full"
            }
        ]
    },
    {
        "template_id": "vulnerability_report",
        "name": "Vulnerability Report",
        "description": "Report discovered vulnerabilities",
        "category": "vulnerability",
        "icon": "🔓",
        "fields": [
            {
                "field_id": "vuln_title",
                "field_type": "text",
                "label": "Vulnerability Title",
                "validation": {"required": True},
                "order": 1,
                "width": "full"
            },
            {
                "field_id": "cve_id",
                "field_type": "text",
                "label": "CVE ID (if known)",
                "placeholder": "CVE-2024-12345",
                "order": 2,
                "width": "half"
            },
            {
                "field_id": "cvss_score",
                "field_type": "number",
                "label": "CVSS Score",
                "validation": {"min_value": 0, "max_value": 10},
                "order": 3,
                "width": "half"
            },
            {
                "field_id": "affected_system",
                "field_type": "text",
                "label": "Affected System/Application",
                "validation": {"required": True},
                "order": 4,
                "width": "full"
            },
            {
                "field_id": "description",
                "field_type": "textarea",
                "label": "Vulnerability Description",
                "validation": {"required": True},
                "order": 5,
                "width": "full"
            },
            {
                "field_id": "remediation",
                "field_type": "textarea",
                "label": "Recommended Remediation",
                "order": 6,
                "width": "full"
            }
        ]
    }
]
