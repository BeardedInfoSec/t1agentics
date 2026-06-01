# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Webform Service

Handles webform creation, validation, and submission for playbook execution.
Supports:
- Form templates with various field types
- Form validation
- Public form submission
- File uploads with forms
- Playbook execution resumption after submission
"""

import json
import logging
import uuid
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, validator
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Models
# ============================================================================

class FieldType(str, Enum):
    TEXT = "text"
    TEXTAREA = "textarea"
    NUMBER = "number"
    EMAIL = "email"
    SELECT = "select"
    MULTISELECT = "multiselect"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    DATE = "date"
    DATETIME = "datetime"
    FILE = "file"
    HIDDEN = "hidden"


class FormField(BaseModel):
    """Definition of a form field."""
    name: str
    label: str
    type: FieldType = FieldType.TEXT
    required: bool = False
    default: Optional[Any] = None
    placeholder: Optional[str] = None
    help_text: Optional[str] = None
    options: Optional[List[Dict[str, str]]] = None  # For select/radio/checkbox
    validation: Optional[Dict[str, Any]] = None  # pattern, min, max, etc.

    @validator('options', always=True)
    def validate_options(cls, v, values):
        field_type = values.get('type')
        if field_type in [FieldType.SELECT, FieldType.MULTISELECT, FieldType.RADIO]:
            if not v or len(v) == 0:
                raise ValueError(f"Options required for {field_type} field")
        return v


class FormDefinition(BaseModel):
    """Complete form definition."""
    name: str
    description: Optional[str] = None
    fields: List[FormField]
    submit_label: str = "Submit"
    success_message: str = "Form submitted successfully"
    expires_in_minutes: int = 60


class FormSubmission(BaseModel):
    """Submitted form data."""
    form_data: Dict[str, Any]
    submitted_by: Optional[str] = None
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
    files: List[Dict[str, Any]] = Field(default_factory=list)


class PublicFormContext(BaseModel):
    """Context for rendering a public form."""
    form_id: str
    execution_id: str
    node_id: str
    form_definition: FormDefinition
    prefilled_data: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None
    is_expired: bool = False
    already_submitted: bool = False


# ============================================================================
# Webform Service
# ============================================================================

class WebformService:
    """
    Service for managing webforms in playbook execution.
    """

    def __init__(self):
        pass

    # ========================================================================
    # Form CRUD
    # ========================================================================

    async def create_form(
        self,
        name: str,
        fields: List[Dict[str, Any]],
        tenant_id: str,
        description: str = None,
        submit_label: str = "Submit",
        created_by: str = None,
    ) -> Dict[str, Any]:
        """
        Create a reusable form template.

        Args:
            name: Form name
            fields: List of field definitions
            description: Form description
            submit_label: Submit button text
            created_by: User ID of creator

        Returns:
            Created form record
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            # Validate fields
            validated_fields = []
            for field in fields:
                try:
                    validated = FormField(**field)
                    validated_fields.append(validated.dict())
                except Exception as e:
                    return {"error": f"Invalid field '{field.get('name', 'unknown')}': {str(e)}"}

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO playbook_forms (tenant_id, name, description, fields, submit_label, created_by)
                    VALUES ($1::uuid, $2, $3, $4, $5, $6)
                    RETURNING *
                ''',
                    str(tenant_id),
                    name,
                    description,
                    json.dumps(validated_fields),
                    submit_label,
                    uuid.UUID(created_by) if created_by else None
                )

            logger.info(f"Created form: {name} ({row['id']})")

            return self._row_to_dict(row)

        except Exception as e:
            logger.error(f"Failed to create form: {e}")
            return {"error": str(e)}

    async def get_form(self, form_id: str) -> Optional[Dict[str, Any]]:
        """Get form by ID."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return None

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM playbook_forms WHERE id = $1",
                    uuid.UUID(form_id)
                )

            return self._row_to_dict(row) if row else None

        except Exception as e:
            logger.error(f"Failed to get form {form_id}: {e}")
            return None

    async def get_form_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get form by name."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return None

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM playbook_forms WHERE name = $1",
                    name
                )

            return self._row_to_dict(row) if row else None

        except Exception as e:
            logger.error(f"Failed to get form by name {name}: {e}")
            return None

    async def list_forms(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List all forms."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return []

            async with postgres_db.tenant_acquire() as conn:
                rows = await conn.fetch('''
                    SELECT * FROM playbook_forms
                    ORDER BY created_at DESC
                    LIMIT $1 OFFSET $2
                ''', limit, offset)

            return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to list forms: {e}")
            return []

    async def update_form(
        self,
        form_id: str,
        name: str = None,
        fields: List[Dict[str, Any]] = None,
        description: str = None,
        submit_label: str = None
    ) -> Dict[str, Any]:
        """Update a form."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            updates = []
            params = []
            param_num = 1

            if name is not None:
                updates.append(f"name = ${param_num}")
                params.append(name)
                param_num += 1

            if description is not None:
                updates.append(f"description = ${param_num}")
                params.append(description)
                param_num += 1

            if fields is not None:
                # Validate fields
                validated_fields = []
                for field in fields:
                    validated = FormField(**field)
                    validated_fields.append(validated.dict())
                updates.append(f"fields = ${param_num}")
                params.append(json.dumps(validated_fields))
                param_num += 1

            if submit_label is not None:
                updates.append(f"submit_label = ${param_num}")
                params.append(submit_label)
                param_num += 1

            if not updates:
                return {"error": "No updates provided"}

            updates.append("updated_at = NOW()")
            params.append(uuid.UUID(form_id))

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(f'''
                    UPDATE playbook_forms
                    SET {', '.join(updates)}
                    WHERE id = ${param_num}
                    RETURNING *
                ''', *params)

            if not row:
                return {"error": "Form not found"}

            return self._row_to_dict(row)

        except Exception as e:
            logger.error(f"Failed to update form: {e}")
            return {"error": str(e)}

    async def delete_form(self, form_id: str) -> bool:
        """Delete a form."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return False

            async with postgres_db.tenant_acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM playbook_forms WHERE id = $1",
                    uuid.UUID(form_id)
                )

            return "DELETE 1" in result

        except Exception as e:
            logger.error(f"Failed to delete form: {e}")
            return False

    # ========================================================================
    # Public Form Access
    # ========================================================================

    async def get_public_form_context(
        self,
        execution_id: str,
        node_id: str
    ) -> Optional[PublicFormContext]:
        """
        Get context for rendering a public form.

        This is called when a user accesses the public form URL.
        The caller MUST have already validated the HMAC token — this
        function runs under platform-admin mode so RLS-scoped reads
        (playbook_executions, playbook_forms) succeed without a
        request-attached tenant context.
        """
        try:
            from services.postgres_db import postgres_db, set_platform_admin_mode

            if not postgres_db.connected:
                return None

            set_platform_admin_mode(True)
            async with postgres_db.tenant_acquire() as conn:
                # Get execution
                execution = await conn.fetchrow('''
                    SELECT pe.*, p.canvas_data
                    FROM playbook_executions pe
                    JOIN playbooks p ON pe.playbook_id = p.id
                    WHERE pe.execution_id = $1
                ''', execution_id)

                if not execution:
                    logger.warning(f"Execution not found: {execution_id}")
                    return None

                # Check if at correct node and waiting
                if execution['current_node_id'] != node_id:
                    logger.warning(f"Execution {execution_id} not at node {node_id}")
                    return None

                if execution['status'] != 'waiting_input':
                    # Check if already submitted
                    if execution['status'] == 'completed':
                        return PublicFormContext(
                            form_id="",
                            execution_id=execution_id,
                            node_id=node_id,
                            form_definition=FormDefinition(name="", fields=[]),
                            already_submitted=True
                        )
                    return None

                # Check for existing submission
                submission = await conn.fetchrow('''
                    SELECT id FROM playbook_form_submissions
                    WHERE execution_id = $1
                ''', execution['id'])

                if submission:
                    return PublicFormContext(
                        form_id="",
                        execution_id=execution_id,
                        node_id=node_id,
                        form_definition=FormDefinition(name="", fields=[]),
                        already_submitted=True
                    )

                # Get node configuration
                canvas_data = execution['canvas_data']
                if isinstance(canvas_data, str):
                    canvas_data = json.loads(canvas_data)

                nodes = canvas_data.get('nodes', [])
                node = next((n for n in nodes if n['id'] == node_id), None)

                if not node:
                    logger.warning(f"Node {node_id} not found in playbook")
                    return None

                node_config = node.get('data', {}).get('config', {})

                # Build form definition
                form_id = node_config.get('form_id')
                if form_id:
                    # Load form from database
                    form = await self.get_form(form_id)
                    if form:
                        form_def = FormDefinition(
                            name=form['name'],
                            description=form.get('description'),
                            fields=[FormField(**f) for f in form['fields']],
                            submit_label=form.get('submit_label', 'Submit')
                        )
                    else:
                        return None
                else:
                    # Use inline fields
                    inline_fields = node_config.get('fields', [])
                    form_def = FormDefinition(
                        name=node.get('data', {}).get('label', 'Form'),
                        description=node_config.get('description'),
                        fields=[FormField(**f) for f in inline_fields],
                        submit_label=node_config.get('submit_label', 'Submit')
                    )

                # Check expiration
                timeout_at = execution.get('timeout_at')
                is_expired = False
                if timeout_at and datetime.utcnow() > timeout_at.replace(tzinfo=None):
                    is_expired = True

                # Get prefilled data from context
                execution_context = execution['execution_context']
                if isinstance(execution_context, str):
                    execution_context = json.loads(execution_context)

                # Form-level mapping is the default for any use of this form;
                # node-level overrides per playbook step.
                form_prefill = (form or {}).get('prefill_mapping') if form_id else None
                if isinstance(form_prefill, str):
                    form_prefill = json.loads(form_prefill)
                node_prefill = node_config.get('prefill', {})
                merged_prefill = {**(form_prefill or {}), **node_prefill}

                resolved_prefill = {}
                for field_name, path in merged_prefill.items():
                    value = self._extract_path(execution_context, path)
                    if value is not None:
                        resolved_prefill[field_name] = value

                return PublicFormContext(
                    form_id=form_id or f"inline_{node_id}",
                    execution_id=execution_id,
                    node_id=node_id,
                    form_definition=form_def,
                    prefilled_data=resolved_prefill if resolved_prefill else None,
                    expires_at=timeout_at,
                    is_expired=is_expired,
                    already_submitted=False
                )

        except Exception as e:
            logger.error(f"Failed to get public form context: {e}")
            return None

    # ========================================================================
    # Form Submission
    # ========================================================================

    async def validate_submission(
        self,
        form_definition: FormDefinition,
        form_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate submitted form data against form definition.

        Returns:
            {
                "valid": bool,
                "errors": {"field_name": "error message", ...},
                "cleaned_data": {...}
            }
        """
        errors = {}
        cleaned_data = {}

        for field in form_definition.fields:
            value = form_data.get(field.name)

            # Required check
            if field.required:
                if value is None or value == '' or (isinstance(value, list) and len(value) == 0):
                    errors[field.name] = f"{field.label} is required"
                    continue

            # Skip if empty and not required
            if value is None or value == '':
                cleaned_data[field.name] = field.default
                continue

            # Type-specific validation
            try:
                if field.type == FieldType.NUMBER:
                    cleaned_data[field.name] = float(value)
                    if field.validation:
                        if 'min' in field.validation and cleaned_data[field.name] < field.validation['min']:
                            errors[field.name] = f"Must be at least {field.validation['min']}"
                        if 'max' in field.validation and cleaned_data[field.name] > field.validation['max']:
                            errors[field.name] = f"Must be at most {field.validation['max']}"

                elif field.type == FieldType.EMAIL:
                    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', str(value)):
                        errors[field.name] = "Invalid email address"
                    else:
                        cleaned_data[field.name] = str(value).lower()

                elif field.type in [FieldType.SELECT, FieldType.RADIO]:
                    valid_values = [opt['value'] for opt in (field.options or [])]
                    if value not in valid_values:
                        errors[field.name] = "Invalid selection"
                    else:
                        cleaned_data[field.name] = value

                elif field.type == FieldType.MULTISELECT:
                    valid_values = [opt['value'] for opt in (field.options or [])]
                    if isinstance(value, list):
                        invalid = [v for v in value if v not in valid_values]
                        if invalid:
                            errors[field.name] = f"Invalid selections: {invalid}"
                        else:
                            cleaned_data[field.name] = value
                    else:
                        errors[field.name] = "Must be a list"

                elif field.type == FieldType.CHECKBOX:
                    cleaned_data[field.name] = bool(value)

                elif field.type == FieldType.DATE:
                    # Validate date format (YYYY-MM-DD)
                    try:
                        datetime.strptime(str(value), '%Y-%m-%d')
                        cleaned_data[field.name] = str(value)
                    except:
                        errors[field.name] = "Invalid date format (YYYY-MM-DD)"

                elif field.type == FieldType.DATETIME:
                    # Validate datetime format
                    try:
                        datetime.fromisoformat(str(value).replace('Z', '+00:00'))
                        cleaned_data[field.name] = str(value)
                    except:
                        errors[field.name] = "Invalid datetime format"

                elif field.type == FieldType.FILE:
                    # File validation is handled separately
                    cleaned_data[field.name] = value

                else:
                    # Text, textarea, hidden
                    cleaned_data[field.name] = str(value)
                    if field.validation:
                        if 'pattern' in field.validation:
                            if not re.match(field.validation['pattern'], str(value)):
                                errors[field.name] = field.validation.get('pattern_message', 'Invalid format')
                        if 'min_length' in field.validation and len(str(value)) < field.validation['min_length']:
                            errors[field.name] = f"Must be at least {field.validation['min_length']} characters"
                        if 'max_length' in field.validation and len(str(value)) > field.validation['max_length']:
                            errors[field.name] = f"Must be at most {field.validation['max_length']} characters"

            except Exception as e:
                errors[field.name] = f"Validation error: {str(e)}"

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "cleaned_data": cleaned_data
        }

    async def submit_form(
        self,
        execution_id: str,
        node_id: str,
        form_data: Dict[str, Any],
        submitted_by: str = None,
        files: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Submit a form and resume playbook execution.

        Args:
            execution_id: Playbook execution ID (PBX-XXXXXX)
            node_id: Node ID that requested the form
            form_data: Submitted form data
            submitted_by: User identifier (email, name, etc.)
            files: List of uploaded file metadata

        Returns:
            Submission result
        """
        try:
            from services.postgres_db import postgres_db, set_platform_admin_mode
            from services.playbook_engine import get_playbook_engine

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            # Caller has already validated the HMAC token; act under
            # admin mode so RLS-scoped reads succeed without an attached
            # tenant context.
            set_platform_admin_mode(True)
            async with postgres_db.tenant_acquire() as conn:
                # Get execution
                execution = await conn.fetchrow('''
                    SELECT pe.*, p.canvas_data
                    FROM playbook_executions pe
                    JOIN playbooks p ON pe.playbook_id = p.id
                    WHERE pe.execution_id = $1
                ''', execution_id)

                if not execution:
                    return {"error": "Execution not found"}

                # Verify execution is waiting for this form
                if execution['current_node_id'] != node_id:
                    return {"error": "Execution not at this node"}

                if execution['status'] != 'waiting_input':
                    return {"error": f"Execution not waiting for input (status: {execution['status']})"}

                # Check expiration
                timeout_at = execution.get('timeout_at')
                if timeout_at and datetime.utcnow() > timeout_at.replace(tzinfo=None):
                    return {"error": "Form has expired"}

                # Get form definition and validate
                canvas_data = execution['canvas_data']
                if isinstance(canvas_data, str):
                    canvas_data = json.loads(canvas_data)

                nodes = canvas_data.get('nodes', [])
                node = next((n for n in nodes if n['id'] == node_id), None)

                if not node:
                    return {"error": "Node not found"}

                node_config = node.get('data', {}).get('config', {})

                # Build form definition for validation
                form_id = node_config.get('form_id')
                if form_id:
                    form = await self.get_form(form_id)
                    if form:
                        form_def = FormDefinition(
                            name=form['name'],
                            fields=[FormField(**f) for f in form['fields']]
                        )
                    else:
                        return {"error": "Form template not found"}
                else:
                    inline_fields = node_config.get('fields', [])
                    form_def = FormDefinition(
                        name="Inline Form",
                        fields=[FormField(**f) for f in inline_fields]
                    )

                # Validate submission
                validation = await self.validate_submission(form_def, form_data)
                if not validation['valid']:
                    return {
                        "error": "Validation failed",
                        "validation_errors": validation['errors']
                    }

                # Record submission
                submission_id = await conn.fetchval('''
                    INSERT INTO playbook_form_submissions (
                        form_id, execution_id, submitted_by, form_data, files
                    ) VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                ''',
                    uuid.UUID(form_id) if form_id and form_id != 'inline' else None,
                    execution['id'],
                    submitted_by,
                    json.dumps(validation['cleaned_data']),
                    json.dumps(files or [])
                )

            # Resume playbook execution
            engine = get_playbook_engine()
            resume_result = await engine.resume_execution(
                execution_id=execution_id,
                resume_data={
                    "form_data": validation['cleaned_data'],
                    "submitted_by": submitted_by,
                    "submitted_at": datetime.utcnow().isoformat(),
                    "files": files or []
                }
            )

            logger.info(f"Form submitted for execution {execution_id}: {submission_id}")

            return {
                "success": True,
                "submission_id": str(submission_id),
                "execution_resumed": resume_result.get('resumed', False),
                "message": form_def.success_message if hasattr(form_def, 'success_message') else "Form submitted successfully"
            }

        except Exception as e:
            logger.error(f"Failed to submit form: {e}")
            return {"error": str(e)}

    # ========================================================================
    # File Uploads
    # ========================================================================

    async def handle_file_upload(
        self,
        execution_id: str,
        node_id: str,
        filename: str,
        file_data: bytes,
        uploaded_by: str = None
    ) -> Dict[str, Any]:
        """
        Handle file upload for a form or file_upload node.

        Args:
            execution_id: Playbook execution ID
            node_id: Node ID requesting the file
            filename: Original filename
            file_data: Raw file bytes
            uploaded_by: User identifier

        Returns:
            Upload result with file metadata
        """
        try:
            from services.postgres_db import postgres_db, set_platform_admin_mode
            from services.file_storage import get_file_storage

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            # Caller has already validated the HMAC token; act under
            # admin mode so RLS-scoped reads succeed without an attached
            # tenant context.
            set_platform_admin_mode(True)
            async with postgres_db.tenant_acquire() as conn:
                # Get execution
                execution = await conn.fetchrow('''
                    SELECT pe.*, p.canvas_data
                    FROM playbook_executions pe
                    JOIN playbooks p ON pe.playbook_id = p.id
                    WHERE pe.execution_id = $1
                ''', execution_id)

                if not execution:
                    return {"error": "Execution not found"}

                # Verify execution is waiting
                if execution['status'] not in ['waiting_input', 'waiting_file']:
                    return {"error": "Execution not waiting for file"}

                # Get node configuration for validation
                canvas_data = execution['canvas_data']
                if isinstance(canvas_data, str):
                    canvas_data = json.loads(canvas_data)

                nodes = canvas_data.get('nodes', [])
                node = next((n for n in nodes if n['id'] == node_id), None)

                if not node:
                    return {"error": "Node not found"}

                node_config = node.get('data', {}).get('config', {})

                # Validate file
                max_size_mb = node_config.get('max_size_mb', 10)
                max_size_bytes = max_size_mb * 1024 * 1024

                if len(file_data) > max_size_bytes:
                    return {"error": f"File too large (max {max_size_mb}MB)"}

                allowed_types = node_config.get('allowed_types', [])
                if allowed_types and '*/*' not in allowed_types:
                    import mimetypes
                    mime_type, _ = mimetypes.guess_type(filename)
                    if mime_type not in allowed_types:
                        return {"error": f"File type not allowed: {mime_type}"}

                # Store file
                file_storage = get_file_storage()
                stored_file = await file_storage.store_file(
                    file_data=file_data,
                    original_filename=filename,
                    alert_id=str(execution['alert_id']) if execution['alert_id'] else execution_id,
                    uploaded_by=uploaded_by
                )

                # Record in database
                from middleware.tenant_middleware import get_optional_tenant_id
                import uuid as _uuid
                _tenant_id = get_optional_tenant_id()

                file_id = await conn.fetchval('''
                    INSERT INTO playbook_files (
                        execution_id, filename, file_type, file_size,
                        storage_path, uploaded_by,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING id
                ''',
                    execution['id'],
                    filename,
                    stored_file.mime_type,
                    stored_file.file_size,
                    stored_file.storage_path,
                    uploaded_by,
                    _uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )

            file_metadata = {
                "file_id": str(file_id),
                "filename": filename,
                "original_filename": stored_file.original_filename,
                "file_size": stored_file.file_size,
                "mime_type": stored_file.mime_type,
                "sha256": stored_file.sha256_hash,
                "storage_path": stored_file.storage_path
            }

            logger.info(f"File uploaded for execution {execution_id}: {filename}")

            return {
                "success": True,
                "file": file_metadata
            }

        except Exception as e:
            logger.error(f"Failed to handle file upload: {e}")
            return {"error": str(e)}

    async def complete_file_upload(
        self,
        execution_id: str,
        node_id: str,
        files: List[Dict[str, Any]],
        uploaded_by: str = None
    ) -> Dict[str, Any]:
        """
        Complete a file upload node and resume execution.

        Called after all files have been uploaded.
        """
        try:
            from services.playbook_engine import get_playbook_engine

            engine = get_playbook_engine()
            resume_result = await engine.resume_execution(
                execution_id=execution_id,
                resume_data={
                    "files": files,
                    "uploaded_by": uploaded_by,
                    "uploaded_at": datetime.utcnow().isoformat()
                }
            )

            return {
                "success": True,
                "execution_resumed": resume_result.get('resumed', False),
                "files_count": len(files)
            }

        except Exception as e:
            logger.error(f"Failed to complete file upload: {e}")
            return {"error": str(e)}

    # ========================================================================
    # Submission History
    # ========================================================================

    async def get_submissions_for_execution(
        self,
        execution_id: str
    ) -> List[Dict[str, Any]]:
        """Get all form submissions for an execution."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return []

            async with postgres_db.tenant_acquire() as conn:
                # Get execution ID from execution_id string
                execution = await conn.fetchrow(
                    "SELECT id FROM playbook_executions WHERE execution_id = $1",
                    execution_id
                )

                if not execution:
                    return []

                rows = await conn.fetch('''
                    SELECT s.*, f.name as form_name
                    FROM playbook_form_submissions s
                    LEFT JOIN playbook_forms f ON s.form_id = f.id
                    WHERE s.execution_id = $1
                    ORDER BY s.submitted_at DESC
                ''', execution['id'])

            return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get submissions: {e}")
            return []

    async def get_files_for_execution(
        self,
        execution_id: str
    ) -> List[Dict[str, Any]]:
        """Get all uploaded files for an execution."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return []

            async with postgres_db.tenant_acquire() as conn:
                execution = await conn.fetchrow(
                    "SELECT id FROM playbook_executions WHERE execution_id = $1",
                    execution_id
                )

                if not execution:
                    return []

                rows = await conn.fetch('''
                    SELECT * FROM playbook_files
                    WHERE execution_id = $1
                    ORDER BY uploaded_at DESC
                ''', execution['id'])

            return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get files: {e}")
            return []

    # ========================================================================
    # Helpers
    # ========================================================================

    def _extract_path(self, data: Any, path: str) -> Any:
        """Extract value from data using JSONPath-like syntax."""
        if not path:
            return data

        if not path.startswith('$'):
            path = '$.' + path

        path = path[2:] if path.startswith('$.') else path[1:]

        if not path:
            return data

        parts = path.replace('[', '.').replace(']', '').split('.')
        current = data

        for part in parts:
            if current is None:
                return None

            if part.isdigit():
                idx = int(part)
                if isinstance(current, list) and idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None

        return current

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Convert database row to dictionary."""
        if not row:
            return None

        result = dict(row)

        # Convert UUID to string
        for field in ['id', 'form_id', 'execution_id', 'created_by']:
            if result.get(field):
                result[field] = str(result[field])

        # Convert datetime to ISO string
        for field in ['created_at', 'updated_at', 'submitted_at', 'uploaded_at']:
            if result.get(field):
                result[field] = result[field].isoformat()

        # Parse JSONB fields
        for field in ['fields', 'form_data', 'files']:
            if result.get(field) and isinstance(result[field], str):
                try:
                    result[field] = json.loads(result[field])
                except:
                    pass

        return result


# ============================================================================
# Singleton
# ============================================================================

_webform_service: Optional[WebformService] = None


def get_webform_service() -> WebformService:
    """Get singleton webform service instance."""
    global _webform_service
    if _webform_service is None:
        _webform_service = WebformService()
    return _webform_service
