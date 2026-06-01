# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Report Generator Service
Generates investigation reports in Markdown and PDF format.

Supports three report templates:
- executive_summary: High-level overview for leadership
- detailed_technical: Full technical analysis with IOC tables and MITRE mapping
- incident_response: Timeline-focused IR report with containment details

Usage:
    service = ReportGeneratorService()
    markdown = await service.generate_report(investigation_id, tenant_id, 'executive_summary', 'markdown', db_pool)
    pdf_bytes = await service.generate_report(investigation_id, tenant_id, 'detailed_technical', 'pdf', db_pool)
"""

import os
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader
from fpdf import FPDF

logger = logging.getLogger(__name__)

VALID_TEMPLATES = ['executive_summary', 'detailed_technical', 'incident_response']
VALID_FORMATS = ['markdown', 'pdf']


class ReportGeneratorService:
    """Generates investigation reports from templates."""

    def __init__(self):
        template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates', 'reports')
        template_dir = os.path.normpath(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Register custom filters
        self.env.filters['severity_label'] = self._severity_label
        self.env.filters['truncate_str'] = self._truncate_str
        self.env.filters['format_datetime'] = self._format_datetime

    @staticmethod
    def _severity_label(value: Any) -> str:
        """Convert numeric severity to label."""
        try:
            val = int(value)
        except (TypeError, ValueError):
            return str(value) if value else "Unknown"
        mapping = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        return mapping.get(val, f"Level {val}")

    @staticmethod
    def _truncate_str(value: str, length: int = 80) -> str:
        """Truncate a string to given length."""
        if not value:
            return ""
        s = str(value)
        return s if len(s) <= length else s[:length] + "..."

    @staticmethod
    def _format_datetime(value: Any) -> str:
        """Format a datetime value for display."""
        if not value:
            return "N/A"
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S UTC')
        return str(value)

    async def generate_report(
        self,
        investigation_id: str,
        tenant_id: str,
        template_name: str,
        format: str = 'markdown',
        db_pool=None,
    ) -> Any:
        """
        Generate a report for the given investigation.

        Args:
            investigation_id: UUID of the investigation
            tenant_id: UUID of the tenant (used for RLS context)
            template_name: One of 'executive_summary', 'detailed_technical', 'incident_response'
            format: 'markdown' or 'pdf'
            db_pool: Database pool instance (postgres_db)

        Returns:
            str for markdown, bytes for PDF

        Raises:
            ValueError: If investigation not found or invalid template/format
        """
        if template_name not in VALID_TEMPLATES:
            raise ValueError(f"Invalid template '{template_name}'. Valid: {VALID_TEMPLATES}")
        if format not in VALID_FORMATS:
            raise ValueError(f"Invalid format '{format}'. Valid: {VALID_FORMATS}")
        if db_pool is None:
            raise ValueError("Database pool is required")

        # 1. Gather data
        data = await self._gather_report_data(investigation_id, tenant_id, db_pool)

        # 2. Render markdown from template
        template = self.env.get_template(f'{template_name}.j2')
        markdown_content = template.render(**data)

        # 3. Convert to requested format
        if format == 'pdf':
            return self._markdown_to_pdf(markdown_content, data)
        return markdown_content

    async def _gather_report_data(
        self,
        investigation_id: str,
        tenant_id: str,
        db_pool,
    ) -> Dict[str, Any]:
        """Gather all data needed for report generation."""
        async with db_pool.tenant_acquire() as conn:
            # Get investigation
            inv = await conn.fetchrow(
                "SELECT * FROM investigations WHERE investigation_id = $1",
                investigation_id,
            )
            if not inv:
                raise ValueError(f"Investigation {investigation_id} not found")

            inv_dict = dict(inv)
            inv_uuid = inv_dict.get('id')  # UUID primary key
            inv_data = inv_dict.get('investigation_data') or '{}'
            if isinstance(inv_data, str):
                try:
                    inv_data = json.loads(inv_data)
                except (json.JSONDecodeError, TypeError):
                    inv_data = {}

            # Get IOCs (join with ioc_enrichments for verdict data)
            # investigation_iocs.investigation_id is UUID (references investigations.id)
            iocs = await self._safe_fetch(
                conn,
                "SELECT ii.*, ie.ioc_value, ie.ioc_type, ie.verdict, ie.score, ie.sources_flagged "
                "FROM investigation_iocs ii "
                "LEFT JOIN ioc_enrichments ie ON ii.ioc_enrichment_id = ie.id "
                "WHERE ii.investigation_id = $1 "
                "ORDER BY ie.score DESC NULLS LAST",
                inv_uuid,
            )

            # Get notes (investigation_notes.investigation_id is VARCHAR, matches investigation_id)
            notes = await self._safe_fetch(
                conn,
                "SELECT * FROM investigation_notes WHERE investigation_id = $1 "
                "AND deleted_at IS NULL ORDER BY created_at ASC",
                investigation_id,
            )

            # Get recommended actions (investigation_id is UUID, references investigations.id)
            actions = await self._safe_fetch(
                conn,
                "SELECT * FROM recommended_actions WHERE investigation_id = $1 "
                "ORDER BY priority ASC, created_at ASC",
                inv_uuid,
            )

            # Get linked alerts (investigation_id is UUID, references investigations.id)
            alerts = await self._safe_fetch(
                conn,
                "SELECT id, title, severity, created_at, status FROM alerts "
                "WHERE investigation_id = $1 ORDER BY created_at ASC",
                inv_uuid,
            )

            # Extract analysis tiers (tier3 > tier2 > tier1)
            tier3 = inv_data.get('tier3_analysis', {})
            tier2 = inv_data.get('tier2_analysis', {})
            tier1 = inv_data.get('tier1_analysis', {})
            riggs = inv_data.get('riggs_analysis', {})
            analysis = tier3 if tier3.get('verdict') else (tier2 if tier2.get('verdict') else (tier1 if tier1.get('verdict') else riggs))
            deep_dive = inv_data.get('riggs_deep_analysis', {})

            # Build action summary counts
            action_counts = {'total': 0, 'approved': 0, 'dismissed': 0, 'pending': 0}
            for a in actions:
                action_counts['total'] += 1
                status = a.get('status', 'pending')
                if status == 'approved':
                    action_counts['approved'] += 1
                elif status == 'dismissed':
                    action_counts['dismissed'] += 1
                else:
                    action_counts['pending'] += 1

            # IOCs — merge from relational table AND investigation_data.indicators
            inv_indicators = inv_data.get('indicators', [])
            if isinstance(inv_indicators, list):
                for ind in inv_indicators:
                    if isinstance(ind, dict) and ind.get('value'):
                        iocs.append({
                            'ioc_type': ind.get('type', 'unknown'),
                            'ioc_value': ind.get('value', ''),
                            'verdict': ind.get('verdict') or ind.get('reputation') or 'unknown',
                            'score': ind.get('score') or ind.get('confidence'),
                        })

            # Pull from riggs_extracted_iocs (dict format: {ips: [], domains: [], hashes: [], ...})
            riggs_iocs = riggs.get('riggs_extracted_iocs', {})
            if isinstance(riggs_iocs, dict):
                type_map = {'ips': 'ip', 'domains': 'domain', 'hashes': 'hash', 'urls': 'url', 'emails': 'email'}
                for key, ioc_type in type_map.items():
                    for val in riggs_iocs.get(key, []):
                        if val:
                            iocs.append({'ioc_type': ioc_type, 'ioc_value': str(val), 'verdict': 'unknown'})

            # Pull from riggs_analysis.iocs (list format)
            riggs_ioc_list = riggs.get('iocs', [])
            if isinstance(riggs_ioc_list, list):
                for ri in riggs_ioc_list:
                    if isinstance(ri, dict) and ri.get('value'):
                        iocs.append({'ioc_type': ri.get('type', 'unknown'), 'ioc_value': ri['value'], 'verdict': ri.get('verdict', 'unknown')})

            # Also pull from malicious_iocs
            for mioc in inv_data.get('malicious_iocs', []):
                if isinstance(mioc, dict) and mioc.get('value'):
                    iocs.append({
                        'ioc_type': mioc.get('type', 'unknown'),
                        'ioc_value': mioc.get('value', ''),
                        'verdict': mioc.get('verdict', 'malicious'),
                        'score': mioc.get('confidence'),
                    })

            # Deduplicate IOCs by value
            seen_ioc_vals = set()
            deduped_iocs = []
            for ioc in iocs:
                val = ioc.get('ioc_value', '')
                if val and val not in seen_ioc_vals:
                    seen_ioc_vals.add(val)
                    deduped_iocs.append(ioc)
            iocs = deduped_iocs

            # IOC verdict summary
            ioc_counts = {'total': 0, 'malicious': 0, 'suspicious': 0, 'clean': 0, 'unknown': 0}
            for ioc in iocs:
                ioc_counts['total'] += 1
                verdict = (ioc.get('verdict') or 'unknown').lower()
                if verdict in ioc_counts:
                    ioc_counts[verdict] += 1
                else:
                    ioc_counts['unknown'] += 1

            # MITRE techniques — check all sources
            mitre = []
            for source in [analysis, riggs, deep_dive]:
                if not source or mitre:
                    continue
                for key in ['mitre_techniques', 'mitre_attack', 'mitre', 'mitre_mapping']:
                    candidate = source.get(key, [])
                    if candidate and isinstance(candidate, list) and len(candidate) > 0:
                        mitre = candidate
                        break

            # Enrichment summary
            enrichment = inv_data.get('enrichment_summary', {})

            # Recommended actions — check multiple sources
            if not actions:
                # Try investigation_data.recommended_actions
                ra = inv_data.get('recommended_actions')
                # Try riggs_analysis.recommendations
                if not ra:
                    ra = riggs.get('recommendations', [])
                # Try riggs_analysis.playbook_recommendations
                if not ra:
                    ra = riggs.get('playbook_recommendations', [])

                if isinstance(ra, list):
                    for a in ra:
                        if isinstance(a, str):
                            actions.append({'action_type': 'action', 'description': a, 'status': 'pending', 'priority': ''})
                        elif isinstance(a, dict):
                            actions.append({
                                'action_type': a.get('type', a.get('action_type', 'action')),
                                'description': a.get('description') or a.get('action') or a.get('text', ''),
                                'status': a.get('status', 'pending'),
                                'priority': a.get('priority', ''),
                            })
                elif isinstance(ra, dict):
                    for key, items in ra.items():
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, str):
                                    actions.append({'action_type': key, 'description': item, 'status': 'pending'})
                                elif isinstance(item, dict):
                                    actions.append({'action_type': key, 'description': item.get('description') or item.get('text', ''), 'status': 'pending'})

            # Timeline
            timeline = inv_data.get('timeline', [])

            return {
                'investigation': inv_dict,
                'investigation_data': inv_data,
                'analysis': analysis if analysis else {},
                'deep_dive': deep_dive if deep_dive else {},
                'riggs': riggs if riggs else {},
                'iocs': iocs,
                'ioc_counts': ioc_counts,
                'notes': notes,
                'actions': actions,
                'action_counts': action_counts,
                'alerts': alerts,
                'enrichment': enrichment,
                'timeline': timeline,
                'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'mitre_techniques': mitre,
            }

    async def _safe_fetch(self, conn, query: str, *args) -> List[Dict[str, Any]]:
        """Execute a fetch query, returning empty list on error (e.g. table missing)."""
        try:
            rows = await conn.fetch(query, *args)
            return [dict(r) for r in rows] if rows else []
        except Exception as e:
            logger.warning(f"Report data query failed (non-fatal): {e}")
            return []

    def _markdown_to_pdf(self, markdown_content: str, data: Dict[str, Any]) -> bytes:
        """Convert markdown report to PDF bytes."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.set_left_margin(15)
        pdf.set_right_margin(15)
        pdf.add_page()

        w = pdf.w - pdf.l_margin - pdf.r_margin  # usable width

        # Title
        pdf.set_font('Helvetica', 'B', 14)
        title = data.get('investigation', {}).get('alert_title') or data.get('investigation', {}).get('title', 'Investigation Report')
        pdf.multi_cell(w, 7, self._sanitize_for_pdf(title))
        pdf.ln(2)

        # Metadata line
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(100, 100, 100)
        inv_id = data.get('investigation', {}).get('investigation_id', '')
        severity = data.get('investigation', {}).get('severity', '')
        state = data.get('investigation', {}).get('state', '')
        pdf.multi_cell(w, 4, self._sanitize_for_pdf(
            f"Generated: {data.get('generated_at', '')}  |  ID: {inv_id}  |  Severity: {severity}  |  State: {state}"
        ))
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        # Render markdown
        lines = markdown_content.split('\n')
        skip_first_h1 = True
        in_code_block = False

        for line in lines:
            stripped = line.rstrip()

            # Skip code block markers
            if stripped.startswith('```'):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                pdf.set_font('Courier', '', 7)
                pdf.multi_cell(w, 4, self._sanitize_for_pdf(stripped))
                continue

            # Clean markdown formatting from text
            clean = self._strip_markdown(stripped)

            if stripped.startswith('# '):
                if skip_first_h1:
                    skip_first_h1 = False
                    continue
                pdf.ln(4)
                pdf.set_font('Helvetica', 'B', 13)
                pdf.multi_cell(w, 7, self._sanitize_for_pdf(stripped[2:]))
                pdf.ln(2)
            elif stripped.startswith('## '):
                pdf.ln(3)
                pdf.set_font('Helvetica', 'B', 11)
                pdf.multi_cell(w, 6, self._sanitize_for_pdf(stripped[3:]))
                pdf.ln(1)
            elif stripped.startswith('### '):
                pdf.ln(2)
                pdf.set_font('Helvetica', 'B', 9)
                pdf.multi_cell(w, 5, self._sanitize_for_pdf(stripped[4:]))
                pdf.ln(1)
            elif stripped.startswith('- ') or stripped.startswith('* '):
                pdf.set_font('Helvetica', '', 8)
                bullet_text = self._sanitize_for_pdf(self._strip_markdown(stripped[2:]))
                pdf.set_x(pdf.l_margin + 4)
                pdf.multi_cell(w - 8, 4, f"- {bullet_text}")
                pdf.ln(0.5)
            elif stripped.startswith('| '):
                # Table row — split into columns
                if stripped.startswith('|---') or stripped.startswith('| ---'):
                    continue  # skip separator rows
                cols = [c.strip() for c in stripped.split('|')[1:-1]]
                if not cols:
                    continue
                is_header = all(c == c.upper() or c in ('Type', 'Value', 'Verdict', 'Status') for c in cols if c)
                # Calculate column widths proportionally
                n = len(cols)
                col_widths = [w / n] * n
                if n >= 3:
                    col_widths = [w * 0.15, w * 0.60, w * 0.25][:n]
                    if n > 3:
                        col_widths = [w / n] * n
                y_before = pdf.get_y()
                x_start = pdf.l_margin
                for ci, col_text in enumerate(cols):
                    pdf.set_xy(x_start + sum(col_widths[:ci]), y_before)
                    pdf.set_font('Helvetica', 'B' if is_header else '', 7)
                    pdf.cell(col_widths[ci], 4, self._sanitize_for_pdf(col_text)[:50], border=0)
                pdf.ln(4.5)
            elif stripped == '---':
                pdf.ln(2)
                y = pdf.get_y()
                pdf.set_draw_color(200, 200, 200)
                pdf.line(pdf.l_margin, y, pdf.l_margin + w, y)
                pdf.set_draw_color(0, 0, 0)
                pdf.ln(2)
            elif stripped.startswith('_') and stripped.endswith('_'):
                # Italic footer text
                pdf.set_font('Helvetica', 'I', 7)
                pdf.set_text_color(120, 120, 120)
                pdf.multi_cell(w, 4, self._sanitize_for_pdf(stripped.strip('_')))
                pdf.set_text_color(0, 0, 0)
            elif clean.strip():
                # Check if line starts bold (like **Key:** value)
                if stripped.startswith('**') and '**' in stripped[2:]:
                    bold_end = stripped.index('**', 2)
                    bold_part = stripped[2:bold_end]
                    rest = self._strip_markdown(stripped[bold_end + 2:])
                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.write(4, self._sanitize_for_pdf(bold_part))
                    pdf.set_font('Helvetica', '', 8)
                    pdf.write(4, self._sanitize_for_pdf(rest))
                    pdf.ln(5)
                else:
                    pdf.set_font('Helvetica', '', 8)
                    pdf.multi_cell(w, 4, self._sanitize_for_pdf(clean))
                    pdf.ln(0.5)
            else:
                pdf.ln(2)

        return bytes(pdf.output())

    @staticmethod
    def _strip_markdown(text: str) -> str:
        """Remove markdown formatting (bold, italic, code) from text."""
        if not text:
            return ""
        import re
        result = text
        result = re.sub(r'\*\*(.+?)\*\*', r'\1', result)  # bold
        result = re.sub(r'\*(.+?)\*', r'\1', result)  # italic
        result = re.sub(r'_(.+?)_', r'\1', result)  # italic
        result = re.sub(r'`(.+?)`', r'\1', result)  # inline code
        return result

    @staticmethod
    def _sanitize_for_pdf(text: str) -> str:
        """Sanitize text for FPDF (latin-1 encoding)."""
        if not text:
            return ""
        # Replace common problematic characters
        replacements = {
            '\u2018': "'", '\u2019': "'",
            '\u201c': '"', '\u201d': '"',
            '\u2013': '-', '\u2014': '--',
            '\u2026': '...',
            '\u2022': '-',
            '\u00a0': ' ',
        }
        result = text
        for old, new in replacements.items():
            result = result.replace(old, new)
        # Encode to latin-1, replacing anything else
        return result.encode('latin-1', errors='replace').decode('latin-1')
