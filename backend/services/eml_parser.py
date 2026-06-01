# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
.eml parser for intake-form attachments.

When a user reports a suspicious email by uploading the .eml file
(rather than pasting body text), we get the full RFC 5322 structure:
authentication headers (SPF / DKIM / DMARC results), the full Received
chain, MIME parts, attachments. All of that is gold for Riggs's triage
because the headers are where most phishing-detection signal lives.

This module pulls the high-value structured fields out of the .eml so
they ride along on the alert payload — Riggs and the analyst both see
parsed sender / subject / auth-results / Received hops next to the
original .eml file (still downloadable for deeper analysis).

Intentionally tolerant: a malformed .eml shouldn't blow up the
submission. Returns whatever it can parse and an `errors` list for
the rest.
"""

import email
import email.policy
import email.utils
import logging
import re
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# Headers worth surfacing on the alert metadata. The full header set is
# also returned but this is the "fast path" list for the analyst view.
HIGH_VALUE_HEADERS = (
    "From", "To", "Cc", "Bcc", "Reply-To", "Return-Path",
    "Subject", "Date", "Message-ID", "In-Reply-To", "References",
    "Authentication-Results", "ARC-Authentication-Results",
    "DKIM-Signature", "Received-SPF",
    "X-Originating-IP", "X-Sender-IP", "X-Mailer", "User-Agent",
    "List-Id", "List-Unsubscribe",
    "X-Spam-Status", "X-Spam-Score", "X-Microsoft-Antispam",
)


def _decode_header(value: Optional[str]) -> Optional[str]:
    """Decode RFC 2047 encoded-word header values to plain unicode."""
    if value is None:
        return None
    try:
        # email.utils.unquote handles routine cases; full path:
        from email.header import decode_header, make_header
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _addresses_from_header(value: Optional[str]) -> List[Dict[str, str]]:
    """Parse a comma-separated address header into [{name, email}, ...]."""
    if not value:
        return []
    try:
        parsed = email.utils.getaddresses([value])
        return [
            {"name": _decode_header(name) or "", "email": addr or ""}
            for (name, addr) in parsed
            if addr or name
        ]
    except Exception as e:
        logger.debug(f"address-header parse failed for {value!r}: {e}")
        return [{"name": "", "email": value}]


_AUTH_RESULT_RE = re.compile(
    r"(?P<mechanism>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)",
    re.IGNORECASE,
)


def _summarize_auth_results(auth_header: Optional[str]) -> Dict[str, Optional[str]]:
    """
    Pull SPF/DKIM/DMARC verdicts out of an Authentication-Results header.
    Returns {"spf": "pass"|None, "dkim": "pass"|None, "dmarc": "pass"|None}.

    Best-effort. A real implementation would parse all the optional
    parameters; we just grab the mechanism=result pairs, which is enough
    for an analyst to see "SPF passed but DMARC failed" at a glance.
    """
    result: Dict[str, Optional[str]] = {"spf": None, "dkim": None, "dmarc": None}
    if not auth_header:
        return result
    for m in _AUTH_RESULT_RE.finditer(auth_header):
        mech = m.group("mechanism").lower()
        verdict = m.group("result").lower()
        if mech in result and result[mech] is None:
            result[mech] = verdict
    return result


def _body_text(msg: EmailMessage) -> Optional[str]:
    """Return the best plain-text body we can find in the message."""
    if msg.is_multipart():
        # Prefer text/plain over text/html
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.is_multipart():
                try:
                    return part.get_content()
                except Exception:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
        # Fall back to html stripped (very crude — full HTML retained
        # separately below in body_html)
        for part in msg.walk():
            if part.get_content_type() == "text/html" and not part.is_multipart():
                try:
                    html = part.get_content()
                except Exception:
                    html = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                # Strip tags crudely. For triage we just need readable text.
                return re.sub(r"<[^>]+>", " ", html)
        return None
    try:
        return msg.get_content()
    except Exception:
        try:
            return msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", errors="replace"
            )
        except Exception:
            return None


def _body_html(msg: EmailMessage) -> Optional[str]:
    """Return the html body if present, untouched."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html" and not part.is_multipart():
                try:
                    return part.get_content()
                except Exception:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
        return None
    if msg.get_content_type() == "text/html":
        try:
            return msg.get_content()
        except Exception:
            return None
    return None


def _inner_attachments(msg: EmailMessage) -> List[Dict[str, Any]]:
    """
    List attachments inside the .eml itself (NOT the .eml's own metadata).
    Returns filename, content_type, size for each — we don't extract the
    bytes because the .eml file is already on disk and downloadable.
    """
    out: List[Dict[str, Any]] = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        if part.is_multipart():
            continue
        cd = part.get_content_disposition()  # 'attachment' / 'inline' / None
        ctype = part.get_content_type()
        if cd != "attachment" and not (ctype.startswith("application/") or ctype.startswith("image/")):
            continue
        if ctype.startswith("text/") and cd != "attachment":
            continue
        filename = _decode_header(part.get_filename()) or "unnamed"
        try:
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
        except Exception:
            size = 0
        out.append({
            "filename": filename,
            "content_type": ctype,
            "size_bytes": size,
        })
    return out


def _received_chain(msg: EmailMessage, limit: int = 10) -> List[str]:
    """All Received: hops in order (most recent first), capped for size."""
    received = msg.get_all("Received") or []
    return [str(_decode_header(r) or r) for r in received[:limit]]


def parse_eml_bytes(data: bytes) -> Dict[str, Any]:
    """
    Parse raw .eml bytes into a structured dict.

    Never raises — malformed input still returns a dict with whatever
    we could extract, plus an `errors` list. Callers decide how to
    treat partial results.
    """
    errors: List[str] = []
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as e:
        return {
            "parsed": False,
            "errors": [f"could not parse message: {e}"],
        }

    try:
        auth_header = msg.get("Authentication-Results") or msg.get("ARC-Authentication-Results")
    except Exception:
        auth_header = None

    headers_pretty: Dict[str, str] = {}
    for h in HIGH_VALUE_HEADERS:
        try:
            v = msg.get(h)
            if v is None:
                continue
            headers_pretty[h] = _decode_header(v) or str(v)
        except Exception as e:
            errors.append(f"header decode failed for {h}: {e}")

    try:
        body_text = _body_text(msg)
    except Exception as e:
        body_text = None
        errors.append(f"body text extraction failed: {e}")

    try:
        body_html = _body_html(msg)
    except Exception as e:
        body_html = None
        errors.append(f"body html extraction failed: {e}")

    try:
        inner_attachments = _inner_attachments(msg)
    except Exception as e:
        inner_attachments = []
        errors.append(f"inner attachment extraction failed: {e}")

    try:
        received = _received_chain(msg)
    except Exception as e:
        received = []
        errors.append(f"received-chain extraction failed: {e}")

    return {
        "parsed": True,
        "from":             _addresses_from_header(msg.get("From")),
        "to":               _addresses_from_header(msg.get("To")),
        "cc":               _addresses_from_header(msg.get("Cc")),
        "reply_to":         _addresses_from_header(msg.get("Reply-To")),
        "return_path":      _addresses_from_header(msg.get("Return-Path")),
        "subject":          _decode_header(msg.get("Subject")),
        "date":             _decode_header(msg.get("Date")),
        "message_id":       _decode_header(msg.get("Message-ID")),
        "auth_results_raw": _decode_header(auth_header),
        "auth_summary":     _summarize_auth_results(auth_header),
        "received_chain":   received,
        "headers":          headers_pretty,
        "body_text":        body_text[:50_000] if body_text else None,
        "body_text_truncated": bool(body_text and len(body_text) > 50_000),
        "body_html":        body_html[:200_000] if body_html else None,
        "body_html_truncated": bool(body_html and len(body_html) > 200_000),
        "inner_attachments": inner_attachments,
        "errors":           errors,
    }


def parse_eml_file(path: Union[str, Path]) -> Dict[str, Any]:
    """Convenience wrapper: read .eml from disk and parse."""
    try:
        with open(path, "rb") as f:
            return parse_eml_bytes(f.read())
    except FileNotFoundError:
        return {"parsed": False, "errors": [f"file not found: {path}"]}
    except Exception as e:
        return {"parsed": False, "errors": [f"read failed: {e}"]}


def is_eml(filename: Optional[str], content_type: Optional[str]) -> bool:
    """
    Quick check: does this attachment look like a parseable email?

    Used to decide whether to invoke the parser on submission. We're
    permissive — many email clients export with the message/rfc822
    content type, but plenty of others just use the filename and
    leave content_type as application/octet-stream.
    """
    if content_type:
        ct = content_type.lower().split(";")[0].strip()
        if ct in ("message/rfc822", "application/eml", "text/eml"):
            return True
    if filename:
        ext = filename.lower().rsplit(".", 1)
        if len(ext) == 2 and ext[1] in ("eml", "msg"):
            return True
    return False
