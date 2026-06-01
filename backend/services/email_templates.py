# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Email Templates for T1 Agentics Platform

Branded HTML email templates with inline CSS for maximum email client compatibility.
All templates use the T1 Agentics brand color palette:
  - Primary: #3CB371 (emerald green)
  - Background: #080a0f (deep dark)
  - Card: #151b23
  - Text: #f0f6fc (light)
  - Secondary text: #8b949e
  - Border: rgba(48, 54, 61, 0.8)
"""


# ---------------------------------------------------------------------------
# Shared layout helpers
# ---------------------------------------------------------------------------

def _base_layout(content: str, preheader: str = "") -> str:
    """Wrap *content* inside the standard T1 Agentics email shell.

    Uses a centered, 600 px max-width card on a dark background with the
    brand header and legal footer baked in.  Everything is inline-styled
    so it renders correctly in Gmail, Outlook, Apple Mail, etc.
    """
    return f"""\
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>T1 Agentics</title>
    <!--[if mso]>
    <style type="text/css">
        body, table, td {{ font-family: Arial, Helvetica, sans-serif !important; }}
    </style>
    <![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#080a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;">
    <!-- Preheader (hidden preview text) -->
    <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">{preheader}</div>

    <!-- Outer wrapper -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#080a0f;">
        <tr>
            <td align="center" style="padding:40px 16px;">
                <!-- Card -->
                <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#151b23;border:1px solid rgba(48,54,61,0.8);border-radius:12px;overflow:hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="padding:32px 40px 24px 40px;border-bottom:1px solid rgba(48,54,61,0.8);text-align:center;">
                            <span style="font-size:24px;font-weight:700;color:#3CB371;letter-spacing:-0.5px;">T1 Agentics</span>
                            <br />
                            <span style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1.5px;">Autonomous Security Operations</span>
                        </td>
                    </tr>

                    <!-- Body -->
                    <tr>
                        <td style="padding:32px 40px;">
                            {content}
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="padding:24px 40px;border-top:1px solid rgba(48,54,61,0.8);text-align:center;">
                            <p style="margin:0 0 4px 0;font-size:12px;color:#8b949e;">
                                T1 Agentics LLC &mdash; Autonomous Security Operations
                            </p>
                            <p style="margin:0;font-size:11px;color:#6e7681;">
                                &copy; 2026 T1 Agentics LLC. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
                <!-- /Card -->
            </td>
        </tr>
    </table>
</body>
</html>"""


def _button(label: str, url: str) -> str:
    """Render a prominent CTA button using the brand green."""
    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin:28px auto;">'
        f'<tr><td align="center" style="border-radius:8px;background-color:#3CB371;">'
        f'<a href="{url}" target="_blank" '
        f'style="display:inline-block;padding:14px 40px;font-size:16px;font-weight:600;'
        f'color:#ffffff;text-decoration:none;border-radius:8px;">{label}</a>'
        f'</td></tr></table>'
    )


def _paragraph(text: str) -> str:
    """Standard paragraph in light text."""
    return f'<p style="margin:0 0 16px 0;font-size:15px;line-height:1.6;color:#f0f6fc;">{text}</p>'


def _muted(text: str) -> str:
    """Small muted helper text."""
    return f'<p style="margin:0 0 12px 0;font-size:13px;line-height:1.5;color:#8b949e;">{text}</p>'


def _detail_row(label: str, value: str) -> str:
    """Key-value detail row for data tables inside the card."""
    return (
        f'<tr>'
        f'<td style="padding:8px 12px;font-size:13px;color:#8b949e;white-space:nowrap;vertical-align:top;">{label}</td>'
        f'<td style="padding:8px 12px;font-size:14px;color:#f0f6fc;word-break:break-word;">{value}</td>'
        f'</tr>'
    )


# ---------------------------------------------------------------------------
# Public template functions
# ---------------------------------------------------------------------------

def render_verification_email(token_url: str, tenant_name: str, full_name: str) -> str:
    """Render the email-verification email sent during self-service registration.

    Parameters
    ----------
    token_url : str
        The full URL the user must visit to verify their email address.
    tenant_name : str
        The display name of the tenant being created.
    full_name : str
        The registrant's name (falls back to "there" if empty).
    """
    greeting = full_name if full_name else "there"
    content = (
        _paragraph(f"Hi {greeting},")
        + _paragraph(
            "Thank you for registering with <strong style=\"color:#3CB371;\">T1 Agentics</strong>. "
            "To complete the setup of your new workspace "
            f"<strong style=\"color:#f0f6fc;\">{tenant_name}</strong>, "
            "please verify your email address by clicking the button below."
        )
        + _button("Verify Your Email", token_url)
        + _muted(
            "This verification link will expire in <strong>24 hours</strong>. "
            "If you did not create this account, you can safely ignore this email."
        )
        + _muted(
            "If the button above does not work, copy and paste the following URL "
            "into your browser:"
        )
        + f'<p style="margin:0 0 16px 0;font-size:12px;line-height:1.4;color:#8b949e;word-break:break-all;">{token_url}</p>'
    )
    return _base_layout(content, preheader=f"Verify your email to activate {tenant_name} on T1 Agentics")


def render_welcome_email(tenant_slug: str, login_url: str, username: str) -> str:
    """Render the welcome email sent after a tenant is successfully provisioned.

    Parameters
    ----------
    tenant_slug : str
        The slug identifier for the new tenant.
    login_url : str
        Direct URL to the tenant login page.
    username : str
        The admin username that was created.
    """
    content = (
        _paragraph(f"Hi {username},")
        + _paragraph(
            "Your workspace is ready! Your <strong style=\"color:#3CB371;\">T1 Agentics</strong> "
            "tenant has been provisioned and is now active."
        )
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + _detail_row("Workspace", f"<strong>{tenant_slug}</strong>")
        + _detail_row("Username", username)
        + _detail_row("Plan", "Community (Free)")
        + '</table>'
        + _paragraph(
            "You can log in now and start configuring your security operations environment "
            "-- add integrations, create playbooks, and let the autonomous agents get to work."
        )
        + _button("Log In to Your Workspace", login_url)
        + _muted(
            "Need help getting started? Check out the documentation inside the platform "
            "or reach out to our support team."
        )
    )
    return _base_layout(content, preheader=f"Your T1 Agentics workspace \"{tenant_slug}\" is ready")


def render_account_created_email(
    username: str,
    email: str,
    tenant_name: str,
    login_url: str,
    created_by: str,
) -> str:
    """Render the email sent when an admin creates a new user account.

    Parameters
    ----------
    username : str
        The new user's username.
    email : str
        The new user's email address.
    tenant_name : str
        Display name of the workspace the account belongs to.
    login_url : str
        Direct URL to the tenant login page.
    created_by : str
        Username of the admin who created the account.
    """
    content = (
        _paragraph(f"Hi {username},")
        + _paragraph(
            f"An account has been created for you in the "
            f"<strong style=\"color:#3CB371;\">{tenant_name}</strong> workspace "
            f"on <strong style=\"color:#3CB371;\">T1 Agentics</strong> by {created_by}."
        )
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + _detail_row("Workspace", f"<strong>{tenant_name}</strong>")
        + _detail_row("Username", username)
        + _detail_row("Email", email)
        + '</table>'
        + _paragraph(
            "Use the credentials provided by your administrator to log in. "
            "You may be prompted to change your password on first login."
        )
        + _button("Log In Now", login_url)
        + _muted(
            "If you did not expect this account, please contact your workspace administrator."
        )
    )
    return _base_layout(content, preheader=f"Your account on {tenant_name} is ready")


def render_enterprise_inquiry_notification(
    name: str,
    email: str,
    company: str,
    message: str,
) -> str:
    """Render the admin notification email for a new enterprise contact inquiry.

    This email is sent to the T1 Agentics platform administrators when someone
    submits the enterprise / contact form on the public website.

    Parameters
    ----------
    name : str
        Submitter's full name.
    email : str
        Submitter's email address.
    company : str
        Company or organization name (may be empty).
    message : str
        Free-text message from the inquiry form.
    """
    # Sanitize message for HTML display
    safe_message = (
        message
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br />")
    )

    content = (
        _paragraph(
            '<span style="font-size:18px;font-weight:600;color:#3CB371;">New Enterprise Inquiry</span>'
        )
        + _paragraph("A new inquiry has been submitted through the contact form.")
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + _detail_row("Name", name)
        + _detail_row("Email", f'<a href="mailto:{email}" style="color:#3CB371;text-decoration:none;">{email}</a>')
        + _detail_row("Company", company if company else "<em style=\"color:#6e7681;\">Not provided</em>")
        + '</table>'
        + '<div style="margin:0 0 24px 0;padding:16px;background-color:#0d1117;'
          'border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + f'<p style="margin:0 0 8px 0;font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">Message</p>'
        + f'<p style="margin:0;font-size:14px;line-height:1.6;color:#f0f6fc;">{safe_message}</p>'
        + '</div>'
        + _muted("Please respond to this inquiry in a timely manner.")
    )
    return _base_layout(content, preheader=f"Enterprise inquiry from {name} at {company}")


def render_admin_playbook_submission(
    playbook_name: str,
    playbook_description: str,
    node_count: int,
    edge_count: int,
    tenant_slug: str,
    submitter_username: str,
    submitter_email: str,
    submission_notes: str,
    review_url: str,
) -> str:
    """Render the admin notification sent when a tenant submits a playbook
    to the community marketplace.

    Surfaces enough detail (size, description, submitter, notes) to triage
    from the inbox before opening the review UI.
    """
    safe_desc = (
        (playbook_description or "")
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\n", "<br />")
    )
    safe_notes = (
        (submission_notes or "")
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\n", "<br />")
    )
    safe_name = (playbook_name or "Untitled").replace("<", "&lt;").replace(">", "&gt;")

    content = (
        _paragraph(
            '<span style="font-size:18px;font-weight:600;color:#3CB371;">New Playbook Submission</span>'
        )
        + _paragraph(
            f'<strong>{tenant_slug}</strong> has submitted a playbook to the community marketplace.'
        )
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + _detail_row("Playbook", f'<strong style="color:#f0f6fc;">{safe_name}</strong>')
        + _detail_row("Description", safe_desc if safe_desc else '<em style="color:#6e7681;">Not provided</em>')
        + _detail_row("Size", f'{node_count} nodes &middot; {edge_count} edges')
        + _detail_row("Submitter", f'{submitter_username}'
                       + (f' &lt;<a href="mailto:{submitter_email}" style="color:#3CB371;text-decoration:none;">{submitter_email}</a>&gt;'
                          if submitter_email else ''))
        + _detail_row("Tenant", tenant_slug)
        + '</table>'
        + (
            '<div style="margin:0 0 24px 0;padding:16px;background-color:#0d1117;'
            'border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
            '<p style="margin:0 0 8px 0;font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">Submitter notes</p>'
            f'<p style="margin:0;font-size:14px;line-height:1.6;color:#f0f6fc;">{safe_notes}</p>'
            '</div>'
            if safe_notes else ''
          )
        + _button("Review Submission", review_url)
        + _muted(
            "Approving clones this playbook into <code>playbook_templates</code> "
            "with <code>source='community'</code> so all tenants can install it."
        )
    )
    return _base_layout(content, preheader=f"{tenant_slug} submitted: {safe_name}")


def render_admin_signup_notification(
    email: str,
    tenant_name: str,
    tenant_slug: str,
    plan: str,
    ip_address: str,
    full_name: str = "",
    referral_code: str = "",
    repeat_signups_from_ip: int = 0,
    repeat_window_days: int = 7,
    waitlisted: bool = False,
) -> str:
    """Render the admin notification sent when a new user registers.

    Sent to platform admins so the founder has a real-time pulse on signups
    and can spot abuse patterns (same IP repeatedly registering after rate
    limits expire).
    """
    flag_banner = ""
    if repeat_signups_from_ip > 0:
        flag_banner = (
            '<div style="margin:0 0 20px 0;padding:14px 16px;background-color:#3a1a1a;'
            'border:1px solid #b53a3a;border-radius:8px;color:#ffb4b4;font-size:14px;">'
            f'<strong>Warning:</strong> {repeat_signups_from_ip} other registration '
            f'attempt(s) from this IP in the last {repeat_window_days} days. Possible abuse — review before granting access.'
            '</div>'
        )

    waitlist_banner = ""
    if waitlisted:
        waitlist_banner = (
            '<div style="margin:0 0 20px 0;padding:14px 16px;background-color:#1a2a3a;'
            'border:1px solid #3a6aa3;border-radius:8px;color:#9ec5ff;font-size:14px;">'
            'This signup hit the Free-tier cap and was placed on the waitlist. '
            'No tenant was provisioned. Approve manually if you want to let them in.'
            '</div>'
        )

    title = "New T1 Agentics signup" if not waitlisted else "Free-tier waitlist entry"

    content = (
        _paragraph(
            f'<span style="font-size:18px;font-weight:600;color:#3CB371;">{title}</span>'
        )
        + flag_banner
        + waitlist_banner
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + _detail_row("Email", f'<a href="mailto:{email}" style="color:#3CB371;text-decoration:none;">{email}</a>')
        + _detail_row("Name", full_name if full_name else "<em style=\"color:#6e7681;\">Not provided</em>")
        + _detail_row("Workspace", f'{tenant_name} <span style="color:#8b949e;">({tenant_slug})</span>')
        + _detail_row("Plan", plan)
        + _detail_row("IP address", ip_address or "<em style=\"color:#6e7681;\">Unknown</em>")
        + _detail_row("Referral code", referral_code if referral_code else "<em style=\"color:#6e7681;\">None</em>")
        + '</table>'
        + _muted("You are receiving this because you are listed in <code>platform_admins</code> or <code>ADMIN_EMAIL</code>.")
    )
    return _base_layout(content, preheader=f"New signup: {email}")


def render_waitlist_email(email: str, tenant_name: str) -> str:
    """Render the email sent to a registrant who hit the Free-tier cap."""
    content = (
        _paragraph(f"Hi,")
        + _paragraph(
            "Thanks for signing up for <strong style=\"color:#3CB371;\">T1 Agentics</strong>. "
            "Our Free tier is currently at capacity while we work through onboarding for our "
            "earliest users one workspace at a time."
        )
        + _paragraph(
            f"We have placed <strong>{tenant_name}</strong> on the waitlist. "
            "When a Free seat opens up we will email you with the verification link. "
            "If you would like to skip the waitlist, you can pick a paid plan and we will "
            "provision your workspace immediately."
        )
        + _button("View paid plans", f"https://t1agentics.ai/pricing")
        + _muted(
            "Questions? Reply to this email and a real human (the founder) will get back to you."
        )
    )
    return _base_layout(content, preheader="You are on the T1 Agentics waitlist")


def render_admin_daily_summary(
    summary_date: str,
    total_cost_usd: float,
    total_calls: int,
    total_tokens: int,
    per_tenant_rows: list,
    new_signups_24h: int = 0,
    waitlisted_24h: int = 0,
    signups: list = None,
    public_triage: dict = None,
    lead_drafts: list = None,
) -> str:
    """Render the daily cost / activity summary email for platform admins.

    Parameters
    ----------
    summary_date : str
        ISO date the summary covers (e.g. "2026-04-26").
    per_tenant_rows : list of dict
        Each dict has keys: ``tenant_slug``, ``calls``, ``tokens``, ``cost_usd``.
    signups : list of dict, optional
        Per-signup detail rows with keys: ``email``, ``full_name``,
        ``tenant_name``, ``tenant_slug``, ``plan``, ``status``.
    public_triage : dict, optional
        Public /tools/triage demo totals: ``calls``, ``tokens``, ``cost_usd``.
    lead_drafts : list of dict, optional
        Pending inbound lead drafts for one-click approve/reject. Each dict:
        ``id, email, name, company, classification, confidence, reason,
        subject, body, approve_url, reject_url``.
    """
    signups = signups or []
    public_triage = public_triage or {"calls": 0, "tokens": 0, "cost_usd": 0.0}
    lead_drafts = lead_drafts or []
    rows_html = ""
    for row in per_tenant_rows[:25]:
        rows_html += (
            '<tr>'
            f'<td style="padding:8px 12px;font-size:13px;color:#f0f6fc;border-top:1px solid rgba(48,54,61,0.5);">{row.get("tenant_slug", "?")}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:#8b949e;text-align:right;border-top:1px solid rgba(48,54,61,0.5);">{row.get("calls", 0):,}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:#8b949e;text-align:right;border-top:1px solid rgba(48,54,61,0.5);">{row.get("tokens", 0):,}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:#3CB371;text-align:right;border-top:1px solid rgba(48,54,61,0.5);font-weight:600;">${row.get("cost_usd", 0.0):.2f}</td>'
            '</tr>'
        )

    if not rows_html:
        rows_html = (
            '<tr><td colspan="4" style="padding:16px;text-align:center;font-size:13px;color:#6e7681;">'
            'No Claude API activity recorded.'
            '</td></tr>'
        )

    signup_rows_html = ""
    for s in signups[:25]:
        name = s.get("full_name") or '<em style="color:#6e7681;">no name</em>'
        workspace = s.get("tenant_name") or s.get("tenant_slug") or ""
        status = s.get("status") or ""
        status_color = "#3CB371" if status not in ("waitlisted", "pending") else "#d29922"
        signup_rows_html += (
            '<tr>'
            f'<td style="padding:8px 12px;font-size:13px;color:#f0f6fc;border-top:1px solid rgba(48,54,61,0.5);">{s.get("email", "?")}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:#8b949e;border-top:1px solid rgba(48,54,61,0.5);">{name}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:#8b949e;border-top:1px solid rgba(48,54,61,0.5);">{workspace}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:#8b949e;border-top:1px solid rgba(48,54,61,0.5);">{s.get("plan", "")}</td>'
            f'<td style="padding:8px 12px;font-size:13px;color:{status_color};border-top:1px solid rgba(48,54,61,0.5);">{status}</td>'
            '</tr>'
        )

    signups_block = ""
    if signup_rows_html:
        signups_block = (
            '<p style="margin:0 0 8px 0;font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">Signups</p>'
            '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
            'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
            '<tr>'
            '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:left;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Email</th>'
            '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:left;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Name</th>'
            '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:left;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Workspace</th>'
            '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:left;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Plan</th>'
            '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:left;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Status</th>'
            '</tr>'
            + signup_rows_html
            + '</table>'
        )

    pt_calls = int(public_triage.get("calls") or 0)
    pt_tokens = int(public_triage.get("tokens") or 0)
    pt_cost = float(public_triage.get("cost_usd") or 0.0)
    grand_total = total_cost_usd + pt_cost

    # Lead-drafts block: one card per pending draft, with classification pill
    # and Approve / Reject buttons that hit signed-URL endpoints.
    drafts_block = ""
    if lead_drafts:
        class_colors = {
            "real_prospect": "#3CB371",
            "partner": "#3b82f6",
            "unknown": "#d29922",
            "competitor": "#8b949e",
            "noise": "#8b949e",
        }
        cards = []
        for d in lead_drafts[:20]:
            cls = (d.get("classification") or "unknown").lower()
            color = class_colors.get(cls, "#d29922")
            conf_pct = int(round(float(d.get("confidence") or 0) * 100))
            email_html = (d.get("email") or "").replace("<", "&lt;").replace(">", "&gt;")
            name = (d.get("name") or "").replace("<", "&lt;").replace(">", "&gt;")
            company = (d.get("company") or "").replace("<", "&lt;").replace(">", "&gt;")
            who = email_html
            if name or company:
                who = f"{name}{' &mdash; ' if name and company else ''}{company} &lt;{email_html}&gt;"
            reason = (d.get("reason") or "").replace("<", "&lt;").replace(">", "&gt;")
            subject = (d.get("subject") or "").replace("<", "&lt;").replace(">", "&gt;")
            body_raw = d.get("body") or ""
            body_paragraphs = "".join(
                f'<p style="margin:0 0 8px 0;font-size:13px;line-height:1.5;color:#c9d1d9;">{p.replace(chr(60),"&lt;").replace(chr(62),"&gt;")}</p>'
                for p in body_raw.split("\n\n") if p.strip()
            )
            action_buttons = ""
            if cls in ("real_prospect", "partner", "unknown") and subject and body_raw:
                action_buttons = (
                    '<div style="display:flex;gap:8px;margin-top:12px;">'
                    f'<a href="{d.get("approve_url", "#")}" '
                    'style="display:inline-block;padding:8px 14px;background-color:#3CB371;'
                    'color:#fff;text-decoration:none;border-radius:6px;font-size:12px;font-weight:600;">'
                    'Approve &amp; Send</a>'
                    f'<a href="{d.get("reject_url", "#")}" '
                    'style="display:inline-block;padding:8px 14px;background-color:transparent;'
                    'color:#8b949e;text-decoration:none;border:1px solid rgba(48,54,61,0.8);'
                    'border-radius:6px;font-size:12px;">Reject</a>'
                    '</div>'
                )
            else:
                action_buttons = (
                    f'<a href="{d.get("reject_url", "#")}" '
                    'style="display:inline-block;margin-top:12px;padding:6px 12px;background-color:transparent;'
                    'color:#8b949e;text-decoration:none;border:1px solid rgba(48,54,61,0.8);'
                    'border-radius:6px;font-size:12px;">Dismiss</a>'
                )
            cards.append(
                '<div style="margin:0 0 16px 0;padding:16px;background-color:#0d1117;'
                'border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">'
                f'<span style="padding:2px 8px;background-color:{color}25;color:{color};'
                f'border:1px solid {color}55;border-radius:4px;font-size:11px;font-weight:600;'
                f'text-transform:uppercase;letter-spacing:0.5px;">{cls.replace("_", " ")} {conf_pct}%</span>'
                f'<span style="font-size:11px;color:#6e7681;">via {d.get("source_type", "?")}</span>'
                '</div>'
                f'<div style="font-size:13px;color:#f0f6fc;margin-bottom:4px;"><strong>{who}</strong></div>'
                + (f'<div style="font-size:12px;color:#8b949e;margin-bottom:12px;">{reason}</div>' if reason else "")
                + (f'<div style="font-size:13px;color:#f0f6fc;margin:8px 0 6px 0;"><strong>Subject:</strong> {subject}</div>' if subject else "")
                + (f'<div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(48,54,61,0.5);">{body_paragraphs}</div>' if body_paragraphs else "")
                + action_buttons
                + '</div>'
            )
        drafts_block = (
            '<p style="margin:0 0 8px 0;font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">'
            f'Inbound leads &mdash; {len(lead_drafts)} pending review'
            '</p>'
            + "".join(cards)
        )

    content = (
        _paragraph(
            f'<span style="font-size:18px;font-weight:600;color:#3CB371;">Daily summary &mdash; {summary_date}</span>'
        )
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + _detail_row("Total spend", f'<strong style="color:#3CB371;">${grand_total:.2f}</strong>')
        + _detail_row("&nbsp;&nbsp;Tenant Claude usage", f'${total_cost_usd:.2f}')
        + _detail_row("&nbsp;&nbsp;Public /tools/triage demo", f'${pt_cost:.2f}')
        + _detail_row("Tenant API calls", f'{total_calls:,}')
        + _detail_row("Tenant tokens", f'{total_tokens:,}')
        + _detail_row("Public-triage calls", f'{pt_calls:,}')
        + _detail_row("Public-triage tokens", f'{pt_tokens:,}')
        + _detail_row("New signups (24h)", str(new_signups_24h))
        + _detail_row("Waitlisted (24h)", str(waitlisted_24h))
        + '</table>'
        + signups_block
        + drafts_block
        + '<p style="margin:0 0 8px 0;font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;">By tenant</p>'
        + '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
          'style="margin:0 0 24px 0;background-color:#0d1117;border:1px solid rgba(48,54,61,0.8);border-radius:8px;">'
        + '<tr>'
        + '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:left;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Tenant</th>'
        + '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:right;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Calls</th>'
        + '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:right;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Tokens</th>'
        + '<th style="padding:8px 12px;font-size:11px;color:#6e7681;text-align:right;text-transform:uppercase;letter-spacing:0.5px;font-weight:500;">Cost</th>'
        + '</tr>'
        + rows_html
        + '</table>'
        + _muted(
            f"Daily kill-switch: <code>CLAUDE_MAX_DAILY_USD</code>. "
            "Adjust in droplet env if this number is climbing."
        )
    )
    return _base_layout(content, preheader=f"Yesterday's total spend: ${grand_total:.2f}")


def render_password_reset_email(reset_url: str, username: str) -> str:
    """Render the password-reset email.

    Parameters
    ----------
    reset_url : str
        The full URL with a one-time reset token.
    username : str
        The account username requesting the reset.
    """
    content = (
        _paragraph(f"Hi {username},")
        + _paragraph(
            "We received a request to reset the password for your "
            "<strong style=\"color:#3CB371;\">T1 Agentics</strong> account. "
            "Click the button below to choose a new password."
        )
        + _button("Reset Password", reset_url)
        + _muted(
            "This link will expire in <strong>1 hour</strong>. "
            "If you did not request a password reset, you can safely ignore this email. "
            "Your password will remain unchanged."
        )
        + _muted(
            "If the button above does not work, copy and paste the following URL "
            "into your browser:"
        )
        + f'<p style="margin:0 0 16px 0;font-size:12px;line-height:1.4;color:#8b949e;word-break:break-all;">{reset_url}</p>'
    )
    return _base_layout(content, preheader="Reset your T1 Agentics password")
