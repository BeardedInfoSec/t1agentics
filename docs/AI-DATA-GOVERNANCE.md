# T1 Agentics AI Data Governance Policy

**Effective Date:** February 2026
**Version:** 1.0
**Contact:** privacy@t1agentics.ai

---

## Our Position, Plainly Stated

Your data is yours. We don't want it. We don't store it. We don't sell it. We don't train on it. We don't share it. We use AI to analyze your security alerts in real time, and then we throw away the conversation. That's it.

This document explains exactly how your data flows through our AI systems, what we keep, what we don't, and what your rights are.

---

## 1. How AI Works in T1 Agentics

T1 Agentics uses large language models (LLMs) to analyze security alerts, assist SOC analysts, and generate playbooks. Here's the data lifecycle for every AI interaction:

```
Your Alert Data → T1 Backend → AI Provider API → Analysis Response → Your Dashboard
 
 
 
 Token counts Structured results
 (billing only) (verdict, summary)
 
 
 ai_token_usage investigation_data
 table (metadata) (your tenant, encrypted)
```

### What happens step by step:

1. **Alert arrives** Your SIEM, EDR, or email gateway sends an alert to T1 via webhook or API.
2. **Prompt is built** T1 constructs an analysis prompt containing the alert title, description, and extracted indicators (IPs, domains, hashes). PII is obfuscated before transmission.
3. **AI processes** The prompt is sent to the AI provider's API. The AI returns a structured analysis (verdict, confidence, MITRE mapping, recommendations).
4. **Response is parsed** T1 extracts structured fields from the AI response and stores them as investigation results in your tenant's database.
5. **Prompt and raw response are discarded** T1 does **not** log, store, or persist the raw prompt text or raw AI response text. Only the structured output is retained.
6. **Usage metadata is recorded** Token counts, cost, model name, and response time are logged for billing and quota enforcement. No content is stored.

---

## 2. What We Store

| Data | Stored? | Purpose | Retention |
|------|---------|---------|-----------|
| Alert data (title, description, IOCs) | Yes | Your security data, in your tenant | Your retention policy |
| Investigation results (verdict, summary, MITRE) | Yes | Structured AI output, in your tenant | Your retention policy |
| Raw AI prompt text | **No** | Not stored anywhere | N/A |
| Raw AI response text | **No** | Discarded after parsing | N/A |
| AI conversation history | **No** | No conversation state maintained | N/A |
| Token usage counts | Yes | Billing and quota enforcement | 12 months |
| Model name and response time | Yes | Performance monitoring | 12 months |
| Cost per request | Yes | Billing | 12 months |

### What "not stored" means:

- The prompt text exists only in memory during the API call.
- Once the HTTP response is received and parsed, both the prompt and raw response are garbage-collected.
- There is no database table, log file, message queue, or cache that retains AI prompts or responses.
- Backend log level is set to WARNING in production prompts are never logged even at debug level.

---

## 3. What We Don't Do

**We do not train AI models on your data.**
T1 Agentics does not operate, fine-tune, or train any AI models. We are an API consumer, not a model provider. Your data is never used to improve, train, or benchmark any AI system.

**We do not sell your data.**
Your data is never sold, licensed, shared, or transferred to any third party for any purpose commercial, research, or otherwise.

**We do not share your data with other tenants.**
T1 Agentics is a multi-tenant platform with strict tenant isolation. Your data is scoped to your tenant at the database level. No data crosses tenant boundaries. Row-level security policies enforce this at the PostgreSQL layer.

**We do not retain AI interactions.**
There is no "AI conversation log" in T1. Each AI call is stateless a prompt goes in, a response comes out, and the raw text is discarded. We store the structured results (which are useful to you), not the AI conversation (which isn't).

**We do not use your data for analytics, benchmarking, or product improvement.**
We don't aggregate your alert data, investigation outcomes, or AI interactions for internal analytics. We don't build dashboards about what our customers' threats look like. Your operational data stays in your tenant.

---

## 4. Our AI Provider

T1 Agentics uses a commercial, enterprise-grade LLM API as its AI provider. We select providers that meet strict data governance requirements. Here's what we require of any AI provider we work with:

### Provider Data Handling Requirements

- **No training on customer data.** Our AI provider contractually agrees not to use data submitted through their commercial API to train or improve their models.
- **Limited retention for safety.** The provider may retain API inputs and outputs for up to 30 days solely for safety monitoring and abuse prevention, after which they are deleted.
- **No human review by default.** API data is not reviewed by provider employees unless required for safety investigation of flagged content.
- **SOC 2 Type II certified.** Our AI provider maintains SOC 2 Type II compliance for their API infrastructure.

We evaluate these terms on an ongoing basis and will notify customers if our AI provider changes or if their data handling terms materially change.

### Platform Key Model

T1 Agentics operates a "platform key" model we hold the AI provider API key, not individual tenants. This means:

- Tenants never interact with the AI provider directly.
- Tenants never need their own AI API keys.
- T1 controls the data boundary we decide what goes to the AI and what stays local.
- All AI calls go through our internal AI gateway, which enforces quotas, tracks usage, and applies PII obfuscation before transmission.

---

## 5. Data Minimization

We send the minimum data necessary for effective analysis:

### What gets sent to the AI:

- Alert title and description
- Extracted indicators of compromise (IPs, domains, hashes, emails)
- Alert source and severity metadata
- Correlated alert summaries (for context)

### What never gets sent to the AI:

- User credentials or passwords
- API keys or integration tokens
- Tenant configuration or billing data
- Other tenants' data (enforced by tenant isolation)
- Full raw log events (truncated and sanitized before transmission)
- PII (obfuscated by our PII service before prompt construction)

### PII Obfuscation

Before any data reaches the AI provider, our PII obfuscation service automatically masks:
- Social Security Numbers
- Credit card numbers
- Personal email addresses (non-IOC context)
- Custom patterns defined by your organization

---

## 6. Tenant Data Isolation

### Database-Level Isolation

Every database query is scoped to the requesting tenant via:

- **Tenant middleware** Sets tenant context from JWT/API key on every request.
- **Row-level security** PostgreSQL policies enforce that tenants can only access their own rows.
- **Tenant-aware connection pool** Every database connection sets `app.current_tenant_id` as a session variable.

### AI Call Isolation

Each AI call is:
- Scoped to a single tenant's data
- Executed with the tenant's quota and billing context
- Logged to the tenant's usage records
- Never batched or combined across tenants

---

## 7. Data Retention and Deletion

### Active Tenants

- Investigation results are retained for as long as your subscription is active.
- You control your own data retention settings.
- You can delete investigations, alerts, and playbooks at any time.

### After Subscription Ends

- Your tenant is downgraded to the Community (free) tier.
- All data remains accessible for **90 days** after your last payment.
- Self-service data export is available throughout this period.
- After 90 days, all tenant data is permanently deleted no exceptions, no hidden copies.

### AI Usage Records

- Token usage metadata (counts, costs) is retained for 12 months for billing audit purposes.
- Usage records contain no prompt content only token counts, model names, timestamps, and cost.
- After 12 months, usage records are purged.

---

## 8. Data Export

You can export all of your data at any time:

- **Formats:** JSON, CSV, or direct S3 bucket transfer
- **Scope:** Alerts, investigations, playbooks, configurations, IOC data, audit logs
- **Access:** Self-service from the dashboard (Pro+) or by request (Community)
- **AI data included:** Structured investigation results (verdicts, summaries, MITRE mappings) are included in exports. Raw AI prompts/responses are not included because they are not stored.

---

## 9. Compliance Alignment

This AI data governance policy supports compliance with:

| Framework | Relevant Controls |
|-----------|-------------------|
| **SOC 2 Type II** | CC6.1 (logical access), CC6.7 (data transmission), CC7.2 (monitoring) |
| **GDPR** | Art. 5 (data minimization), Art. 28 (processor obligations), Art. 32 (security) |
| **CCPA** | 1798.100 (right to know), 1798.105 (right to delete), 1798.120 (right to opt-out of sale) |
| **HIPAA** | 164.312 (technical safeguards), 164.502 (uses and disclosures) |
| **NIST CSF** | PR.DS-1 (data-at-rest), PR.DS-2 (data-in-transit), PR.PT-3 (least functionality) |

---

## 10. Your Rights

As a T1 Agentics customer, you have the right to:

1. **Know** what data we process and how this document fulfills that obligation.
2. **Export** all of your data at any time, in standard formats.
3. **Delete** your data, including requesting full tenant deletion.
4. **Opt out** of AI features entirely alerts can be triaged manually without AI.
5. **Audit** your AI usage through the token usage dashboard and audit logs.
6. **Request** a Data Processing Agreement (DPA) for your compliance requirements.

---

## 11. Subprocessor List

| Subprocessor | Purpose | Data Shared |
|-------------|---------|-------------|
| **AI Provider** | LLM analysis via commercial API | Alert metadata, IOCs (PII-obfuscated) |
| **DigitalOcean** | Infrastructure hosting | All tenant data (encrypted at rest) |
| **Stripe** | Billing and payments | Billing email, payment method (no alert data) |

We will notify customers 30 days before adding a new subprocessor that handles customer data.

---

## 12. Incident Response

In the event of a data breach affecting AI-processed data:

1. We will notify affected tenants within **72 hours** of confirmed breach.
2. We will provide a full accounting of what data was affected.
3. We will engage third-party forensic investigators if warranted.
4. Because we don't store raw AI prompts/responses, the blast radius of any breach is limited to structured investigation results within tenant-isolated database rows.

---

## 13. Changes to This Policy

We will notify all active customers at least 30 days before making material changes to this policy. Minor clarifications or formatting changes may be made without notice.

The current version is always available at `docs/AI-DATA-GOVERNANCE.md` in the T1 Agentics codebase and will be published on our website.

---

## Summary

| Question | Answer |
|----------|--------|
| Do you store our AI prompts? | No. |
| Do you store AI responses? | Only structured results (verdicts, summaries). Not raw text. |
| Do you train models on our data? | No. We don't train or operate any models. |
| Do you sell our data? | No. Never. |
| Do you share data between tenants? | No. Strict tenant isolation at every layer. |
| Does your AI provider train on our data? | No. Our provider's commercial API terms prohibit this. |
| Can we export our data? | Yes. Anytime. JSON, CSV, or S3. |
| Can we delete our data? | Yes. Immediately or via 90-day post-cancellation window. |
| Can we opt out of AI? | Yes. Manual triage is always available. |

---

**T1 Agentics LLC**
**Last Updated:** February 2026
