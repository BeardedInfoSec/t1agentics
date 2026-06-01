# T1 Agentics Documentation

This directory contains the in-depth documentation that ships with T1 Agentics.
Start at the repository root for installation, project overview, and security
contact information (`README.md`, `INSTALL.md`, `OVERVIEW.md`, `SECURITY.md`,
`CONTRIBUTING.md`). The files here go deeper on specific subsystems and
day-to-day operation.

## Top-level guides

- [USER-GUIDE.md](USER-GUIDE.md) — end-user guide for SOC analysts using the
  platform (alerts, investigations, playbooks, MFA).
- [ADMIN-GUIDE.md](ADMIN-GUIDE.md) — operator guide: configuration, user
  management, AI provider setup, backups, monitoring, upgrades.
- [API-REFERENCE.md](API-REFERENCE.md) — REST API endpoint reference.
- [MFA-SETUP-GUIDE.md](MFA-SETUP-GUIDE.md) — enabling TOTP-based multi-factor
  authentication.
- [SECURITY.md](SECURITY.md) — security architecture, hardening notes, and
  audit-logging behaviour. (For reporting a vulnerability, see the root
  `SECURITY.md` instead.)
- [AI-DATA-GOVERNANCE.md](AI-DATA-GOVERNANCE.md) — what data is sent to LLM
  providers, retention controls, and per-tenant quota knobs.

## Subsystem deep-dives

- [multi-tenant-architecture.md](multi-tenant-architecture.md) — tenant
  isolation, row-level security, and the auth model.
- [ENTITY_CORRELATION_SYSTEM.md](ENTITY_CORRELATION_SYSTEM.md) — hypothesis
  -driven alert correlation engine.

## Developer / operator guides

- [guides/API_AUTHENTICATION_REFERENCE.md](guides/API_AUTHENTICATION_REFERENCE.md)
  — auth methods, session cookies, and CSRF handling.
- [guides/FRONTEND_DEV_SETUP.md](guides/FRONTEND_DEV_SETUP.md) — local
  frontend development environment.
- [guides/HTTPS_SETUP.md](guides/HTTPS_SETUP.md) — TLS configuration (self
  -signed, Let's Encrypt, and bring-your-own-CA).
- [guides/SECURITY_DEVELOPER_GUIDE.md](guides/SECURITY_DEVELOPER_GUIDE.md) —
  secure-coding patterns used in the codebase (RLS context, credential vault,
  rate limiting, etc.).

## License

This project is released under the Apache License 2.0. See the `LICENSE` file
at the repository root for the full text.
