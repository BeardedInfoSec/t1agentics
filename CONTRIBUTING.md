# Contributing to T1 Agentics

Thanks for considering a contribution. This document covers what we accept, how to file an issue, how to propose a feature, and how to get a pull request merged.

## Scope of accepted contributions

We actively want:

- Bug fixes with a clear reproduction
- New connectors (extending the integration catalog)
- New playbook templates
- New knowledge-base articles
- Documentation improvements
- Performance and security fixes
- Well-scoped feature work that has been discussed in an issue or discussion first

We are slower to accept:

- Large refactors that touch many files at once
- Changes that add a new top-level dependency
- Reformatting-only PRs
- Speculative features that have not been discussed

If you are not sure whether something fits, open a Discussion before writing code.

## Reporting bugs

File a [GitHub Issue](https://github.com/BeardedInfoSec/t1agentics/issues) with:

- What you ran (commands, version, OS)
- What you expected to happen
- What actually happened (logs, error messages, screenshots)
- Steps to reproduce
- Whether the bug is reproducible on a fresh install

For security vulnerabilities, do not file a public issue. See [SECURITY.md](SECURITY.md).

## Proposing features

Open a [GitHub Discussion](https://github.com/BeardedInfoSec/t1agentics/discussions) first. Outline:

- The problem you are trying to solve
- Who it is for (analysts, MSP operators, tenant admins, platform admins)
- A rough sketch of the approach
- Anything you have already tried

A maintainer will weigh in within a few business days. Once the approach has rough consensus, file the issue and start work.

## Pull request process

1. Fork the repository.
2. Create a branch from `main`. Branch naming is up to you; descriptive is better than clever.
3. Make your change. Keep the diff focused — one logical change per PR.
4. Add or update tests where appropriate.
5. Update documentation if you changed user-visible behavior.
6. Run the linters and tests locally (see below).
7. Open the PR against `main`. In the description, link the issue or discussion, summarize the change, and call out anything reviewers should look at carefully.
8. At least one maintainer review is required to merge. Address review feedback by pushing new commits to the same branch; we squash on merge.

For larger changes, draft PRs are welcome — open one early to get feedback on direction before you polish.

## Development setup

```bash
# Clone your fork
git clone https://github.com/your-username/t1agentics.git
cd t1agentics

# Bring up the stack for local dev
docker compose up -d

# Run the backend tests
docker compose exec backend pytest

# Frontend dev server (live-reload, talks to the backend container)
cd frontend
npm install
npm start
```

The frontend dev server runs on port 3000 and proxies API calls to the backend on port 8000. Backend code in the container hot-reloads on save when running with `--reload`; for most flows you can also `docker compose restart backend` after editing.

Database migrations apply automatically on backend startup. To reset to a clean slate:

```bash
docker compose down -v
docker compose up -d
```

## Code style

**Python.** The repo does not enforce a formatter in CI, but new code should match the existing style:

- 4-space indentation
- Type hints on public functions
- f-strings, not `.format()` or `%`
- Async-first; use `asyncpg` directly for new database code unless touching the `platform_core/` subsystem which uses SQLAlchemy

If you want to run a formatter locally, [Black](https://black.readthedocs.io/) with default settings and [Ruff](https://docs.astral.sh/ruff/) for linting will not fight the existing code.

**JavaScript / React.** The frontend uses Create React App defaults:

- 2-space indentation
- Functional components with hooks
- One component per file
- No emojis in UI strings (this is a project-wide rule)

Prettier with defaults and ESLint with the `react-app` config (already in `frontend/package.json`) keep you in line.

**Commit messages.** Short imperative subject line ("Add Splunk connector", not "Added"). Wrap the body at 72 columns if there is one.

## Adding a connector

Connectors live in `integration-store-output/`. The simplest path is to copy an existing connector definition closest to what you are wrapping, edit the manifest, and add any new action handlers.

## Adding a playbook template

Playbook templates live in `playbook-store-output/playbooks/`. They are JSON files describing the canvas graph. The simplest path is to author one in the visual editor, export it, and submit the JSON.

## Adding a knowledge-base article

Knowledge-base articles live in `kb-content-output/articles/`. Markdown with YAML frontmatter (title, domain, tags). The schema is documented at the top of any existing article.

## Sign-off (DCO)

We do not require a signed Contributor License Agreement, but please sign your commits with `git commit -s` to indicate you have the right to contribute the code under Apache-2.0. This adds a `Signed-off-by` line and certifies the [Developer Certificate of Origin](https://developercertificate.org/).

## Questions

Open a Discussion. We will get back to you.
