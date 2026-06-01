#!/usr/bin/env python3
"""
draft_release_notes.py — Draft release-note markdown from git commit history.

Finds the most recent file in frontend/public/_release-notes/, takes its date as
the lower bound, and groups every commit since that date into thematic buckets
based on simple keyword heuristics on the commit subject.

Outputs:
  - stdout: a paste-ready markdown body for `<today>.md`.
  - stderr (after a trailing `---` divider on stdout): a one-line JSON object
    suitable for prepending to `frontend/public/_release-notes/index.json`.

The author still owns the title and summary — both are emitted as `TODO:` so
they're impossible to miss.

Usage (from repo root):
    python scripts/draft_release_notes.py > frontend/public/_release-notes/$(date +%Y-%m-%d).md

If there are zero commits since the most recent release file, the script exits
0 with a stderr-only message and writes nothing to stdout.

Stdlib only. No external dependencies.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path


# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------

# Repo-relative path to the release-notes directory. The script assumes it
# lives at <repo>/scripts/draft_release_notes.py, so the repo root is its
# parent's parent.
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RELEASE_NOTES_DIR = REPO_ROOT / "frontend" / "public" / "_release-notes"

# Filename pattern for a release-note markdown file.
DATE_FILENAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.md$")

# Safe delimiter for `git log --pretty=format:`. A pipe is risky because
# commit subjects can legitimately contain `|`. Use a control character that
# essentially never appears in subjects: ASCII Unit Separator (0x1F).
LOG_DELIM = "\x1f"

# Theme buckets, in display order. Each entry: (header, [patterns]).
# Patterns are matched case-insensitively against the full commit subject.
# Order matters — the first matching theme wins. "Fixes" is intentionally
# checked late so a "Fix: dashboard X" still lands under Dashboards if it's
# really a dashboard change… actually the user spec says "Fix:" goes to
# Fixes. We match in spec order so Fixes wins for "Fix:" / "Fix " prefixes.
#
# The spec listed themes in this order:
#   Dashboards, Intake Forms, Riggs/AI, Notifications, Search, Playbooks,
#   BYO LLM, Fixes, Release notes
# Fixes comes before Release notes per the spec, and we honor the listed
# order so e.g. "Fix: search bug" lands under Fixes (the spec example
# "Fix: ... both go to Fixes" makes this intent explicit).
THEMES: list[tuple[str, list[str]]] = [
    ("Dashboards", ["dashboard", "soc", "chart", "widget"]),
    ("Intake Forms", ["intake", "intake form", "submission"]),
    ("Riggs / AI", ["riggs", "ai triage", "t1 triage", "prompt"]),
    ("Notifications", ["notification", "notif", "bell"]),
    ("Search", ["search", "fts", "global search"]),
    ("Playbooks", ["playbook"]),
    ("BYO LLM", ["byo llm", "byo_", "tenant_ai", "byo-"]),
    ("Fixes", [r"\bfix:", r"\bfix\b", "bug"]),
    ("Release notes", ["release notes"]),
]

OTHER_HEADER = "Other"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def find_last_release_date() -> dt.date | None:
    """Return the date of the most recent release-note markdown file, or None.

    Scans `frontend/public/_release-notes/` for files matching `YYYY-MM-DD.md`
    and returns the maximum date. Returns None if the directory is missing or
    contains no matching files.
    """
    if not RELEASE_NOTES_DIR.is_dir():
        return None

    dates: list[dt.date] = []
    for entry in RELEASE_NOTES_DIR.iterdir():
        m = DATE_FILENAME_RE.match(entry.name)
        if not m:
            continue
        try:
            dates.append(dt.date.fromisoformat(m.group(1)))
        except ValueError:
            continue

    return max(dates) if dates else None


def git_commits_since(since_date: dt.date) -> list[tuple[str, str, str]]:
    """Return commits authored strictly AFTER `since_date`.

    Each tuple is (short_hash, iso_author_date, subject). We pass
    `--since="YYYY-MM-DD 23:59:59"` to git so that commits made on the same
    calendar day as the last release are not re-included.
    """
    fmt = LOG_DELIM.join(["%h", "%ai", "%s"])
    # End-of-day cutoff so we don't double-list commits from the release day.
    since_arg = f"{since_date.isoformat()} 23:59:59"

    try:
        result = subprocess.run(
            [
                "git",
                "log",
                f"--since={since_arg}",
                f"--pretty=format:{fmt}",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        sys.stderr.write("error: git not found on PATH\n")
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"error: git log failed: {e.stderr}\n")
        sys.exit(2)

    commits: list[tuple[str, str, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        # Split with maxsplit=2 so any stray delimiters in the subject stay
        # in the subject field (defensive even though LOG_DELIM is 0x1F).
        parts = line.split(LOG_DELIM, 2)
        if len(parts) != 3:
            continue
        commits.append((parts[0], parts[1], parts[2]))
    return commits


def classify(subject: str) -> str:
    """Return the theme header for a commit subject.

    Matching is case-insensitive. Patterns are tried in spec order; first hit
    wins. Anything unmatched lands in "Other".
    """
    s = subject.lower()
    for header, patterns in THEMES:
        for pat in patterns:
            # Treat patterns starting with `\b` as regex; otherwise plain
            # substring. Keeps the config readable while still letting us
            # express word-boundary intent for "fix".
            if pat.startswith(r"\b"):
                if re.search(pat, s):
                    return header
            else:
                if pat in s:
                    return header
    return OTHER_HEADER


def group_commits(
    commits: list[tuple[str, str, str]],
) -> dict[str, list[tuple[str, str]]]:
    """Group commits into themed buckets. Returns {header: [(subject, hash)]}.

    Preserves git-log order within each bucket (most recent first).
    """
    groups: dict[str, list[tuple[str, str]]] = {}
    for short_hash, _date, subject in commits:
        header = classify(subject)
        groups.setdefault(header, []).append((subject, short_hash))
    return groups


def render_markdown(
    today: dt.date,
    groups: dict[str, list[tuple[str, str]]],
) -> str:
    """Render the markdown body. Skips empty groups."""
    version = today.strftime("%Y.%m.%d")
    lines: list[str] = [
        f"# {version} — TODO: write a title",
        "",
        "TODO: write a one-paragraph summary.",
        "",
    ]

    # Emit themes in the canonical order, then Other last.
    ordered_headers = [h for h, _ in THEMES] + [OTHER_HEADER]
    for header in ordered_headers:
        bucket = groups.get(header)
        if not bucket:
            continue
        lines.append(f"## {header}")
        lines.append("")
        for subject, short_hash in bucket:
            lines.append(f"- {subject} ({short_hash})")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_index_entry(today: dt.date) -> str:
    """Render the one-line JSON object for index.json."""
    entry = {
        "version": today.strftime("%Y.%m.%d"),
        "date": today.isoformat(),
        "title": "TODO: write a title",
        "summary": "TODO: write a one-paragraph summary",
        "file": f"{today.isoformat()}.md",
    }
    # Compact one-liner — easy to paste into the manifest's `releases` array.
    return json.dumps(entry, ensure_ascii=False)


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------


def _force_utf8_streams() -> None:
    """Best-effort reconfigure stdout/stderr to UTF-8.

    Commit subjects can contain non-ASCII glyphs (arrows, em-dashes, smart
    quotes). The default Windows console encoding (cp1252) crashes on those.
    Python 3.7+ exposes `reconfigure` on TextIOWrapper; we use it when
    available and silently skip otherwise.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main() -> int:
    _force_utf8_streams()
    today = dt.date.today()

    last_date = find_last_release_date()
    if last_date is None:
        last_date = today - dt.timedelta(days=7)
        sys.stderr.write(
            f"note: no existing release-note files found; defaulting to "
            f"7 days ago ({last_date.isoformat()}).\n"
        )

    commits = git_commits_since(last_date)
    if not commits:
        sys.stderr.write(
            f"No new commits since {last_date.isoformat()} — nothing to draft.\n"
        )
        return 0

    groups = group_commits(commits)
    markdown = render_markdown(today, groups)
    index_entry = render_index_entry(today)

    # stdout: the markdown body, then a `---` separator, then the JSON line.
    # This way `python ... > file.md` captures the markdown plus a clearly-
    # marked appendix the author can copy-paste into index.json and then trim.
    sys.stdout.write(markdown)
    sys.stdout.write("\n---\n")
    sys.stdout.write("<!-- paste-ready index.json entry below; remove before publishing -->\n")
    sys.stdout.write(index_entry + "\n")

    # Also echo the JSON entry to stderr so it survives `> file.md` redirection.
    sys.stderr.write(index_entry + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
