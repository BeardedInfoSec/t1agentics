"""Pytest fixtures for triage contract tests.

Run only when explicitly invoked:  pytest -m droplet -v tests/triage_contract
"""
from __future__ import annotations

import pytest

from .helpers import droplet


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "droplet: triage contract test that hits the live droplet (barbas rooster co tenant)",
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark every test in this dir with @pytest.mark.droplet."""
    for item in items:
        if "triage_contract" in str(item.fspath):
            item.add_marker(pytest.mark.droplet)


@pytest.fixture(scope="session")
def webhook():
    """Session-scoped webhook in barbas rooster co. Cleaned up at session end."""
    creds = droplet.create_test_webhook()
    yield creds
    droplet.delete_webhook(creds.name)


@pytest.fixture(scope="session", autouse=True)
def cleanup_at_session_end():
    """Hard cleanup of all TEST_MARKER artifacts before AND after the session."""
    droplet.cleanup_test_artifacts()
    yield
    counts = droplet.cleanup_test_artifacts()
    print(f"\n[triage_contract cleanup] {counts}")
