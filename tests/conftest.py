"""Shared fixtures."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import ldap_server  # noqa: E402


@pytest.fixture(scope="session")
def slapd(tmp_path_factory):
    """A running private OpenLDAP server (see ``tests/ldap_server.py``)."""
    reason = ldap_server.available()
    if reason:
        pytest.skip(reason)
    server = ldap_server.start(tmp_path_factory.mktemp("slapd"))
    yield server
    server.stop()
