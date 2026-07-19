"""GitHub `.keys` source: URL templating, percent-encoding, non-2xx handling.

`requests` is faked (like `pwd` is faked for file-source tests) so these run
without the optional `[http]` extra installed and without a network call.
"""

import sys
import types

import pytest

from authkeys import AuthkeysConfig
from authkeys.sources.github import GithubKeys

RSA = "ssh-rsa AAAAB3Nza"
ED = "ssh-ed25519 AAAAC3Nza"


class FakeResponse:
    def __init__(self, content: bytes, status: int = 200):
        self.content = content
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")


class FakeSession:
    """Records the last request; returns a preconfigured `FakeResponse`."""

    instances = []

    def __init__(self):
        self.last_url = None
        self.last_kwargs = None
        self.response = FakeResponse(b"")
        FakeSession.instances.append(self)

    def get(self, url, **kwargs):
        self.last_url = url
        self.last_kwargs = kwargs
        return self.response


@pytest.fixture
def fake_requests(monkeypatch):
    FakeSession.instances.clear()
    fake = types.ModuleType("requests")
    fake.Session = FakeSession  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "requests", fake)
    return fake


def _source(fake_requests, section="source:github", options=None):
    conf = AuthkeysConfig.from_config({section: options or {}})
    return GithubKeys(conf[section], {})


def test_fetches_keys_from_default_github_url(fake_requests):
    src = _source(fake_requests)
    session = FakeSession.instances[-1]
    session.response = FakeResponse(f"{RSA}\n{ED}\n".encode())

    keys = list(src.authorized_keys("alice"))

    assert keys == [RSA, ED]
    assert session.last_url == "https://github.com/alice.keys"


def test_username_is_percent_encoded(fake_requests):
    src = _source(fake_requests)
    session = FakeSession.instances[-1]
    session.response = FakeResponse(b"")

    list(src.authorized_keys("weird user/name"))

    assert session.last_url == "https://github.com/weird%20user%2Fname.keys"


def test_custom_url_template_eg_gitlab(fake_requests):
    src = _source(
        fake_requests,
        options={"url": "https://gitlab.com/{username}.keys"},
    )
    session = FakeSession.instances[-1]
    session.response = FakeResponse(f"{RSA}\n".encode())

    keys = list(src.authorized_keys("bob"))

    assert keys == [RSA]
    assert session.last_url == "https://gitlab.com/bob.keys"


def test_non_2xx_raises(fake_requests):
    src = _source(fake_requests)
    session = FakeSession.instances[-1]
    session.response = FakeResponse(b"", status=404)

    with pytest.raises(RuntimeError):
        list(src.authorized_keys("ghost"))


def test_blank_and_comment_lines_skipped(fake_requests):
    src = _source(fake_requests)
    session = FakeSession.instances[-1]
    session.response = FakeResponse(f"# comment\n\n{RSA}\n   \n".encode())

    assert list(src.authorized_keys("alice")) == [RSA]
