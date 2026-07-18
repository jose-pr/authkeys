"""File source: reads ~/.ssh/authorized_keys, skipping blanks/comments.

`pwd` is POSIX-only, so we inject a fake module to run cross-platform.
"""

import sys
import types

import pytest

from authkeys import AuthkeysConfig
from authkeys.sources.file import AuthorizedKeysFiles

RSA = "ssh-rsa AAAAB3Nza alice@host"


@pytest.fixture
def fake_pwd(monkeypatch, tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)

    fake = types.ModuleType("pwd")

    def getpwnam(name):
        return types.SimpleNamespace(pw_name=name, pw_dir=str(home))

    fake.getpwnam = getpwnam  # type: ignore
    monkeypatch.setitem(sys.modules, "pwd", fake)
    return home


def _source():
    conf = AuthkeysConfig.from_config({"source:files": {}})
    return AuthorizedKeysFiles(conf["source:files"], {})


def test_reads_keys_skipping_blanks_and_comments(fake_pwd):
    (fake_pwd / ".ssh" / "authorized_keys").write_text(
        f"# comment\n\n{RSA}\n   \n"
    )
    keys = list(_source().authorized_keys("alice"))
    assert keys == [RSA]


def test_missing_user_yields_nothing(monkeypatch):
    fake = types.ModuleType("pwd")

    def getpwnam(name):
        raise KeyError(name)

    fake.getpwnam = getpwnam  # type: ignore
    monkeypatch.setitem(sys.modules, "pwd", fake)
    assert list(_source().authorized_keys("ghost")) == []


def test_reads_multiple_key_files(fake_pwd):
    (fake_pwd / ".ssh" / "authorized_keys").write_text(f"{RSA}\n")
    (fake_pwd / ".ssh" / "authorized_keys2").write_text("ssh-ed25519 BBBB k2\n")
    keys = list(_source().authorized_keys("alice"))
    assert len(keys) == 2
