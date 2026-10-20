"""Files the target user controls: the delegation file and authorized_keys are read
under sshd-like StrictModes checks, get no environment expansion, and a grant ends
when its file does. Also: key-type validation, `%` in values, `max_stale`."""

import configparser
import os
import stat
import time
import types
from pathlib import Path

import pytest

from authkeys import AuthKeys, AuthkeysConfig, AuthkeysSource, AuthorizedKey, Source
from authkeys import _describe_config_error, utils
from authkeys.cache import AuthKeysCache, AuthKeysCacheMemBackend

ED = "ssh-ed25519 AAAAC3Nza"


class Keys(AuthkeysSource):
    def __init__(self, keys):
        self.keys = keys

    def authorized_keys(self, username):
        return list(self.keys.get(username, []))


def _auth(tmp_path, keys, monkeypatch):
    # A passwd entry for every test user, owning the files the test writes.
    monkeypatch.setattr(
        utils,
        "get_user",
        lambda username=None: types.SimpleNamespace(
            pw_name=username, pw_dir=str(tmp_path), pw_uid=getattr(os, "getuid", lambda: 0)()
        ),
    )
    auth = AuthKeys()
    auth.sources = {
        "s": Source(cached=False, enabled=True, backend=Keys(keys), sanitize=None, expire=None)
    }
    conf = tmp_path / "authkeys.conf"
    auth.user_config_path = lambda username: conf
    return auth, conf


def test_delegation_file_gets_no_environment(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("AUTHKEYS_APIKEY", "TOPSECRET")
    auth, conf = _auth(tmp_path, {}, monkeypatch)
    conf.write_text("[authorized]\nusers = ${env:AUTHKEYS_APIKEY}\n")
    auth.resolve("mallory")
    assert auth.users["mallory"].authorized_users == ["${env:AUTHKEYS_APIKEY}"]
    assert not any("TOPSECRET" in r.getMessage() for r in caplog.records)


def test_grant_ends_when_the_file_breaks_or_goes(tmp_path, monkeypatch):
    auth, conf = _auth(tmp_path, {"bob": [f"{ED} bob@x"]}, monkeypatch)
    conf.write_text("[authorized]\nusers = bob\n")
    assert [k.key for k in auth.resolve("alice")] == ["AAAAC3Nza"]
    conf.write_text("users = bob\n")  # no section header
    assert auth.resolve("alice") == []
    conf.write_text("[authorized]\nusers = bob\n")
    auth.resolve("alice")
    conf.unlink()
    assert auth.resolve("alice") == []


def test_missing_delegation_file_logs_nothing(tmp_path, monkeypatch, caplog):
    auth, _ = _auth(tmp_path, {}, monkeypatch)
    auth.resolve("bob")
    assert [r for r in caplog.records if r.levelname == "WARNING"] == []


def test_broken_delegation_file_is_named_by_line_not_content(tmp_path, monkeypatch, caplog):
    auth, conf = _auth(tmp_path, {}, monkeypatch)
    conf.write_text("secret line one\n")
    auth.resolve("alice")
    messages = [r.getMessage() for r in caplog.records]
    assert any("MissingSectionHeaderError at line 1" in m for m in messages)
    assert not any("secret line" in m for m in messages)


def test_describe_config_error_never_quotes_text():
    with pytest.raises(configparser.Error) as info:
        AuthkeysConfig.from_config(b"[authorized]\nusers = a\nnot an option line\n")
    assert "not an option" not in _describe_config_error(info.value)


def test_percent_in_a_value_is_data():
    conf = AuthkeysConfig.from_config(b"[serve]\napi_key = abc%def\n")
    assert conf["serve"]["api_key"] == "abc%def"


# --- StrictModes-like checks ---------------------------------------------------


def _fake_modes(monkeypatch, tmp_path, overrides):
    """Report ``overrides[path] = (uid, mode)`` for paths under ``tmp_path``."""
    real_lstat, real_stat = os.lstat, os.stat

    def fake(real):
        def wrapper(path, *args, **kwargs):
            st = real(path, *args, **kwargs)
            key = os.path.abspath(path)
            if key in overrides:
                uid, mode = overrides[key]
                fields = list(st)
                fields[0] = mode
                fields[4] = uid
                return os.stat_result(fields)
            if key.startswith(os.path.abspath(tmp_path)):
                fields = list(st)
                fields[0] = (stat.S_IFDIR | 0o755) if stat.S_ISDIR(st.st_mode) else (stat.S_IFREG | 0o644)
                fields[4] = 1000
                return os.stat_result(fields)
            return st

        return wrapper

    monkeypatch.setattr(utils, "_STRICT_MODES", True)
    monkeypatch.setattr(os, "lstat", fake(real_lstat))
    monkeypatch.setattr(os, "stat", fake(real_stat))


def _home(tmp_path):
    ssh = tmp_path / "home" / ".ssh"
    ssh.mkdir(parents=True)
    keyfile = ssh / "authorized_keys"
    keyfile.write_bytes(f"{ED} me\n".encode())
    return tmp_path / "home", ssh, keyfile


def test_secure_file_is_read(tmp_path, monkeypatch):
    home, _, keyfile = _home(tmp_path)
    _fake_modes(monkeypatch, tmp_path, {})
    assert utils.read_user_file(keyfile, 1000, home) == f"{ED} me\n"


@pytest.mark.parametrize(
    "target,uid,mode,reason",
    [
        ("ssh", 1000, stat.S_IFDIR | 0o775, "writable by group or others"),
        ("home", 1000, stat.S_IFDIR | 0o757, "writable by group or others"),
        ("file", 1001, stat.S_IFREG | 0o644, "owned by another user"),
        ("file", 1000, stat.S_IFREG | 0o664, "writable by group or others"),
        ("file", 1000, stat.S_IFLNK | 0o777, "symbolic link"),
    ],
)
def test_insecure_file_is_refused(tmp_path, monkeypatch, caplog, target, uid, mode, reason):
    home, ssh, keyfile = _home(tmp_path)
    path = {"ssh": ssh, "home": home, "file": keyfile}[target]
    _fake_modes(monkeypatch, tmp_path, {os.path.abspath(path): (uid, mode)})
    assert utils.read_user_file(keyfile, 1000, home) is None
    assert any(reason in r.getMessage() for r in caplog.records)


def test_root_owned_file_is_accepted(tmp_path, monkeypatch):
    home, _, keyfile = _home(tmp_path)
    _fake_modes(monkeypatch, tmp_path, {os.path.abspath(keyfile): (0, stat.S_IFREG | 0o644)})
    assert utils.read_user_file(keyfile, 1000, home) is not None


def test_oversized_file_is_refused(tmp_path, caplog):
    home, _, keyfile = _home(tmp_path)
    keyfile.write_bytes(b"x" * (utils.MAX_USER_FILE_BYTES + 1))
    assert utils.read_user_file(keyfile, 1000, home) is None
    assert any("larger than" in r.getMessage() for r in caplog.records)


# --- key types and staleness ---------------------------------------------------


@pytest.mark.parametrize("line", ["db_password = hunter2", "foo bar baz", 'no-pty bogus AAAA'])
def test_unknown_key_type_is_malformed(line):
    with pytest.raises(ValueError):
        AuthorizedKey.parse(line)


def test_certificate_key_type_is_accepted():
    k = AuthorizedKey.parse("ssh-ed25519-cert-v01@openssh.com AAAA c")
    assert k.type == "ssh-ed25519-cert-v01@openssh.com"


@pytest.mark.parametrize("max_stale,served", [(None, True), (100, False), (2000, True)])
def test_max_stale_bounds_expired_fallback(max_stale, served):
    backend = AuthKeysCacheMemBackend()
    cache = AuthKeysCache(backend, ttl=10, max_stale=max_stale)
    backend.db[("bob", "s")] = (f"{ED} bob", time.time() - 1000)
    assert cache.get(("bob", "s")) is None
    got = cache.get(("bob", "s"), include_expired=True)
    assert (got is not None) is served
