"""File cache: entries stay under the root, untrusted paths are ignored, and cache
failures never cost the keys a source returned."""

import os
import pathlib

import pytest

from authkeys import AuthKeys, AuthkeysSource, Source
from authkeys.cache import AuthKeysCache, AuthKeysCacheFileBackend

ED = "ssh-ed25519 AAAAC3Nza"


class Keys(AuthkeysSource):
    def __init__(self, keys):
        self.keys = keys
        self.calls = 0

    def authorized_keys(self, username):
        self.calls += 1
        return list(self.keys.get(username, []))


def _auth(tmp_path, keys, *, expired_on_error=False):
    root = tmp_path / "cache"
    root.mkdir()
    auth = AuthKeys()
    auth.cache = AuthKeysCache(AuthKeysCacheFileBackend(root), ttl=300)
    auth.use_expired_on_error = expired_on_error
    src = Keys(keys)
    auth.sources = {
        "s": Source(cached=True, enabled=True, backend=src, sanitize=None, expire=None)
    }
    return auth, src, root


@pytest.mark.parametrize("uid", ["", ".", "..", "../x", "a/b", "a\\b", "C:x", "a\x00b"])
def test_entry_path_refuses_non_plain_names(tmp_path, uid):
    backend = AuthKeysCacheFileBackend(tmp_path)
    with pytest.raises(ValueError):
        backend.cached_entry_path((uid, "s"))
    with pytest.raises(ValueError):
        backend.cached_entry_path(("alice", uid))


def test_traversal_username_reads_and_writes_nothing_outside(tmp_path):
    auth, _, root = _auth(tmp_path, {})
    victim = tmp_path / "victim.txt"
    victim.write_text("db_password = hunter2\n")
    assert list(auth.authorized_keys("../../victim.txt")) == []
    os.utime(victim, (1, 1))
    assert list(auth.authorized_keys("../../victim.txt")) == []
    assert victim.read_text() == "db_password = hunter2\n"


def test_dotdot_username_does_not_escape_resolve(tmp_path):
    auth, _, _ = _auth(tmp_path, {})
    assert list(auth.authorized_keys("..")) == []


def test_malformed_cache_entry_is_a_miss(tmp_path):
    auth, src, root = _auth(tmp_path, {"bob": [f"{ED} bob@x"]})
    (root / "s").mkdir()
    (root / "s" / "bob").write_text("JUSTONETOKEN\n")
    assert [str(k) for k in auth.authorized_keys("bob")] == [f"{ED} bob@x"]
    assert src.calls == 1


def test_failed_cache_write_keeps_the_fetched_keys(tmp_path, monkeypatch, caplog):
    auth, _, _ = _auth(tmp_path, {"bob": [f"{ED} bob@x"]})

    def full(self, key, value):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(AuthKeysCacheFileBackend, "__setitem__", full)
    assert [str(k) for k in auth.authorized_keys("bob")] == [f"{ED} bob@x"]
    assert any("Could not cache keys for bob" in r.getMessage() for r in caplog.records)


def test_failed_cache_read_is_a_miss(tmp_path, monkeypatch):
    auth, src, _ = _auth(tmp_path, {"bob": [f"{ED} bob@x"]})

    def unreadable(self, key):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(AuthKeysCacheFileBackend, "__getitem__", unreadable)
    assert [str(k) for k in auth.authorized_keys("bob")] == [f"{ED} bob@x"]
    assert src.calls == 1


def _fake_owner(monkeypatch, root, uid, mode_bits):
    """Report every path under ``root`` as owned by ``uid`` with ``mode_bits``."""
    real_stat = pathlib.Path.stat

    def stat(self, *args, **kwargs):
        st = real_stat(self, *args, **kwargs)
        if os.path.abspath(self).startswith(os.path.abspath(root)):
            fields = list(st)
            fields[0] = (st.st_mode & ~0o7777) | mode_bits
            fields[4] = uid
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(pathlib.Path, "stat", stat)
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)


@pytest.mark.parametrize("uid,mode", [(1000, 0o600), (1000, 0o700)])
def test_entry_owned_by_this_user_is_used(tmp_path, monkeypatch, uid, mode):
    auth, src, root = _auth(tmp_path, {"bob": [f"{ED} bob@x"]})
    list(auth.authorized_keys("bob"))
    _fake_owner(monkeypatch, root, uid, mode)
    assert [str(k) for k in auth.authorized_keys("bob")] == [f"{ED} bob@x"]
    assert src.calls == 1


@pytest.mark.parametrize("uid,mode", [(0, 0o600), (1000, 0o620), (1000, 0o606)])
def test_entry_others_could_write_is_ignored(tmp_path, monkeypatch, caplog, uid, mode):
    auth, src, root = _auth(tmp_path, {"bob": [f"{ED} bob@x"]})
    list(auth.authorized_keys("bob"))
    _fake_owner(monkeypatch, root, uid, mode)
    assert [str(k) for k in auth.authorized_keys("bob")] == [f"{ED} bob@x"]
    assert src.calls == 2
    assert any("Ignoring cache path" in r.getMessage() for r in caplog.records)
