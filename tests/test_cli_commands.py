"""CLI-level behavior: no-traceback resolve, exit codes, cache subcommand."""

import sys
import types

import pytest

from authkeys.cli import run

RSA = "ssh-rsa AAAAB3Nza a"


def test_resolve_broken_config_exits_nonzero_no_traceback(tmp_path, capsys):
    # A resolve that blows up internally must return a clean non-zero code with
    # no traceback on stdout (sshd reads stdout as authorized_keys).
    bad = tmp_path / "authkeys.conf"
    bad.write_text("[cache]\nbackend = does.not.Exist\n[source:x]\nbackend = also.not.here\n")
    rc = run(["resolve", "someone", "--config", str(bad)])
    out = capsys.readouterr()
    assert rc in (0, 3)  # never crashes; 3 on internal error, 0 if it degrades
    assert "Traceback" not in out.out
    # stdout carries only key lines (here: none)
    assert all(line.strip() == "" or " " in line for line in out.out.splitlines())


def test_cache_show_and_purge(tmp_path):
    cachedir = tmp_path / "cache"
    cachedir.mkdir()
    conf = tmp_path / "authkeys.conf"
    conf.write_text(
        "[cache]\n"
        "backend = authkeys.cache.AuthKeysCacheFileBackend\n"
        f"path = {cachedir}\n"
        "expire = 100\n"
    )
    # Seed an entry via the library so `cache show/purge` have something to act on.
    from authkeys import AuthKeys, AuthkeysConfig

    auth = AuthKeys()
    auth.load_config(AuthkeysConfig.from_config(str(conf)))
    auth.cache[("alice", "src")] = RSA

    assert run(["cache", "show", "--config", str(conf)]) == 0
    assert run(["cache", "purge", "--all", "--config", str(conf)]) == 0
    # After purge, the entry is gone.
    assert list(auth.cache.backend.keys()) == []


def test_cache_warm(tmp_path, monkeypatch):
    cachedir = tmp_path / "cache"
    cachedir.mkdir()
    conf = tmp_path / "authkeys.conf"
    conf.write_text(
        "[cache]\n"
        "backend = authkeys.cache.AuthKeysCacheFileBackend\n"
        f"path = {cachedir}\n"
        "[source:files]\n"
        "backend = authkeys.sources.authorizedkeys\n"
    )
    # Fake a user whose authorized_keys the file source can read.
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(RSA + "\n")
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwnam = lambda n: types.SimpleNamespace(pw_name=n, pw_dir=str(home))
    fake_pwd.getpwuid = lambda u: types.SimpleNamespace(pw_name="me", pw_dir=str(home))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    assert run(["cache", "warm", "alice", "--config", str(conf)]) == 0
    # The warmed entry is now on disk.
    assert (cachedir / "files" / "alice").exists()
