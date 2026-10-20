"""CLI-level behavior: no-traceback resolve, exit codes, cache subcommand."""

import os
import json
import sys
import types

import pytest

from authkeys.cache import CacheBackend, register_cache
from authkeys.cli import main as run

# The fake passwd entry's uid matches the files the test writes, as on a real host.
_UID = getattr(os, "getuid", lambda: 0)()

RSA = "ssh-rsa AAAAB3Nza a"


def test_resolve_broken_config_exits_nonzero_no_traceback(tmp_path, capsys):
    # A resolve that blows up internally must return a clean non-zero code with
    # no traceback on stdout (sshd reads stdout as authorized_keys).
    bad = tmp_path / "authkeys.cfg"
    bad.write_text('[source.x]\nbackend = "also-not-here"\n')
    rc = run(["--config", str(bad), "resolve", "someone"])
    out = capsys.readouterr()
    assert rc == 3
    assert "Traceback" not in out.out
    # stdout carries only key lines (here: none)
    assert all(line.strip() == "" or " " in line for line in out.out.splitlines())


def test_cache_show_and_purge(tmp_path):
    cachedir = tmp_path / "cache"
    cachedir.mkdir()
    conf = tmp_path / "authkeys.cfg"
    conf.write_text(
        f'[cache]\nbackend = "file"\npath = {str(cachedir)!r}\nexpire = 100\n'
    )
    # Seed an entry via the library so `cache show/purge` have something to act on.
    from authkeys import AuthKeys, load_settings

    auth = AuthKeys()
    auth.load_config(load_settings(conf))
    auth.cache[("alice", "src")] = RSA

    assert run(["--config", str(conf), "cache", "show"]) == 0
    assert run(["--config", str(conf), "cache", "purge", "--all", "--dry-run"]) == 0
    assert list(auth.cache.backend.keys()) == [("alice", "src")]
    assert run(["--config", str(conf), "cache", "purge", "--all"]) == 0
    # After purge, the entry is gone.
    assert list(auth.cache.backend.keys()) == []


def test_cache_warm(tmp_path, monkeypatch):
    cachedir = tmp_path / "cache"
    cachedir.mkdir()
    conf = tmp_path / "authkeys.cfg"
    conf.write_text(
        f'[cache]\nbackend = "file"\npath = {str(cachedir)!r}\n[source.files]\nbackend = "file"\n'
    )
    # Fake a user whose authorized_keys the file source can read.
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(RSA + "\n")
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwnam = lambda n: types.SimpleNamespace(
        pw_name=n, pw_dir=str(home), pw_uid=_UID
    )
    fake_pwd.getpwuid = lambda u: types.SimpleNamespace(
        pw_name="me", pw_dir=str(home), pw_uid=_UID
    )
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    assert run(["--config", str(conf), "cache", "warm", "alice"]) == 0
    # The warmed entry is now on disk.
    assert (cachedir / "files" / "alice").exists()


def _file_source_config(tmp_path, lines):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("\n".join(lines) + "\n")
    conf = tmp_path / "authkeys.cfg"
    conf.write_text('[source.files]\nbackend = "file"\n')
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwnam = lambda n: types.SimpleNamespace(
        pw_name=n, pw_dir=str(home), pw_uid=_UID
    )
    fake_pwd.getpwuid = lambda u: types.SimpleNamespace(
        pw_name="alice", pw_dir=str(home), pw_uid=_UID
    )
    return conf, fake_pwd


def test_resolve_format_json_matches_resolved_keys(tmp_path, monkeypatch, capsys):
    conf, fake_pwd = _file_source_config(
        tmp_path, [RSA, 'command="x",no-pty ssh-ed25519 AAAAC3Nza bob']
    )
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    rc = run(["--config", str(conf), "resolve", "alice", "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert parsed == [
        {"type": "ssh-rsa", "key": "AAAAB3Nza", "comment": "a", "options": ""},
        {
            "type": "ssh-ed25519",
            "key": "AAAAC3Nza",
            "comment": "bob",
            "options": 'command="x",no-pty',
        },
    ]


def test_resolve_format_json_handles_options_with_quoted_spaces(
    tmp_path, monkeypatch, capsys
):
    # The documented structured output must carry the real fields for an
    # sshd-legal `command="a b"` line, not the shifted ones a first-space
    # split produced.
    line = 'command="/usr/bin/tunnel -n 5",no-pty ssh-ed25519 AAAAC3Nza bob'
    conf, fake_pwd = _file_source_config(tmp_path, [line])
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    rc = run(["--config", str(conf), "resolve", "alice", "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out) == [
        {
            "type": "ssh-ed25519",
            "key": "AAAAC3Nza",
            "comment": "bob",
            "options": 'command="/usr/bin/tunnel -n 5",no-pty',
        }
    ]


def test_resolve_wire_format_preserves_options_with_quoted_spaces(
    tmp_path, monkeypatch, capsys
):
    line = 'command="/usr/bin/tunnel -n 5",no-pty ssh-ed25519 AAAAC3Nza bob'
    conf, fake_pwd = _file_source_config(tmp_path, [line])
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    rc = run(["--config", str(conf), "resolve", "alice"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.splitlines() == [line]


def test_resolve_format_default_unchanged(tmp_path, monkeypatch, capsys):
    conf, fake_pwd = _file_source_config(tmp_path, [RSA])
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    rc = run(["--config", str(conf), "resolve", "alice"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.splitlines() == [RSA]


def test_check_format_json(tmp_path, monkeypatch, capsys):
    conf, fake_pwd = _file_source_config(tmp_path, [RSA])
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    rc = run(["--config", str(conf), "check", "alice", "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert parsed == [
        {"type": "ssh-rsa", "key": "AAAAB3Nza", "comment": "a", "options": ""}
    ]


def test_cache_without_cache_configured_logs_and_exits_3(tmp_path, caplog, capsys):
    conf = tmp_path / "authkeys.cfg"
    conf.write_text('[cache]\nbackend = "file"\n')
    with caplog.at_level("ERROR", logger="authkeys"):
        rc = run(["--config", str(conf), "cache", "show"])
    assert rc == 3
    last = [r for r in caplog.records if r.name == "authkeys"][-1]
    assert (last.levelname, last.getMessage()) == ("ERROR", "No cache configured")
    assert last.exc_info is None
    assert capsys.readouterr().out == ""


def test_cache_unknown_action_is_a_usage_error(tmp_path, capsys):
    conf = tmp_path / "authkeys.cfg"
    conf.write_text("")
    assert run(["--config", str(conf), "cache", "bogus"]) == 2
    assert "invalid choice" in capsys.readouterr().err


class NoListCache(CacheBackend):
    """Stores entries but cannot enumerate them."""

    def __init__(self):
        self.db = {}

    def __getitem__(self, key):
        return self.db.get(key)

    def __setitem__(self, key, value):
        self.db[key] = (value, 0.0)


register_cache("test-cli-nolist", NoListCache)


def test_cache_unsupported_backend_action_logs_and_exits_3(tmp_path, caplog):
    conf = tmp_path / "authkeys.cfg"
    conf.write_text('[cache]\nbackend = "test-cli-nolist"\n')
    with caplog.at_level("ERROR", logger="authkeys"):
        rc = run(["--config", str(conf), "cache", "show"])
    assert rc == 3
    assert [r.getMessage() for r in caplog.records if r.name == "authkeys"][-1] == (
        "The configured cache backend does not support this action "
        "(in-memory caches are per-process)."
    )


# --- configuration file selection and serve settings ---------------------------


def test_authkeys_config_names_the_file(tmp_path, monkeypatch, capsys):
    conf, fake_pwd = _file_source_config(tmp_path, [RSA])
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)
    monkeypatch.setenv("AUTHKEYS_CONFIG", str(conf))
    assert run(["alice"]) == 0
    assert capsys.readouterr().out.splitlines() == [RSA]


def test_a_named_file_that_does_not_exist_is_a_usage_error(tmp_path):
    assert run(["--config", str(tmp_path / "absent.cfg"), "alice"]) == 2


def _capture_server(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, auth, **options):
            seen.update(options)

    import authkeys.server

    monkeypatch.setattr(authkeys.server, "KeyServer", Fake)
    monkeypatch.setattr(authkeys.server, "serve", lambda server: None)
    return seen


@pytest.mark.parametrize(
    "argv,env,expected",
    [
        ([], None, 8090),  # default
        ([], "", 9001),  # file
        ([], "9002", 9002),  # env beats file
        (["--port", "9003"], "9002", 9003),  # command line beats env
    ],
)
def test_serve_port_precedence(tmp_path, monkeypatch, argv, env, expected):
    seen = _capture_server(monkeypatch)
    conf = tmp_path / "authkeys.cfg"
    conf.write_text("" if env is None else "[serve]\nport = 9001\n")
    monkeypatch.delenv("AUTHKEYS_SERVE_PORT", raising=False)
    if env:
        monkeypatch.setenv("AUTHKEYS_SERVE_PORT", env)
    assert run(["--config", str(conf), "serve", *argv]) == 0
    assert seen["port"] == expected


def test_serve_with_a_malformed_port_is_one_line(tmp_path, monkeypatch, capsys):
    _capture_server(monkeypatch)
    conf = tmp_path / "authkeys.cfg"
    conf.write_text('[serve]\nport = "abc"\n')
    assert run(["--config", str(conf), "serve"]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and "port" in err


def test_broken_config_file_exits_3(tmp_path, caplog, capsys):
    conf = tmp_path / "authkeys.cfg"
    conf.write_text("[cache\n")
    assert run(["--config", str(conf), "alice"]) == 3
    assert "Traceback" not in capsys.readouterr().err
