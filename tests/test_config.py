"""Configuration: TOML `.cfg` through anycfg, validation that warns, the
delegation file's restrictions, and which file is in force."""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from authkeys import config
from authkeys.config import (
    Delegation,
    Settings,
    chosen_path,
    load_settings,
    parse_delegation,
)
from authkeys.exceptions import ConfigError

SRC = str(Path(__file__).resolve().parents[1] / "src")

FULL = """\
[cache]
backend = "file"
path = "/var/cache/authkeys"
expire = 3600
negative_expire = 60
expired_on_error = true
max_stale = 86400

[globals]
usermap = "authkeys.usermaps.none"

[serve]
bind = "127.0.0.1"
api_key = "${env.AUTHKEYS_TEST_SECRET}"

[source.files]
backend = "file"
paths = ["authorized_keys", "authorized_keys2"]

[source.ldap]
backend = "ldap"
enabled = false
server = "ldaps://ldap.example.com"
"""


def _write(tmp_path, text, name="authkeys.cfg"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_every_table_is_read(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTHKEYS_TEST_SECRET", "s3cr3t")
    settings = load_settings(_write(tmp_path, FULL))
    assert settings.cache.backend == "file"
    assert settings.cache.options == {"path": "/var/cache/authkeys"}
    assert (settings.cache.expire, settings.cache.negative_expire) == (3600, 60)
    assert settings.cache.expired_on_error is True and settings.cache.max_stale == 86400
    assert settings.globals.usermap == "authkeys.usermaps.none"
    assert settings.serve["api_key"] == "s3cr3t"
    files = settings.sources["files"]
    assert files.backend == "file" and files.options == {
        "paths": ["authorized_keys", "authorized_keys2"]
    }
    assert settings.sources["ldap"].enabled is False


def test_unset_environment_variable_is_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTHKEYS_TEST_SECRET", raising=False)
    settings = load_settings(_write(tmp_path, FULL))
    assert not settings.serve["api_key"]


def test_percent_is_data(tmp_path):
    settings = load_settings(_write(tmp_path, '[serve]\napi_key = "abc%def"\n'))
    assert settings.serve["api_key"] == "abc%def"


def test_a_document_may_name_its_format(tmp_path):
    path = _write(tmp_path, '#!json\n{"cache": {"expire": 7}}\n')
    assert load_settings(path).cache.expire == 7


def test_unknown_keys_warn_by_name(tmp_path, caplog):
    load_settings(
        _write(tmp_path, '[cache]\nexpier = 5\n[sources.x]\nbackend = "file"\n')
    )
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert "Ignoring unknown setting config.sources" in messages
    # a backend's own keys are checked once the backend is known
    assert not any("expier" in m for m in messages)


def test_wrong_type_warns_without_the_value_and_keeps_the_default(tmp_path, caplog):
    settings = load_settings(_write(tmp_path, '[cache]\nexpire = "s3cr3t-looking"\n'))
    assert settings.cache.expire == 300
    messages = [r.getMessage() for r in caplog.records]
    assert any("cache.expire: expected int, got str" in m for m in messages)
    assert not any("s3cr3t" in m for m in messages)


def test_bool_is_not_an_int(tmp_path):
    assert (
        load_settings(_write(tmp_path, "[cache]\nexpire = true\n")).cache.expire == 300
    )


def test_source_without_backend_is_skipped(tmp_path, caplog):
    settings = load_settings(_write(tmp_path, "[source.x]\nenabled = true\n"))
    assert settings.sources == {}
    assert any("names no backend" in r.getMessage() for r in caplog.records)


def test_broken_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(_write(tmp_path, "[cache\nexpire = 1\n"))


def test_missing_file_warns_and_is_empty(tmp_path, caplog):
    settings = load_settings(tmp_path / "absent.cfg")
    assert settings.sources == {}
    assert any("No config file found" in r.getMessage() for r in caplog.records)


def test_no_path_is_empty_without_warning(caplog):
    assert load_settings(None) == Settings()
    assert not caplog.records


def test_from_mapping_takes_python_data():
    settings = Settings.from_mapping(
        {"source": {"a": {"backend": "file", "paths": "ak"}}}
    )
    assert settings.sources["a"].options == {"paths": "ak"}


# --- which file -----------------------------------------------------------------


def test_argument_beats_environment_beats_default(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTHKEYS_CONFIG", str(tmp_path / "env.cfg"))
    assert chosen_path(tmp_path / "arg.cfg") == tmp_path / "arg.cfg"
    assert chosen_path(None) == tmp_path / "env.cfg"
    monkeypatch.setenv("AUTHKEYS_CONFIG", "")
    assert chosen_path(None) is None
    monkeypatch.delenv("AUTHKEYS_CONFIG")
    assert chosen_path(None) == config.SYSTEM_CONFIG


def test_importing_reads_no_authkeys_variable():
    # os.environ is replaced by a mapping that records reads, then authkeys and
    # its CLI are imported in a fresh interpreter.
    code = (
        "import os, sys\n"
        "seen = []\n"
        "class Spy(type(os.environ)):\n"
        "    def __getitem__(self, key):\n"
        "        seen.append(key); return super().__getitem__(key)\n"
        "os.environ = Spy(os.environ._data, os.environ.encodekey, os.environ.decodekey,"
        " os.environ.encodevalue, os.environ.decodevalue)\n"
        "import authkeys, authkeys.cli, authkeys.config\n"
        "print([k for k in seen if str(k).upper().startswith('AUTHKEYS')])\n"
    )
    env = dict(os.environ, AUTHKEYS_CONFIG="/somewhere/else.cfg")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [SRC, env.get("PYTHONPATH", "")]))
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


# --- the delegation file --------------------------------------------------------


def test_delegation_lists():
    d = parse_delegation(
        '[authorized]\nusers = ["alice", "bob"]\ngroups = ["admins"]\n'
    )
    assert d == Delegation(users=["alice", "bob"], groups=["admins"])


def test_delegation_without_users_means_the_user_alone():
    assert parse_delegation('[authorized]\ngroups = ["admins"]\n').users is None


def test_delegation_gets_no_interpolation(monkeypatch):
    monkeypatch.setenv("AUTHKEYS_TEST_SECRET", "s3cr3t")
    d = parse_delegation('[authorized]\nusers = ["${env.AUTHKEYS_TEST_SECRET}"]\n')
    assert d.users == ["${env.AUTHKEYS_TEST_SECRET}"]


def test_delegation_is_toml_only():
    pytest.importorskip("yaml")
    with pytest.raises(ConfigError):
        parse_delegation("#!yaml\nauthorized: !include /etc/authkeys.cfg\n")


def test_delegation_error_names_the_position_not_the_text():
    with pytest.raises(ConfigError) as info:
        parse_delegation("secret line one\n")
    assert "secret" not in str(info.value)


@pytest.mark.parametrize(
    "name",
    [
        "AuthkeysConfig",
        "SYSTEM_CONF_PATHS",
        "USER_CONF_PATH",
        "_split_path_list",
        "_interpolate_env",
    ],
)
def test_removed_names_are_gone(name):
    assert not hasattr(config, name)
