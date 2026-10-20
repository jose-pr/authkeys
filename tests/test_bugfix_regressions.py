"""Regression tests for assorted security and correctness fixes."""

import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from authkeys import AuthKeys, KeySource, Settings
from authkeys.sources import HTTPSource, LDAPSource, register_source

# The fake passwd entry's uid matches the files the test writes, as on a real host.
_UID = getattr(os, "getuid", lambda: 0)()

RSA = "ssh-rsa AAAAB3Nza alice@host"


# --- LDAP filter injection --------------------------------------------------


def test_ldap_search_filter_escapes_username():
    pytest.importorskip("ldap3")
    src = LDAPSource({"username_attr": "uid"}, {})
    flt = src._search_filter("*)(uid=*")
    # The injection metacharacters must be escaped, not passed through literally.
    assert "*)(uid=*" not in flt
    assert flt.startswith("(uid=") and flt.endswith(")")
    # ldap3 escapes '*' as \2a, '(' as \28, ')' as \29
    assert r"\2a" in flt.lower()


# --- HTTP username URL-encoding ----------------------------------------------


class _FakeResp:
    status_code = 200
    content = b""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeSession:
    def __init__(self):
        self.url = None

    def get(self, url, **kwargs):
        self.url = url
        return _FakeResp()


def test_http_username_is_url_encoded(monkeypatch):
    pytest.importorskip("requests")
    src = HTTPSource({"address": "https://k.example/{username}"}, {})
    fake = _FakeSession()
    src.session = fake
    list(src.authorized_keys("a/b?c&d#e"))
    assert fake.url == "https://k.example/a%2Fb%3Fc%26d%23e"


# --- Verify bool-or-path -----------------------------------------------------


@pytest.mark.parametrize("value", [False, True, "/etc/pki/ca.pem"])
def test_http_verify_takes_a_bool_or_a_path(value):
    pytest.importorskip("requests")
    src = HTTPSource({"address": "https://k/{username}", "verify": value}, {})
    assert src.request_options["verify"] == value


def test_http_verify_as_text_bool_is_ignored(caplog):
    pytest.importorskip("requests")
    src = HTTPSource({"address": "https://k/{username}", "verify": 0}, {})
    assert "verify" not in src.request_options
    assert any("verify: expected bool or str" in r.getMessage() for r in caplog.records)


# --- api_key fail-closed ------------------------------------------------


def _serve_argv(config_text, tmp_path):
    p = tmp_path / "ak.cfg"
    p.write_text(config_text)
    from authkeys.cli import main

    return main(["--config", str(p), "serve", "--port", "0"])


def test_serve_fails_closed_on_empty_api_key(tmp_path, monkeypatch, capsys, caplog):
    monkeypatch.delenv("AUTHKEYS_TEST_KEY", raising=False)
    rc = _serve_argv('[serve]\napi_key = "${env.AUTHKEYS_TEST_KEY}"\n', tmp_path)
    assert rc == 1
    assert capsys.readouterr().out == ""
    assert any("'api_key' is configured" in r.getMessage() for r in caplog.records)


# --- Thread-safe cache (contract: correct + non-blocking, NOT fetch-dedup) ---


class SlowCountingSource(KeySource):
    instances = []

    def __init__(self, options, globals):
        self.calls = 0
        SlowCountingSource.instances.append(self)

    def authorized_keys(self, username):
        self.calls += 1
        time.sleep(0.05)  # widen the race window
        return [RSA]


register_source("test-bugfix-slow", SlowCountingSource)


def test_concurrent_resolution_is_correct_and_lock_not_held_across_fetch():
    # The lock guards only the cache read/write, NOT the upstream fetch, so one
    # slow source can't stall other users' logins. Concurrent cold requests are
    # correctness-safe (all return the right keys); fetch dedup is deliberately
    # NOT guaranteed (that was traded away for availability).
    SlowCountingSource.instances.clear()
    conf = Settings.from_mapping(
        {
            "cache": {"backend": "memory", "expire": 100},
            "source": {"t": {"backend": "test-bugfix-slow"}},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    results = []

    def worker():
        results.append(list(auth.resolve("alice", load_delegation=False)))

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    # Bounded join + daemon threads: if a worker ever wedges (e.g. on a loaded
    # CI runner) this fails fast instead of hanging the whole job forever.
    assert not any(t.is_alive() for t in threads), "worker thread did not finish"

    assert all(len(r) == 1 for r in results)  # every caller gets the right key
    # A later resolve is served from cache (one of the concurrent writes landed).
    before = SlowCountingSource.instances[0].calls
    list(auth.resolve("alice", load_delegation=False))
    assert SlowCountingSource.instances[0].calls == before  # cache hit, no new fetch


# --- Serve honors per-user delegation -----------------------------------


class DelegationSource(KeySource):
    keys = {"alice": ["ssh-rsa AAAAalice a"], "bob": ["ssh-rsa AAAAbob b"]}

    def authorized_keys(self, username):
        return list(self.keys.get(username, []))


register_source("test-bugfix-delegation", DelegationSource)


def test_serve_resolves_delegated_users(tmp_path, monkeypatch):
    # alice's ~/.ssh/authkeys.cfg authorizes bob too.
    import sys
    import types

    home = tmp_path / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authkeys.cfg").write_text(
        '[authorized]\nusers = ["alice", "bob"]\n'
    )
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwnam = lambda n: types.SimpleNamespace(
        pw_name=n, pw_dir=str(home), pw_uid=_UID
    )
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    conf = Settings.from_mapping(
        {"source": {"d": {"backend": "test-bugfix-delegation"}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    keys = [str(k) for k in auth.resolve("alice")]
    assert any("AAAAalice" in k for k in keys)
    assert any("AAAAbob" in k for k in keys)  # delegation honored


# --- Expire validation --------------------------------------------------


def test_invalid_expire_keeps_cache_at_default():
    conf = Settings.from_mapping({"cache": {"expire": "1h"}})
    auth = AuthKeys()
    auth.load_config(conf)
    assert auth.cache is not None
    assert auth.cache.ttl == 300


# --- Default-command insertion -------------------------------------------


@pytest.mark.parametrize(
    "argv,username",
    [
        (["alice"], "alice"),
        (["-v", "alice"], "alice"),
        (["resolve", "alice"], "alice"),
        (["keys", "alice"], "alice"),
        (["--config", "{cfg}", "alice"], "alice"),
    ],
)
def test_resolve_is_the_default_command(argv, username, monkeypatch, tmp_path):
    from authkeys.cli import main
    from authkeys.cli.resolve import Resolve

    cfg = tmp_path / "a.cfg"
    cfg.write_text("")
    seen = []
    monkeypatch.setattr(
        Resolve, "__call__", lambda self: seen.append(self.username) or 0
    )
    assert main([a.replace("{cfg}", str(cfg)) for a in argv]) == 0
    assert seen == [username]
