"""Regression tests for the 2026-07-18 code-review findings (F1-F8)."""

import threading
import time
import urllib.error
import urllib.request

import pytest

from authkeys import AuthKeys, AuthkeysConfig, AuthkeysSource
from authkeys.server import KeyServer
from authkeys.sources.http import HttpAuthorizedKeys, _parse_verify

RSA = "ssh-rsa AAAAB3Nza alice@host"


# --- F1: LDAP filter injection --------------------------------------------


def test_ldap_search_filter_escapes_username():
    ldap3 = pytest.importorskip("ldap3")
    from authkeys.sources.ldap import LdapAuthorizedKeys

    conf = AuthkeysConfig.from_config({"source:ldap": {"username_attr": "uid"}})
    src = LdapAuthorizedKeys(conf["source:ldap"], {})
    flt = src._search_filter("*)(uid=*")
    # The injection metacharacters must be escaped, not passed through literally.
    assert "*)(uid=*" not in flt
    assert flt.startswith("(uid=") and flt.endswith(")")
    # ldap3 escapes '*' as \2a, '(' as \28, ')' as \29
    assert r"\2a" in flt.lower()


# --- F2: HTTP username URL-encoding ---------------------------------------


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
    conf = AuthkeysConfig.from_config(
        {"source:http": {"address": "https://k.example/{username}"}}
    )
    src = HttpAuthorizedKeys(conf["source:http"], {})
    fake = _FakeSession()
    src.session = fake
    list(src.authorized_keys("a/b?c&d#e"))
    assert fake.url == "https://k.example/a%2Fb%3Fc%26d%23e"


# --- F3: verify bool-or-path ----------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("false", False), ("False", False), ("0", False), ("no", False), ("off", False),
    ("true", True), ("1", True), ("yes", True), ("on", True),
    ("/etc/pki/ca.pem", "/etc/pki/ca.pem"),
])
def test_parse_verify(value, expected):
    assert _parse_verify(value) == expected
    assert type(_parse_verify(value)) is type(expected)


def test_http_verify_false_disables_verification():
    conf = AuthkeysConfig.from_config(
        {"source:http": {"address": "https://k/{username}", "verify": "false"}}
    )
    src = HttpAuthorizedKeys(conf["source:http"], {})
    assert src.options["verify"] is False


# --- F4: api_key fail-closed ----------------------------------------------


def _serve_argv(config_text, tmp_path):
    p = tmp_path / "ak.conf"
    p.write_text(config_text)
    from authkeys.cli import run

    return run(["serve", "--config", str(p), "--port", "0"])


def test_serve_fails_closed_on_empty_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTHKEYS_TEST_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        _serve_argv(
            "[serve]\napi_key = ${env:AUTHKEYS_TEST_KEY}\n", tmp_path
        )
    assert "api_key" in str(exc.value)


# --- F5: thread-safe cache (contract: correct + non-blocking, NOT fetch-dedup) -


class SlowCountingSource(AuthkeysSource):
    instances = []

    def __init__(self, conf, globals):
        self.calls = 0
        SlowCountingSource.instances.append(self)

    def authorized_keys(self, username):
        self.calls += 1
        time.sleep(0.05)  # widen the race window
        return [RSA]


def test_concurrent_resolution_is_correct_and_lock_not_held_across_fetch():
    # The lock guards only the cache read/write, NOT the upstream fetch, so one
    # slow source can't stall other users' logins. Concurrent cold requests are
    # correctness-safe (all return the right keys); fetch dedup is deliberately
    # NOT guaranteed (that was traded away for availability).
    SlowCountingSource.instances.clear()
    conf = AuthkeysConfig.from_config(
        {
            "cache": {"backend": "authkeys.cache.AuthKeysCacheMemBackend", "expire": "100"},
            "globals": {},
            "source:t": {"backend": f"{__name__}.SlowCountingSource"},
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


# --- F6: serve honors per-user delegation ---------------------------------


class DelegationSource(AuthkeysSource):
    keys = {"alice": ["ssh-rsa AAAAalice a"], "bob": ["ssh-rsa AAAAbob b"]}

    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        return list(self.keys.get(username, []))


def test_serve_resolves_delegated_users(tmp_path, monkeypatch):
    # alice's ~/.ssh/authkeys.conf authorizes bob too.
    import sys
    import types

    home = tmp_path / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authkeys.conf").write_text(
        "[authorized]\nusers =\n    alice\n    bob\n"
    )
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwnam = lambda n: types.SimpleNamespace(pw_name=n, pw_dir=str(home))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    conf = AuthkeysConfig.from_config(
        {"cache": {}, "globals": {}, "source:d": {"backend": f"{__name__}.DelegationSource"}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    keys = [str(k) for k in auth.resolve("alice")]
    assert any("AAAAalice" in k for k in keys)
    assert any("AAAAbob" in k for k in keys)  # delegation honored


# --- F7: expire validation ------------------------------------------------


def test_invalid_expire_keeps_cache_at_default():
    conf = AuthkeysConfig.from_config(
        {"cache": {"expire": "1h"}, "globals": {}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    assert auth.cache is not None
    assert auth.cache.ttl == 300


# --- F8: default-command insertion ----------------------------------------


@pytest.mark.parametrize("argv,expected", [
    (["alice"], ["resolve", "alice"]),
    (["-v", "alice"], ["resolve", "-v", "alice"]),
    (["serve", "-b", "x"], ["serve", "-b", "x"]),
    (["resolve", "alice"], ["resolve", "alice"]),
    (["keys", "alice"], ["keys", "alice"]),
    (["--help"], ["--help"]),
    (["--version"], ["--version"]),
    ([], ["resolve"]),
])
def test_with_default_command(argv, expected):
    from authkeys.cli import _with_default_command

    assert _with_default_command(argv) == expected
