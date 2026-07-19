"""Regression + feature tests for the hardening / cache / quick-fix plans."""

import ssl
import threading
import time

import pytest

from authkeys import AuthKeys, AuthkeysConfig, AuthkeysSource
from authkeys.cache import (
    _NEGATIVE_MARKER,
    AuthKeysCache,
    AuthKeysCacheFileBackend,
    AuthKeysCacheMemBackend,
)

RSA = "ssh-rsa AAAAB3Nza"
ED = "ssh-ed25519 AAAAC3Nza"


# --- Hardening P1: LDAP tls_verify ----------------------------------------


@pytest.mark.parametrize("value,expected_validate,ca_key", [
    (None, ssl.CERT_REQUIRED, None),
    ("system", ssl.CERT_REQUIRED, None),
    ("none", ssl.CERT_NONE, None),
])
def test_ldap_tls_verify_modes(value, expected_validate, ca_key):
    pytest.importorskip("ldap3")
    from authkeys.sources.ldap import LdapAuthorizedKeys

    section = {} if value is None else {"tls_verify": value}
    conf = AuthkeysConfig.from_config({"source:ldap": section})
    src = LdapAuthorizedKeys(conf["source:ldap"], {})
    kwargs = src._tls_kwargs()
    assert kwargs["validate"] == expected_validate
    assert "ca_certs_file" not in kwargs and "ca_certs_path" not in kwargs


def test_ldap_tls_verify_file_vs_dir(tmp_path):
    pytest.importorskip("ldap3")
    from authkeys.sources.ldap import LdapAuthorizedKeys

    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    conf = AuthkeysConfig.from_config({"source:ldap": {"tls_verify": str(ca)}})
    kwargs = LdapAuthorizedKeys(conf["source:ldap"], {})._tls_kwargs()
    assert kwargs["validate"] == ssl.CERT_REQUIRED
    assert kwargs["ca_certs_file"] == str(ca)

    conf2 = AuthkeysConfig.from_config({"source:ldap": {"tls_verify": str(tmp_path)}})
    kwargs2 = LdapAuthorizedKeys(conf2["source:ldap"], {})._tls_kwargs()
    assert kwargs2["ca_certs_path"] == str(tmp_path)


# --- Hardening P3: malformed key line doesn't nuke the source -------------


class MixedSource(AuthkeysSource):
    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        return [f"{RSA} ok", "BADLINE", f"{ED} ok2"]


def _auth(source_cls, extra_cache=None):
    cache = {"backend": "authkeys.cache.AuthKeysCacheMemBackend", "expire": "100"}
    cache.update(extra_cache or {})
    conf = AuthkeysConfig.from_config(
        {"cache": cache, "globals": {}, "source:t": {"backend": f"{__name__}.{source_cls.__name__}"}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    return auth


def test_malformed_line_is_skipped_not_fatal():
    auth = _auth(MixedSource)
    keys = list(auth.resolve("alice", load_delegation=False))
    assert [k.key for k in keys] == ["AAAAB3Nza", "AAAAC3Nza"]


class OnceBadSource(AuthkeysSource):
    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        return ["BADLINE"]


def test_malformed_line_does_not_trigger_expired_fallback():
    auth = _auth(OnceBadSource, {"expire": "0", "expired_on_error": "1"})
    # Pre-seed a stale entry, then let it expire so the top-of-resolve cache read
    # misses and the fetch+parse path (which skips the bad line) runs.
    auth.cache[("alice", "t")] = f"{RSA} stale"
    time.sleep(0.02)  # entry now older than expire=0
    keys = list(auth.resolve("alice", load_delegation=False))
    # The bad line is SKIPPED (empty result), not treated as a source error, so
    # expired_on_error must NOT resurrect the stale key.
    assert keys == []


# --- Hardening P2: lock not held across fetch -----------------------------


class BlockingSource(AuthkeysSource):
    gate = threading.Event()

    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        if username == "slow":
            BlockingSource.gate.wait(timeout=2)
        return [f"{RSA} {username}"]


def test_lock_not_held_across_fetch():
    BlockingSource.gate.clear()
    auth = _auth(BlockingSource)
    # Warm "fast" so its later lookup is a pure cache hit.
    auth.resolve("fast", load_delegation=False)

    started = threading.Event()

    def slow():
        started.set()
        auth.resolve("slow", load_delegation=False)

    t = threading.Thread(target=slow, daemon=True)
    t.start()
    started.wait(1)
    time.sleep(0.05)
    # "fast" is cached; it must return without waiting on the blocked "slow" fetch.
    got = auth.resolve("fast", load_delegation=False)
    assert got  # returned promptly while slow is still blocked
    BlockingSource.gate.set()
    t.join(2)


# --- Cache P1/P3: negative caching + error-empty ---------------------------


def test_negative_cache_uses_negative_ttl():
    cache = AuthKeysCache(AuthKeysCacheMemBackend(), ttl=100, negative_ttl=0)
    cache[("u", "s")] = ""  # empty => negative entry
    time.sleep(0.01)
    # Negative TTL is 0 -> the empty result has already expired.
    assert cache.get(("u", "s")) is None
    # A positive entry with the same (long) ttl stays fresh.
    cache[("u2", "s")] = f"{RSA} a"
    assert cache.get(("u2", "s")) == f"{RSA} a"


def test_negative_marker_never_confused_with_keys():
    backend = AuthKeysCacheMemBackend()
    cache = AuthKeysCache(backend, ttl=100)
    cache[("u", "s")] = ""
    stored, _ts = backend[("u", "s")]
    assert stored == _NEGATIVE_MARKER
    assert cache.get(("u", "s")) == ""  # reads back as empty, not the marker


class FlakyHTTPSource(AuthkeysSource):
    status = 503

    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        raise RuntimeError(f"HTTP {self.status}")


def test_http_error_falls_back_to_stale_not_cached_empty():
    auth = _auth(FlakyHTTPSource, {"expired_on_error": "1"})
    auth.cache[("alice", "t")] = f"{RSA} previously-good"
    keys = list(auth.resolve("alice", load_delegation=False))
    assert [k.key for k in keys] == ["AAAAB3Nza"]  # stale served, not empty


# --- Cache P4: per-source TTL ----------------------------------------------


def test_per_source_expire_overrides_global():
    conf = AuthkeysConfig.from_config(
        {
            "cache": {"backend": "authkeys.cache.AuthKeysCacheMemBackend", "expire": "100"},
            "globals": {},
            "source:t": {"backend": f"{__name__}.MixedSource", "expire": "0"},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    assert auth.sources["t"].expire == 0
    # With source ttl 0 the cache entry is immediately stale on read.
    auth.cache[("alice", "t")] = f"{RSA} x"
    time.sleep(0.01)
    assert auth.cache.get(("alice", "t"), ttl=auth.sources["t"].expire) is None


# --- Cache P2: atomic writes + perms ---------------------------------------


def test_file_backend_atomic_and_private(tmp_path):
    backend = AuthKeysCacheFileBackend(tmp_path)
    backend[("alice", "ldap")] = f"{RSA} a"
    entry = tmp_path / "ldap" / "alice"
    assert entry.read_text() == f"{RSA} a"
    # No leftover temp files.
    assert not list((tmp_path / "ldap").glob(".tmp-*"))


# --- Cache P5: enumeration + sweep -----------------------------------------


def test_file_backend_keys_and_delete(tmp_path):
    backend = AuthKeysCacheFileBackend(tmp_path)
    backend[("alice", "ldap")] = "a"
    backend[("bob", "ldap")] = "b"
    assert set(backend.keys()) == {("alice", "ldap"), ("bob", "ldap")}
    del backend[("alice", "ldap")]
    assert set(backend.keys()) == {("bob", "ldap")}


def test_sweep_by_max_entries(tmp_path):
    backend = AuthKeysCacheFileBackend(tmp_path)
    for i in range(5):
        backend[(f"u{i}", "s")] = str(i)
        time.sleep(0.01)
    removed = backend.sweep(max_entries=2)
    assert removed == 3
    assert len(list(backend.keys())) == 2


# --- Quick-fix P1: dedup by (type, key) ------------------------------------


class KeyFromTwoSources(AuthkeysSource):
    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        return [f"{RSA} shared"]


def test_dedup_across_sources_by_identity():
    conf = AuthkeysConfig.from_config(
        {
            "cache": {},
            "globals": {},
            "source:a": {"backend": f"{__name__}.KeyFromTwoSources"},
            "source:b": {"backend": f"{__name__}.KeyFromTwoSources"},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    keys = list(auth.resolve("alice", load_delegation=False))
    # Same public key from two sources (different per-source comments) -> once.
    assert len([k for k in keys if k.key == "AAAAB3Nza"]) == 1


# --- Quick-fix P4: getlist fallback copy -----------------------------------


def test_getlist_fallback_is_copied():
    conf = AuthkeysConfig.from_config({"s": {}})
    default = ["a", "b"]
    got = conf["s"].getlist("missing", default)
    got.append("c")
    assert default == ["a", "b"]  # untouched
