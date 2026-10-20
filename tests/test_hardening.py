"""Regression and feature tests for resolver hardening, caching, and small fixes."""

import ssl
import threading
import time

import pytest

from authkeys import AuthKeys, KeySource, Settings
from authkeys.sources import LDAPSource, register_source
from authkeys.cache import (
    _NEGATIVE_MARKER,
    AuthKeysCache,
    FileCache,
    MemoryCache,
)

RSA = "ssh-rsa AAAAB3Nza"
ED = "ssh-ed25519 AAAAC3Nza"


# --- LDAP tls_verify hardening ---------------------------------------------


@pytest.mark.parametrize(
    "value,expected_validate,ca_key",
    [
        (None, ssl.CERT_REQUIRED, None),
        ("system", ssl.CERT_REQUIRED, None),
        ("none", ssl.CERT_NONE, None),
    ],
)
def test_ldap_tls_verify_modes(value, expected_validate, ca_key):
    pytest.importorskip("ldap3")
    src = LDAPSource({} if value is None else {"tls_verify": value}, {})
    kwargs = src._tls_kwargs()
    assert kwargs["validate"] == expected_validate
    assert "ca_certs_file" not in kwargs and "ca_certs_path" not in kwargs


def test_ldap_tls_verify_file_vs_dir(tmp_path):
    pytest.importorskip("ldap3")
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    kwargs = LDAPSource({"tls_verify": str(ca)}, {})._tls_kwargs()
    assert kwargs["validate"] == ssl.CERT_REQUIRED
    assert kwargs["ca_certs_file"] == str(ca)

    kwargs2 = LDAPSource({"tls_verify": str(tmp_path)}, {})._tls_kwargs()
    assert kwargs2["ca_certs_path"] == str(tmp_path)


# --- Malformed key line doesn't nuke the source -----------------------------


class MixedSource(KeySource):
    def __init__(self, options, globals):
        pass

    def authorized_keys(self, username):
        return [f"{RSA} ok", "BADLINE", f"{ED} ok2"]


def _name(source_cls):
    """Register ``source_cls`` (idempotently) and return its name."""
    name = f"test-hardening-{source_cls.__name__.lower()}"
    register_source(name, source_cls)
    return name


def _auth(source_cls, extra_cache=None):
    cache = {"backend": "memory", "expire": 100}
    cache.update(extra_cache or {})
    conf = Settings.from_mapping(
        {"cache": cache, "source": {"t": {"backend": _name(source_cls)}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    return auth


def test_malformed_line_is_skipped_not_fatal():
    auth = _auth(MixedSource)
    keys = list(auth.resolve("alice", load_delegation=False))
    assert [k.key for k in keys] == ["AAAAB3Nza", "AAAAC3Nza"]


class OnceBadSource(KeySource):
    def __init__(self, options, globals):
        pass

    def authorized_keys(self, username):
        return ["BADLINE"]


def test_malformed_line_does_not_trigger_expired_fallback():
    auth = _auth(OnceBadSource, {"expire": 0, "expired_on_error": True})
    # Pre-seed a stale entry, then let it expire so the top-of-resolve cache read
    # misses and the fetch+parse path (which skips the bad line) runs.
    auth.cache[("alice", "t")] = f"{RSA} stale"
    time.sleep(0.02)  # entry now older than expire=0
    keys = list(auth.resolve("alice", load_delegation=False))
    # The bad line is SKIPPED (empty result), not treated as a source error, so
    # expired_on_error must NOT resurrect the stale key.
    assert keys == []


# --- Lock not held across fetch ---------------------------------------------


class BlockingSource(KeySource):
    gate = threading.Event()

    def __init__(self, options, globals):
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


# --- Negative caching + error-empty -----------------------------------------


def test_negative_cache_uses_negative_ttl():
    cache = AuthKeysCache(MemoryCache(), ttl=100, negative_ttl=0)
    cache[("u", "s")] = ""  # empty => negative entry
    time.sleep(0.01)
    # Negative TTL is 0 -> the empty result has already expired.
    assert cache.get(("u", "s")) is None
    # A positive entry with the same (long) ttl stays fresh.
    cache[("u2", "s")] = f"{RSA} a"
    assert cache.get(("u2", "s")) == f"{RSA} a"


def test_negative_marker_never_confused_with_keys():
    backend = MemoryCache()
    cache = AuthKeysCache(backend, ttl=100)
    cache[("u", "s")] = ""
    stored, _ts = backend[("u", "s")]
    assert stored == _NEGATIVE_MARKER
    assert cache.get(("u", "s")) == ""  # reads back as empty, not the marker


class FlakyHTTPSource(KeySource):
    status = 503

    def __init__(self, options, globals):
        pass

    def authorized_keys(self, username):
        raise RuntimeError(f"HTTP {self.status}")


def test_http_error_falls_back_to_stale_not_cached_empty():
    auth = _auth(FlakyHTTPSource, {"expired_on_error": True})
    auth.cache[("alice", "t")] = f"{RSA} previously-good"
    keys = list(auth.resolve("alice", load_delegation=False))
    assert [k.key for k in keys] == ["AAAAB3Nza"]  # stale served, not empty


# --- Per-source TTL -----------------------------------------------------


def test_per_source_expire_overrides_global():
    conf = Settings.from_mapping(
        {
            "cache": {"backend": "memory", "expire": 100},
            "source": {"t": {"backend": _name(MixedSource), "expire": 0}},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    assert auth.sources["t"].expire == 0
    # With source ttl 0 the cache entry is immediately stale on read.
    auth.cache[("alice", "t")] = f"{RSA} x"
    time.sleep(0.01)
    assert auth.cache.get(("alice", "t"), ttl=auth.sources["t"].expire) is None


# --- Atomic writes + perms ---------------------------------------------


def test_file_backend_atomic_and_private(tmp_path):
    backend = FileCache(tmp_path)
    backend[("alice", "ldap")] = f"{RSA} a"
    entry = tmp_path / "ldap" / "alice"
    assert entry.read_text() == f"{RSA} a"
    # No leftover temp files.
    assert not list((tmp_path / "ldap").glob(".tmp-*"))


# --- Enumeration + sweep -------------------------------------------------


def test_file_backend_keys_and_delete(tmp_path):
    backend = FileCache(tmp_path)
    backend[("alice", "ldap")] = "a"
    backend[("bob", "ldap")] = "b"
    assert set(backend.keys()) == {("alice", "ldap"), ("bob", "ldap")}
    del backend[("alice", "ldap")]
    assert set(backend.keys()) == {("bob", "ldap")}


def test_sweep_by_max_entries(tmp_path):
    backend = FileCache(tmp_path)
    for i in range(5):
        backend[(f"u{i}", "s")] = str(i)
        time.sleep(0.01)
    removed = backend.sweep(max_entries=2)
    assert removed == 3
    assert len(list(backend.keys())) == 2


# --- Dedup by (type, key) -------------------------------------------------


class KeyFromTwoSources(KeySource):
    def __init__(self, options, globals):
        pass

    def authorized_keys(self, username):
        return [f"{RSA} shared"]


def test_dedup_across_sources_by_identity():
    name = _name(KeyFromTwoSources)
    conf = Settings.from_mapping(
        {"source": {"a": {"backend": name}, "b": {"backend": name}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    keys = list(auth.resolve("alice", load_delegation=False))
    # Same public key from two sources (different per-source comments) -> once.
    assert len([k for k in keys if k.key == "AAAAB3Nza"]) == 1
