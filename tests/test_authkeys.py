"""Core behavior: key parsing, cache TTL, source resolution, dedup, caching."""

import time

import pytest

from authkeys import (
    AuthKeys,
    AuthkeysConfig,
    AuthkeysSource,
    AuthorizedKey,
    default_sanitize,
)
from authkeys.cache import (
    AuthKeysCache,
    AuthKeysCacheFileBackend,
    AuthKeysCacheMemBackend,
)

RSA = "ssh-rsa AAAAB3Nza"
ED = "ssh-ed25519 AAAAC3Nza"


class StaticSource(AuthkeysSource):
    """Test source returning preconfigured keys, counting calls."""

    registry: "dict[str, list[str]]" = {}

    def __init__(self, conf, globals):
        self.name = conf.name.split(":", 1)[-1]
        self.calls = 0
        StaticSource.registry[self.name] = self  # type: ignore

    def authorized_keys(self, username):
        self.calls += 1
        return list(getattr(self, "keys", {}).get(username, []))


# --- AuthorizedKey parsing ------------------------------------------------


def test_parse_type_key_comment():
    k = AuthorizedKey.parse(f"{RSA} alice@host")
    assert (k.type, k.key, k.comment) == ("ssh-rsa", "AAAAB3Nza", "alice@host")


def test_parse_no_comment():
    k = AuthorizedKey.parse(RSA)
    assert k.comment == ""
    assert repr(k) == RSA


def test_parse_explicit_comment_wins_when_absent():
    k = AuthorizedKey.parse(RSA, comment="c")
    assert k.comment == "c"


def test_parse_rejects_single_token():
    with pytest.raises(ValueError):
        AuthorizedKey.parse("ssh-rsa")


def test_parse_all_skips_blank_and_comment_lines():
    text = f"# header\n\n{RSA} a\n   \n# c\n{ED} b\n"
    keys = list(AuthorizedKey.parse_all(text))
    assert [k.key for k in keys] == ["AAAAB3Nza", "AAAAC3Nza"]


# --- Cache ----------------------------------------------------------------


def test_mem_cache_roundtrip_hits():
    cache = AuthKeysCache(AuthKeysCacheMemBackend(), ttl=100)
    cache[("alice", "src")] = "value"
    assert cache[("alice", "src")] == "value"


def test_mem_cache_respects_ttl():
    cache = AuthKeysCache(AuthKeysCacheMemBackend(), ttl=0)
    cache[("alice", "src")] = "value"
    time.sleep(0.01)
    assert cache[("alice", "src")] is None
    assert cache.get(("alice", "src"), include_expired=True) == "value"


def test_file_cache_roundtrip(tmp_path):
    backend = AuthKeysCacheFileBackend(tmp_path)
    cache = AuthKeysCache(backend, ttl=100)
    cache[("alice", "ldap")] = f"{RSA} a"
    assert (tmp_path / "ldap" / "alice").exists()
    assert cache[("alice", "ldap")] == f"{RSA} a"


def test_file_cache_from_config_requires_existing_path(tmp_path):
    conf = AuthkeysConfig.from_config({"cache": {"path": str(tmp_path)}})
    backend = AuthKeysCacheFileBackend.from_config(conf["cache"])
    assert backend.path == tmp_path
    conf2 = AuthkeysConfig.from_config({"cache": {"path": "/does/not/exist"}})
    with pytest.raises(FileNotFoundError):
        AuthKeysCacheFileBackend.from_config(conf2["cache"])


# --- AuthKeys resolution --------------------------------------------------


def _config(extra=None):
    base = {
        "cache": {"backend": "authkeys.cache.AuthKeysCacheMemBackend", "expire": "100"},
        "globals": {},
        "source:test": {"backend": f"{__name__}.StaticSource"},
    }
    if extra:
        base.update(extra)
    return AuthkeysConfig.from_config(base)


def test_resolution_and_default_sanitize_adds_comment():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(_config())
    src = StaticSource.registry["test"]
    src.keys = {"alice": [f"{RSA}"]}  # no comment -> sanitized
    keys = list(auth.authorized_keys("alice"))
    assert len(keys) == 1
    assert keys[0].comment == "alice(src=test)"


def test_resolution_dedups_across_users():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(_config())
    src = StaticSource.registry["test"]
    src.keys = {"alice": [f"{RSA} x"], "bob": [f"{RSA} x", f"{ED} y"]}
    auth.load_user_config(
        "alice", AuthkeysConfig.from_config({"authorized": {"users": "alice\nbob"}})
    )
    keys = list(auth.authorized_keys("alice"))
    assert [k.key for k in keys] == ["AAAAB3Nza", "AAAAC3Nza"]


def test_second_lookup_uses_cache():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(_config())
    src = StaticSource.registry["test"]
    src.keys = {"alice": [f"{RSA} x"]}
    list(auth.authorized_keys("alice"))
    list(auth.authorized_keys("alice"))
    assert src.calls == 1  # second call served from cache


def test_disabled_source_is_skipped():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(
        _config({"source:test": {"backend": f"{__name__}.StaticSource", "enabled": "0"}})
    )
    assert list(auth.authorized_keys("alice")) == []


def test_source_error_falls_back_to_expired_cache():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(
        _config({"cache": {"expire": "0", "expired_on_error": "1"}})
    )
    src = StaticSource.registry["test"]
    src.keys = {"alice": [f"{RSA} x"]}
    list(auth.authorized_keys("alice"))  # populate cache (already expired at ttl=0)

    def boom(username):
        raise RuntimeError("source down")

    src.authorized_keys = boom
    keys = list(auth.authorized_keys("alice"))
    assert [k.key for k in keys] == ["AAAAB3Nza"]
