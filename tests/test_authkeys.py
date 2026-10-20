"""Core behavior: key parsing, cache TTL, source resolution, dedup, caching."""

import time

import pytest

from authkeys import AuthKeys, AuthorizedKey, KeySource, Settings, default_sanitize
from authkeys.cache import AuthKeysCache, FileCache, MemoryCache
from authkeys.config import Delegation
from authkeys.exceptions import ConfigError
from authkeys.sources import register_source

RSA = "ssh-rsa AAAAB3Nza"
ED = "ssh-ed25519 AAAAC3Nza"


class StaticSource(KeySource):
    """Test source returning preconfigured keys, counting calls."""

    options = frozenset({"name"})
    registry: "dict[str, list[str]]" = {}

    def __init__(self, options, globals):
        self.name = options.get("name", "test")
        self.calls = 0
        StaticSource.registry[self.name] = self  # type: ignore

    def authorized_keys(self, username):
        self.calls += 1
        return list(getattr(self, "keys", {}).get(username, []))


register_source("test-authkeys-static", StaticSource)


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


# --- Options-prefixed lines --------------------------------------------


def test_parse_options_prefix_round_trips_byte_for_byte():
    line = 'command="x",no-pty ssh-rsa AAAA bob'
    k = AuthorizedKey.parse(line)
    assert (k.type, k.key, k.comment) == ("ssh-rsa", "AAAA", "bob")
    assert k.options == 'command="x",no-pty'
    assert str(k) == line


def test_parse_bare_key_has_no_options():
    k = AuthorizedKey.parse(RSA)
    assert k.options == ""
    assert str(k) == RSA


def test_parse_options_without_equals_sign_still_detected():
    # A token that isn't a recognized key type is an options prefix even
    # without a literal "=" (e.g. a single bare option keyword).
    line = "no-pty ssh-rsa AAAA bob"
    k = AuthorizedKey.parse(line)
    assert k.options == "no-pty"
    assert (k.type, k.key) == ("ssh-rsa", "AAAA")


def test_parse_still_rejects_single_token():
    with pytest.raises(ValueError):
        AuthorizedKey.parse("ssh-rsa")


def test_parse_rejects_options_only_line():
    with pytest.raises(ValueError):
        AuthorizedKey.parse('command="x",no-pty')


# --- Options containing quoted spaces --------------------------------------
#
# sshd(8): the options list is the first token, "no spaces are permitted,
# except within double quotes", and \" escapes a quote inside a quoted value.
# A `partition(" ")` on the first space cuts such a token in half and shifts
# every following field; the wire format still round-tripped (repr rejoins
# with single spaces), which is why only JSON/dedup/sanitize showed the damage.

QUOTED = 'command="/usr/bin/tunnel -n 5",no-pty ssh-ed25519 AAAAC3Nza bob'
ESCAPED = 'command="echo \\"hi there\\"",no-pty ssh-ed25519 AAAAC3Nza bob'


def test_parse_options_with_quoted_space_keeps_fields_aligned():
    k = AuthorizedKey.parse(QUOTED)
    assert k.options == 'command="/usr/bin/tunnel -n 5",no-pty'
    assert (k.type, k.key, k.comment) == ("ssh-ed25519", "AAAAC3Nza", "bob")


def test_parse_options_with_quoted_space_round_trips_byte_for_byte():
    assert str(AuthorizedKey.parse(QUOTED)) == QUOTED


def test_parse_options_with_escaped_quote_keeps_fields_aligned():
    k = AuthorizedKey.parse(ESCAPED)
    assert k.options == 'command="echo \\"hi there\\"",no-pty'
    assert (k.type, k.key, k.comment) == ("ssh-ed25519", "AAAAC3Nza", "bob")
    assert str(k) == ESCAPED


def test_parse_options_with_quoted_space_and_no_comment():
    line = 'command="a b" ssh-rsa AAAAB3Nza'
    k = AuthorizedKey.parse(line)
    assert k.options == 'command="a b"'
    assert (k.type, k.key, k.comment) == ("ssh-rsa", "AAAAB3Nza", "")
    assert str(k) == line


def test_parse_rejects_unterminated_quote_in_options():
    # Decision: the unterminated quote swallows the rest of the line, leaving
    # nothing to parse as type/key -- the same skip-and-log path as any other
    # malformed line, rather than a silent misparse.
    with pytest.raises(ValueError):
        AuthorizedKey.parse('command="oops ssh-rsa AAAAB3Nza bob')


def test_parse_all_skips_line_with_unterminated_quote():
    text = f'command="oops ssh-rsa AAAA bob\n{RSA} a\n'
    with pytest.raises(ValueError):
        list(AuthorizedKey.parse_all(text))


def test_default_sanitize_injects_comment_for_quoted_space_options():
    # The injected comment keys off `comment`, which was garbage before the
    # quote-aware split (it used to absorb the real type/key tokens).
    k = AuthorizedKey.parse('command="a b",no-pty ssh-rsa AAAAB3Nza')
    sanitized = default_sanitize("src", "alice", k)
    assert sanitized.comment == "alice(src=src)"
    assert sanitized.options == 'command="a b",no-pty'
    assert (sanitized.type, sanitized.key) == ("ssh-rsa", "AAAAB3Nza")


def test_dedup_identity_uses_real_fields_for_quoted_space_options():
    # Two lines whose *options* differ only inside the quotes must stay
    # distinct, and a repeat of the same line must still collapse to one.
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(_config())
    src = StaticSource.registry["test"]
    src.keys = {
        "alice": [
            'command="a b",no-pty {}'.format(ED),
            'command="a c",no-pty {}'.format(ED),
            'command="a b",no-pty {}'.format(ED),
        ]
    }
    keys = list(auth.authorized_keys("alice"))
    assert len(keys) == 2
    assert {k.options for k in keys} == {'command="a b",no-pty', 'command="a c",no-pty'}
    assert {(k.type, k.key) for k in keys} == {("ssh-ed25519", "AAAAC3Nza")}


def test_dedup_treats_option_bearing_and_bare_key_as_distinct():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(_config())
    src = StaticSource.registry["test"]
    src.keys = {"alice": [RSA, f'command="x",no-pty {RSA}']}
    keys = list(auth.authorized_keys("alice"))
    assert len(keys) == 2
    assert {k.options for k in keys} == {"", 'command="x",no-pty'}


def test_default_sanitize_does_not_touch_options():
    k = AuthorizedKey("ssh-rsa", "AAAA", "", 'command="x",no-pty')
    sanitized = default_sanitize("src", "alice", k)
    assert sanitized.options == 'command="x",no-pty'
    assert sanitized.comment == "alice(src=src)"


# --- Cache ----------------------------------------------------------------


def test_mem_cache_roundtrip_hits():
    cache = AuthKeysCache(MemoryCache(), ttl=100)
    cache[("alice", "src")] = "value"
    assert cache[("alice", "src")] == "value"


def test_mem_cache_respects_ttl():
    cache = AuthKeysCache(MemoryCache(), ttl=0)
    cache[("alice", "src")] = "value"
    time.sleep(0.01)
    assert cache[("alice", "src")] is None
    assert cache.get(("alice", "src"), include_expired=True) == "value"


def test_file_cache_roundtrip(tmp_path):
    backend = FileCache(tmp_path)
    cache = AuthKeysCache(backend, ttl=100)
    cache[("alice", "ldap")] = f"{RSA} a"
    assert (tmp_path / "ldap" / "alice").exists()
    assert cache[("alice", "ldap")] == f"{RSA} a"


def test_file_cache_from_config_requires_existing_path(tmp_path):
    backend = FileCache.from_config({"path": str(tmp_path)})
    assert backend.path == tmp_path
    assert (
        FileCache.from_config({"path": ["/does/not/exist", str(tmp_path)]}).path
        == tmp_path
    )
    with pytest.raises(ConfigError):
        FileCache.from_config({"path": "/does/not/exist"})


# --- AuthKeys resolution --------------------------------------------------


def _config(extra=None):
    base = {
        "cache": {"backend": "memory", "expire": 100},
        "source": {"test": {"backend": "test-authkeys-static"}},
    }
    if extra:
        base.update(extra)
    return Settings.from_mapping(base)


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
    auth.load_user_config("alice", Delegation(users=["alice", "bob"]))
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
        _config(
            {"source": {"test": {"backend": "test-authkeys-static", "enabled": False}}}
        )
    )
    assert list(auth.authorized_keys("alice")) == []


def test_source_error_falls_back_to_expired_cache():
    StaticSource.registry.clear()
    auth = AuthKeys()
    auth.load_config(_config({"cache": {"expire": 0, "expired_on_error": True}}))
    src = StaticSource.registry["test"]
    src.keys = {"alice": [f"{RSA} x"]}
    list(auth.authorized_keys("alice"))  # populate cache (already expired at ttl=0)

    def boom(username):
        raise RuntimeError("source down")

    src.authorized_keys = boom
    keys = list(auth.authorized_keys("alice"))
    assert [k.key for k in keys] == ["AAAAB3Nza"]


# --- Source dataclass ----------------------------------------------------


def test_source_is_a_dataclass_with_expected_fields():
    import dataclasses

    from authkeys import Source

    assert dataclasses.is_dataclass(Source)
    assert {f.name for f in dataclasses.fields(Source)} == {
        "cached",
        "enabled",
        "backend",
        "sanitize",
        "expire",
    }


def test_load_config_builds_sources_from_settings():
    auth = AuthKeys()
    auth.load_config(
        Settings.from_mapping(
            {"source": {"test": {"backend": "test-authkeys-static", "expire": 42}}}
        )
    )
    src = auth.sources["test"]
    assert src.cached is True
    assert src.enabled is True
    assert src.expire == 42
    assert src.sanitize is default_sanitize
    assert isinstance(src.backend, StaticSource)


def test_unknown_backend_name_is_a_config_error():
    with pytest.raises(ConfigError, match="unknown source backend 'nope'"):
        AuthKeys().load_config(
            Settings.from_mapping({"source": {"x": {"backend": "nope"}}})
        )
