"""Source and cache registries: built-in names, registration, entry points."""

import types

import pytest

from authkeys import KeySource, cache, sources
from authkeys.cache import CacheBackend, MemoryCache
from authkeys.exceptions import ConfigError
from authkeys.sources import FileSource, get_source, register_source, source_names


def test_builtin_sources_are_registered():
    assert {"file", "http", "github", "ldap"} <= set(source_names())
    assert get_source("file") is FileSource


def test_builtin_caches_are_registered():
    assert {"memory", "file"} <= set(cache.cache_names())
    assert cache.get_cache("memory") is MemoryCache


def test_register_and_look_up_a_custom_source():
    class CustomSource(KeySource):
        pass

    assert register_source("test-registry-custom", CustomSource) is CustomSource
    assert get_source("test-registry-custom") is CustomSource
    # the same class again is fine
    register_source("test-registry-custom", CustomSource)


def test_a_taken_name_is_an_error():
    class Other(KeySource):
        pass

    with pytest.raises(ValueError, match="already registered"):
        register_source("file", Other)


def test_unknown_name_lists_the_registered_ones():
    with pytest.raises(ConfigError, match="registered: .*file"):
        get_source("nope")
    with pytest.raises(ConfigError, match="registered: .*memory"):
        cache.get_cache("nope")


def _fake_entry_points(monkeypatch, group, entries):
    from authkeys import _plugins

    def fake(wanted):
        return entries if wanted == group else []

    monkeypatch.setattr(_plugins, "_entry_points", fake)


class _EP:
    def __init__(self, name, obj=None, error=None):
        self.name, self._obj, self._error = name, obj, error

    def load(self):
        if self._error:
            raise self._error
        return self._obj


def test_entry_points_add_sources_and_skip_broken_ones(monkeypatch, caplog):
    class PluginSource(KeySource):
        pass

    _fake_entry_points(
        monkeypatch,
        "authkeys.sources",
        [
            _EP("test-plugin", PluginSource),
            _EP("test-broken", error=ImportError("no module named x")),
            _EP("test-notasource", object),
            _EP("file", PluginSource),  # a built-in name is never replaced
        ],
    )
    monkeypatch.setattr(sources, "_SOURCES", dict(sources._SOURCES))
    monkeypatch.setattr(sources, "_PLUGINS_LOADED", False)
    assert get_source("test-plugin") is PluginSource
    assert get_source("file") is FileSource
    names = source_names()
    assert "test-broken" not in names and "test-notasource" not in names
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "test-broken" in messages and "test-notasource" in messages


def test_entry_points_add_caches(monkeypatch):
    class PluginCache(CacheBackend):
        pass

    _fake_entry_points(
        monkeypatch, "authkeys.caches", [_EP("test-plugin-cache", PluginCache)]
    )
    monkeypatch.setattr(cache, "_CACHES", dict(cache._CACHES))
    monkeypatch.setattr(cache, "_PLUGINS_LOADED", False)
    assert cache.get_cache("test-plugin-cache") is PluginCache


def test_sources_package_attributes_are_the_classes_not_modules():
    assert isinstance(sources.FileSource, type)
    assert not isinstance(getattr(sources, "file", None), types.ModuleType)
