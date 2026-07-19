"""Source-alias registry: built-ins registered, custom sources register+lookup."""

from authkeys import AuthkeysSource
from authkeys.sources import (
    authorizedkeys,
    get_source,
    github,
    http,
    ldap,
    register_source,
)


def test_builtin_sources_registered():
    assert get_source("authorizedkeys") is authorizedkeys
    assert get_source("http") is http
    assert get_source("ldap") is ldap
    assert get_source("github") is github


def test_register_and_lookup_custom_source():
    class CustomSource(AuthkeysSource):
        pass

    register_source("custom", CustomSource)
    assert get_source("custom") is CustomSource


def test_module_attr_backcompat_still_resolves():
    # `backend = authkeys.sources.github` (module attribute) must keep
    # working via utils.import_module_object, independent of the registry.
    from authkeys import utils

    resolved = utils.import_module_object("authkeys.sources.github")
    assert resolved is github


def test_unregistered_alias_raises_keyerror():
    import pytest

    with pytest.raises(KeyError):
        get_source("does-not-exist")
