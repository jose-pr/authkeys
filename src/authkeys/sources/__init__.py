"""Key sources, found by name.

``backend = "<name>"`` in a ``[source.<name>]`` table selects one. ``file``,
``http``, ``github`` and ``ldap`` are built in; an installed distribution adds a
source through the ``authkeys.sources`` entry-point group (``name =
"pkg.module:Class"``, a :class:`~authkeys.KeySource` subclass). Optional
dependencies (``syshttp``/``requests``, ``ldap3``, ``cryptography``) are imported
inside each source, so naming a source never fails for a missing extra until it
is used.
"""

from typing import Dict, Tuple, Type

from .. import KeySource
from ..exceptions import ConfigError
from ._file import FileSource
from ._github import GitHubSource
from ._http import HTTPSource
from ._ldap import LDAPSource, only_auth_keys

__all__ = [
    "FileSource",
    "GitHubSource",
    "HTTPSource",
    "LDAPSource",
    "get_source",
    "only_auth_keys",
    "register_source",
    "source_names",
]

_SOURCES: "Dict[str, Type[KeySource]]" = {}
_PLUGINS_LOADED = False


def register_source(name: str, cls: "Type[KeySource]") -> "Type[KeySource]":
    """Register a source class under ``name``; a name taken by another class is a
    ``ValueError``. Returns ``cls``."""
    if _SOURCES.get(name, cls) is not cls:
        raise ValueError(f"source {name!r} is already registered")
    _SOURCES[name] = cls
    return cls


def _load_plugins() -> None:
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    _PLUGINS_LOADED = True
    from .._plugins import load_entry_points

    load_entry_points("authkeys.sources", _SOURCES, KeySource)


def source_names() -> "Tuple[str, ...]":
    """The registered source names, sorted."""
    _load_plugins()
    return tuple(sorted(_SOURCES))


def get_source(name: str) -> "Type[KeySource]":
    """The source class registered as ``name``; ``ConfigError`` listing the names."""
    _load_plugins()
    try:
        return _SOURCES[name]
    except KeyError:
        raise ConfigError(
            f"unknown source backend {name!r}; registered: {', '.join(source_names())}"
        ) from None


register_source("file", FileSource)
register_source("http", HTTPSource)
register_source("github", GitHubSource)
register_source("ldap", LDAPSource)
