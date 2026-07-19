"""Built-in key sources, re-exported under short aliases used in config.

``backend = authkeys.sources.<alias>`` in a ``[source:*]`` section selects one.
Optional third-party dependencies (``requests``, ``ldap3``, ``cryptography``) are
imported lazily inside each module so the core package stays dependency-free.

Built-ins are also registered by name in ``_SOURCE_REGISTRY`` via
:func:`register_source`. This is additive: config resolution still goes
through ``utils.import_module_object`` unchanged (a fully-qualified
``backend =`` dotted path always works). The registry exists as a lookup
helper for future entry-point-based discovery of third-party sources.
"""

from typing import Dict, Type

from .file import AuthorizedKeysFiles as authorizedkeys
from .github import GithubKeys as github
from .http import HttpAuthorizedKeys as http
from .ldap import LdapAuthorizedKeys as ldap

_SOURCE_REGISTRY: "Dict[str, type]" = {}


def register_source(alias: str, cls: "Type") -> "Type":
    """Register ``cls`` under ``alias`` in the source registry.

    Returns ``cls`` unchanged so it can also be used as a decorator.
    """
    _SOURCE_REGISTRY[alias] = cls
    return cls


def get_source(alias: str) -> "Type":
    """Look up a registered source class by alias.

    Raises ``KeyError`` if ``alias`` was never registered.
    """
    return _SOURCE_REGISTRY[alias]


register_source("authorizedkeys", authorizedkeys)
register_source("http", http)
register_source("ldap", ldap)
register_source("github", github)

__all__ = [
    "authorizedkeys",
    "http",
    "ldap",
    "github",
    "register_source",
    "get_source",
]
