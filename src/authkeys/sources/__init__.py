"""Built-in key sources, re-exported under short aliases used in config.

``backend = authkeys.sources.<alias>`` in a ``[source:*]`` section selects one.
Optional third-party dependencies (``requests``, ``ldap3``, ``cryptography``) are
imported lazily inside each module so the core package stays dependency-free.
"""

from .file import AuthorizedKeysFiles as authorizedkeys
from .http import HttpAuthorizedKeys as http
from .ldap import LdapAuthorizedKeys as ldap

__all__ = ["authorizedkeys", "http", "ldap"]
