"""Small helpers: user/group lookups, dynamic imports, bool parsing.

The ``pwd``/``grp`` modules are POSIX-only and imported lazily so this package
stays importable (and unit-testable) on non-POSIX platforms; only the functions
that actually resolve system users/groups require them.
"""

import os
from importlib import import_module
from typing import Any, Callable, List


def parse_bool(val: Any) -> bool:
    return str(val).lower() in ("1", "true", "enabled", "yes", "on")


def get_user(username: "str | None" = None):
    """Return a ``pwd.struct_passwd`` for ``username`` (or the current uid)."""
    import pwd

    if username is None:
        return pwd.getpwuid(os.getuid())
    return pwd.getpwnam(username)


def import_module_object(fqdn: str) -> Any:
    """Import ``pkg.mod.attr`` and return ``attr``."""
    domain, name = fqdn.rsplit(".", maxsplit=1)
    module = import_module(domain)
    return getattr(module, name)


def try_import(fqdn: str) -> Any:
    try:
        return import_module_object(fqdn)
    except Exception:
        return None


def call(target: "str | Callable", *args, **kwargs) -> Any:
    if isinstance(target, str):
        target = import_module_object(target)
    return target(*args, **kwargs)


def get_groupmembers(name: str) -> "List[str]":
    import grp

    return list(grp.getgrnam(name).gr_mem)
