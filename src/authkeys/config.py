"""Configuration: one TOML ``.cfg`` file read with anycfg.

The system file is ``/etc/authkeys.cfg`` (or the path given with ``--config`` or
``AUTHKEYS_CONFIG``). Its tables are ``[cache]``, ``[globals]``, ``[serve]`` and one
``[source.<name>]`` per key source; ``${env.NAME}`` is replaced from the
environment. A user's ``~/.ssh/authkeys.cfg`` delegation file is read as TOML with
no includes and no interpolation: its author is the user it delegates for.

Unknown keys and values of the wrong type are logged as one WARNING naming the
key (never the value) and ignored; a file that does not parse is a
:class:`~authkeys.exceptions.ConfigError`.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from duho import logging

from .exceptions import ConfigError

__all__ = [
    "CONFIG_ENV",
    "SYSTEM_CONFIG",
    "USER_CONFIG",
    "CacheSettings",
    "Delegation",
    "GlobalSettings",
    "Settings",
    "SourceSettings",
    "chosen_path",
    "duho_loader",
    "load_settings",
    "parse_delegation",
    "read_document",
    "typed",
    "warn_unknown",
]

LOGGER = logging.getLogger("authkeys")

SYSTEM_CONFIG = Path("/etc/authkeys.cfg")
USER_CONFIG = Path(".ssh/authkeys.cfg")
CONFIG_ENV = "AUTHKEYS_CONFIG"

_TOP_KEYS = frozenset({"cache", "globals", "serve", "source"})
_CACHE_KEYS = frozenset(
    {"backend", "expire", "negative_expire", "expired_on_error", "max_stale"}
)
_GLOBAL_KEYS = frozenset({"usermap", "groupmembers"})
_SOURCE_KEYS = frozenset({"backend", "enabled", "cached", "sanitize", "expire"})

_MISSING = object()


def _type_name(types: "Union[type, Tuple[type, ...]]") -> str:
    types = types if isinstance(types, tuple) else (types,)
    return " or ".join(t.__name__ for t in types)


def typed(
    table: Mapping[str, Any],
    key: str,
    types: "Union[type, Tuple[type, ...]]",
    default: Any,
    where: str,
) -> Any:
    """Return ``table[key]`` when it has one of ``types``, else ``default``.

    A present value of another type logs one WARNING naming ``where.key`` and the
    expected type, not the value (it may be a secret). ``bool`` is not an ``int``.
    """
    value = table.get(key, _MISSING)
    if value is _MISSING or value is None:
        return default
    wanted = types if isinstance(types, tuple) else (types,)
    if isinstance(value, bool) and bool not in wanted:
        ok = False
    else:
        ok = isinstance(value, wanted)
    if ok:
        return value
    LOGGER.warning(
        f"Ignoring {where}.{key}: expected {_type_name(types)}, "
        f"got {type(value).__name__}"
    )
    return default


def warn_unknown(table: Mapping[str, Any], known: Iterable[str], where: str) -> None:
    """Log one WARNING per key of ``table`` that is not in ``known``."""
    known = set(known)
    for key in table:
        if key not in known:
            LOGGER.warning(f"Ignoring unknown setting {where}.{key}")


def _list_of_str(table: Mapping[str, Any], key: str, default, where: str):
    value = typed(table, key, (list, str), default, where)
    if isinstance(value, str):
        return [value]
    if value is default:
        return default
    items = [v for v in value if isinstance(v, str)]
    if len(items) != len(value):
        LOGGER.warning(f"Ignoring non-text entries in {where}.{key}")
    return items


@dataclass(frozen=True)
class CacheSettings:
    """The ``[cache]`` table. ``options`` holds the backend's own keys."""

    backend: str = "memory"
    expire: int = 300
    negative_expire: Optional[int] = None
    expired_on_error: bool = False
    max_stale: Optional[int] = None
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GlobalSettings:
    """The ``[globals]`` table: dotted paths of the usermap and group resolver."""

    usermap: str = "authkeys.usermaps.none"
    groupmembers: str = "authkeys.groupmembers.system_groupmembers"


@dataclass(frozen=True)
class SourceSettings:
    """One ``[source.<name>]`` table. ``options`` holds the backend's own keys."""

    name: str
    backend: str
    enabled: bool = True
    cached: bool = True
    sanitize: Optional[str] = None
    expire: Optional[int] = None
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Settings:
    """A whole configuration, as :func:`load_settings` reads it."""

    cache: CacheSettings = field(default_factory=CacheSettings)
    globals: GlobalSettings = field(default_factory=GlobalSettings)
    sources: Mapping[str, SourceSettings] = field(default_factory=dict)
    serve: Mapping[str, Any] = field(default_factory=dict)
    path: Optional[Path] = None

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, Any], *, path: "Optional[Path]" = None
    ) -> "Settings":
        """Build settings from a loaded document, warning about what it ignores."""
        if not isinstance(data, Mapping):
            raise ConfigError(
                f"{path or 'configuration'}: the top level is not a table"
            )
        warn_unknown(data, _TOP_KEYS, "config")
        cache_table = _table(data, "cache")
        globals_table = _table(data, "globals")
        warn_unknown(globals_table, _GLOBAL_KEYS, "globals")
        cache = CacheSettings(
            backend=typed(cache_table, "backend", str, "memory", "cache"),
            expire=typed(cache_table, "expire", int, 300, "cache"),
            negative_expire=typed(cache_table, "negative_expire", int, None, "cache"),
            expired_on_error=typed(
                cache_table, "expired_on_error", bool, False, "cache"
            ),
            max_stale=typed(cache_table, "max_stale", int, None, "cache"),
            options={k: v for k, v in cache_table.items() if k not in _CACHE_KEYS},
        )
        defaults = GlobalSettings()
        global_settings = GlobalSettings(
            usermap=typed(globals_table, "usermap", str, defaults.usermap, "globals"),
            groupmembers=typed(
                globals_table, "groupmembers", str, defaults.groupmembers, "globals"
            ),
        )
        sources: "Dict[str, SourceSettings]" = {}
        for name, table in _table(data, "source").items():
            where = f"source.{name}"
            if not isinstance(table, Mapping):
                LOGGER.warning(f"Ignoring {where}: not a table")
                continue
            backend = typed(table, "backend", str, None, where)
            if not backend:
                LOGGER.warning(f"Ignoring {where}: it names no backend")
                continue
            sources[name] = SourceSettings(
                name=name,
                backend=backend,
                enabled=typed(table, "enabled", bool, True, where),
                cached=typed(table, "cached", bool, True, where),
                sanitize=typed(table, "sanitize", str, None, where),
                expire=typed(table, "expire", int, None, where),
                options={k: v for k, v in table.items() if k not in _SOURCE_KEYS},
            )
        return cls(
            cache=cache,
            globals=global_settings,
            sources=sources,
            serve=dict(_table(data, "serve")),
            path=path,
        )


def _table(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key, {})
    if isinstance(value, Mapping):
        return value
    LOGGER.warning(f"Ignoring {key}: not a table")
    return {}


def read_document(path: "Union[str, os.PathLike]") -> Dict[str, Any]:
    """Read a system configuration file with anycfg; ``ConfigError`` if it fails.

    TOML unless its first line names another format (``#!yaml``); ``${env.NAME}``
    is replaced from the environment, an unset variable giving an empty value.
    """
    import anycfg

    loader = anycfg.Loader(interpolate="vars", inject_env=True)
    try:
        data = loader.load(Path(path), format="cfg")
    except anycfg.ConfigError as e:
        raise ConfigError(str(e)) from None
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ConfigError(f"{path}: the top level is not a table")
    return dict(data)


def duho_loader(path: Path, source: str = "default") -> Dict[str, Any]:
    """``_config_loader_`` for the CLI: the document, or ``{}`` when it is broken.

    duho cannot report a loader's exception as an exit status, so a file that
    does not parse is reported by the command itself when it loads its settings.
    """
    try:
        return read_document(path)
    except ConfigError:
        return {}


def chosen_path(argument: "Optional[Union[str, os.PathLike]]") -> "Optional[Path]":
    """The configuration file in force: ``--config``, else ``AUTHKEYS_CONFIG``
    (empty means none), else :data:`SYSTEM_CONFIG`."""
    if argument:
        return Path(argument)
    if CONFIG_ENV in os.environ:
        value = os.environ[CONFIG_ENV]
        return Path(value) if value else None
    return SYSTEM_CONFIG


def load_settings(path: "Optional[Union[str, os.PathLike]]") -> Settings:
    """Load and validate the configuration at ``path``.

    ``None`` is an empty configuration. A missing file logs one WARNING and is an
    empty configuration too ("no keys" stays a valid answer for sshd); a file that
    does not parse raises :class:`ConfigError`.
    """
    if path is None:
        return Settings()
    path = Path(path)
    if not path.exists():
        LOGGER.warning(
            f"No config file found; resolving with an empty configuration "
            f"(searched: {path})"
        )
        return Settings(path=path)
    return Settings.from_mapping(read_document(path), path=path)


@dataclass(frozen=True)
class Delegation:
    """A user's ``[authorized]`` table: ``users`` is ``None`` when unset."""

    users: Optional[List[str]] = None
    groups: List[str] = field(default_factory=list)


def parse_delegation(text: str, *, where: str = "authkeys.cfg") -> Delegation:
    """Parse a delegation file's text: TOML only, no includes, no interpolation.

    Raises :class:`ConfigError` naming the position, not the text.
    """
    import anycfg

    try:
        data = anycfg.loads(
            text, format="toml", policy=anycfg.Policy(allow_includes=False)
        )
    except anycfg.ConfigError as e:
        raise ConfigError(f"{where}: {_position(e)}") from None
    data = data or {}
    warn_unknown(data, {"authorized"}, where)
    table = _table(data, "authorized")
    warn_unknown(table, {"users", "groups"}, f"{where} authorized")
    users = (
        _list_of_str(table, "users", None, f"{where} authorized")
        if "users" in table
        else None
    )
    groups = _list_of_str(table, "groups", [], f"{where} authorized")
    return Delegation(users=users, groups=list(groups))


def _position(error: Exception) -> str:
    lineno = getattr(error, "lineno", None)
    return (
        f"{type(error).__name__} at line {lineno}" if lineno else type(error).__name__
    )
