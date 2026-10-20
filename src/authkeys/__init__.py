"""authkeys: pluggable ``AuthorizedKeysCommand`` provider for OpenSSH.

Resolves a user's authorized SSH keys from one or more configured *sources*
(local files, an HTTP endpoint, LDAP certificates, ...), with optional TTL
caching and user/group aliasing. Designed to be driven either from the CLI as an
``AuthorizedKeysCommand`` or as a long-running key server (``authkeys serve``).
"""

import re
import threading
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Union,
)

from duho import logging

from . import groupmembers, usermaps, utils
from .cache import AuthKeysCache
from .config import Delegation, Settings, load_settings, parse_delegation, warn_unknown
from .exceptions import AuthKeysError, ConfigError, SourceError

__all__ = [
    "AuthKeys",
    "AuthKeysError",
    "AuthorizedKey",
    "ConfigError",
    "KeySource",
    "Sanitizer",
    "Settings",
    "Source",
    "SourceError",
    "UserConfig",
    "Usermap",
    "__version__",
    "default_sanitize",
    "load_settings",
]

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("authkeys")
except Exception:  # not installed (bare source checkout)
    __version__ = "0+unknown"

LOGGER = logging.getLogger("authkeys")


# A recognized `authorized_keys` key-type token (prefix or exact set), per the
# OpenSSH manual: ssh-rsa/ssh-dss/ssh-ed25519(-sk)/sk-ssh-ed25519@openssh.com/
# ecdsa-sha2-*/sk-ecdsa-sha2-*, and their `*-cert-v01@openssh.com` cert variants.
# Anything else as the first token (or any token containing `=`, i.e. an
# options list like `command="...",no-pty`) is an options prefix, not a type.
_KEY_TYPE_RE = re.compile(r"^(ssh-|ecdsa-|sk-)")


def _is_options_prefix(token: str) -> bool:
    return "=" in token or not _KEY_TYPE_RE.match(token)


def _split_first_token(line: str) -> "tuple":
    """Split ``line`` into (first token, remainder), honoring double quotes.

    Per sshd(8) the options list is the first token of an ``authorized_keys``
    line and "no spaces are permitted, except within double quotes"; a ``\\"``
    escapes a quote inside a quoted value. So a plain ``partition(" ")`` cuts
    ``command="/usr/bin/tunnel -n 5",no-pty`` in half. This walks the line
    instead, ending the token only at a space that is *outside* quotes.

    An unterminated quote consumes the rest of the line, leaving an empty
    remainder -- ``AuthorizedKey.parse`` then raises ``ValueError``, which is
    the same skip-and-log path any other malformed line takes.
    """
    quoted = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == " " and not quoted:
            return line[:index], line[index + 1 :]
    return line, ""


class AuthorizedKey(NamedTuple):
    type: str
    key: str
    comment: str
    options: str = ""

    def __repr__(self) -> str:
        base = (
            f"{self.type} {self.key} {self.comment}"
            if self.comment
            else f"{self.type} {self.key}"
        )
        if self.options:
            return f"{self.options} {base}"
        return base

    @classmethod
    def parse(
        cls, authorized_key: str, comment: "Optional[str]" = None
    ) -> "AuthorizedKey":
        options = ""
        first, rest = _split_first_token(authorized_key)
        if first and _is_options_prefix(first):
            options = first
            authorized_key = rest
        parts = authorized_key.split(" ", maxsplit=2)
        if len(parts) < 2:
            raise ValueError("fewer than two fields")
        if not _KEY_TYPE_RE.match(parts[0]):
            raise ValueError("not a known key type")
        if len(parts) == 3 and comment is None:
            comment = parts[2]
        return cls(parts[0], parts[1], comment or "", options)

    @classmethod
    def parse_all(
        cls, keys: "Union[str, Iterable[Union[AuthorizedKey, str]], None]"
    ) -> "Iterable[AuthorizedKey]":
        keys = keys or ""
        if isinstance(keys, str):
            keys = keys.splitlines()
        for key in keys:
            if isinstance(key, str):
                key = key.strip()
                if not key or key.startswith("#"):
                    continue
                key = cls.parse(key)
            if key:
                yield key


class KeySource:
    """Base class for key sources. Subclasses yield raw ``authorized_keys`` lines.

    ``options`` names the keys a source reads from its ``[source.<name>]`` table;
    any other key there is reported as unknown. The constructor gets those keys as
    a read-only mapping and the shared ``globals`` dict.
    """

    options: ClassVar[FrozenSet[str]] = frozenset()

    def __init__(self, options: Mapping[str, Any], globals: dict) -> None:
        pass

    def authorized_keys(self, username: str) -> Iterable[str]:
        return ()


Usermap = Callable[[str, str, "Source"], str]
Sanitizer = Callable[[str, str, AuthorizedKey], "Optional[AuthorizedKey]"]


class UserConfig:
    authorized_users: "List[str]"
    authorized_groups: "List[str]"

    def __init__(self, authorized_users=None, authorized_groups=None) -> None:
        self.authorized_users = authorized_users or []
        self.authorized_groups = authorized_groups or []


def default_sanitize(src: str, uid: str, key: AuthorizedKey) -> AuthorizedKey:
    if not key.comment:
        key = key._replace(comment=f"{uid}(src={src})")
    return key


@dataclass
class Source:
    """A configured source as the resolver runs it."""

    cached: bool
    enabled: bool
    backend: "Optional[KeySource]"
    sanitize: "Optional[Sanitizer]"
    expire: "Optional[int]"  # per-source TTL override; None => use [cache] expire


class AuthKeys:
    def __init__(self) -> None:
        self.globals: dict = {}
        self.sources: "Dict[str, Source]" = {}
        self.usermap: Usermap = usermaps.none
        self.users: "Dict[str, UserConfig]" = {}
        self.cache: "Optional[AuthKeysCache]" = None
        self.use_expired_on_error = False
        self.groupmembers = groupmembers.system_groupmembers
        self.source_defaults = Source(
            cached=True,
            enabled=True,
            backend=None,
            sanitize=default_sanitize,
            expire=None,
        )
        # Guards the per-(uid, source) cache miss -> compute -> store section so
        # the threaded key server (ThreadingHTTPServer) doesn't race on the
        # shared cache backend (esp. the file backend's read/write).
        self._lock = threading.RLock()

    def load_config(self, settings: Settings) -> None:
        """Build the sources, usermap, group resolver and cache from ``settings``.

        An unknown backend name raises :class:`ConfigError`; a cache backend that
        cannot be built is logged and leaves caching off.
        """
        from .cache import get_cache
        from .sources import get_source

        for name, source in settings.sources.items():
            LOGGER.info(f"Registering source {name}")
            backend = None
            if source.enabled:
                cls = get_source(source.backend)
                warn_unknown(source.options, cls.options, f"source.{name}")
                backend = cls(source.options, self.globals)
            sanitize = (
                utils.import_module_object(source.sanitize)
                if source.sanitize
                else self.source_defaults.sanitize
            )
            self.sources[name] = Source(
                cached=source.cached,
                enabled=source.enabled,
                backend=backend,
                sanitize=sanitize,
                expire=source.expire,
            )

        self.usermap = utils.import_module_object(settings.globals.usermap)
        self.groupmembers = utils.import_module_object(settings.globals.groupmembers)

        cache = settings.cache
        cache_cls = get_cache(cache.backend)
        warn_unknown(cache.options, cache_cls.options, "cache")
        try:
            self.cache = AuthKeysCache(
                backend=cache_cls.from_config(cache.options),
                ttl=cache.expire,
                negative_ttl=cache.negative_expire,
                max_stale=cache.max_stale,
            )
        except Exception as e:
            LOGGER.error(f"Could not load cache due to\n{e}")
            self.cache = None
        self.use_expired_on_error = cache.expired_on_error

    def user_config_path(self, username: str):
        """Return a user's ``~/.ssh/authkeys.cfg`` path, or None if unknown.

        POSIX-only (uses ``pwd``); returns None when the user has no local
        account, so the caller can fall back to resolving the literal username.
        """
        from pathlib import Path

        from . import config as _config

        try:
            user = utils.get_user(username)
        except Exception:
            return None
        return Path(user.pw_dir) / _config.USER_CONFIG

    def resolve(
        self, username: str, *, load_delegation: bool = True
    ) -> "List[AuthorizedKey]":
        """Load per-user delegation (if any) and resolve keys.

        Used by both the CLI and the HTTP server so ``[authorized]``
        user/group delegation behaves identically for each. Only the shared
        ``self.users`` mutation in ``load_user_config`` is done under the lock;
        the resolution (which may fetch from a slow upstream) runs OUTSIDE it so
        one hung source can't stall concurrent requests. Returns a
        fully-materialized list.
        """
        if load_delegation:
            # The file as it is now decides: a grant from an earlier load must
            # not survive the file being removed or broken.
            with self._lock:
                self.users.pop(username, None)
            try:
                text = self._delegation_text(username)
                if text is not None:
                    delegation = parse_delegation(
                        text, where=f"{username}'s authkeys.cfg"
                    )
                    with self._lock:
                        self.load_user_config(username, delegation)
            except Exception as e:
                LOGGER.error(f"Could not load delegation config for {username}: {e}")
        return list(self.authorized_keys(username))

    def _delegation_text(self, username: str) -> "Optional[str]":
        """The user's delegation file, read under the user-file checks, or None."""
        from pathlib import Path

        path = self.user_config_path(username)
        if not path:
            return None
        try:
            user = utils.get_user(username)
            owner, home = user.pw_uid, Path(user.pw_dir)
        except Exception:
            owner, home = -1, Path(path).parent.parent
        return utils.read_user_file(Path(path), owner, home)

    def load_user_config(self, username: str, delegation: Delegation) -> None:
        """Apply a delegation: its ``users`` (default: the user alone) plus the
        members of its ``groups``, resolved through ``self.groupmembers``."""
        config = UserConfig()
        config.authorized_users = (
            [username] if delegation.users is None else list(delegation.users)
        )
        config.authorized_groups = list(delegation.groups)
        LOGGER.info(f"Authorized Users: {config.authorized_users}")
        LOGGER.info(f"Authorized Groups: {config.authorized_groups}")
        for groupname in delegation.groups:
            try:
                members = self.groupmembers(groupname, self.globals)
            except Exception as e:
                LOGGER.error(f"Could not resolve group '{groupname}': {e}")
                continue
            LOGGER.info(f"{groupname}: {members}")
            for usr in members:
                if usr not in config.authorized_users:
                    config.authorized_users.append(usr)

        self.users[username] = config

    def _parse_source_lines(
        self, src_name: str, uid: str, raw_lines: "Iterable[str]", sanitize
    ) -> "List[AuthorizedKey]":
        """Parse raw source lines into keys, skipping (not aborting on) bad ones.

        A single malformed line must not discard the whole source's keys, so each
        line is parsed defensively -- a ``ValueError`` on one line is logged and
        skipped and parsing continues.
        """
        keys: "List[AuthorizedKey]" = []
        for raw in raw_lines:
            for line in (raw.splitlines() if isinstance(raw, str) else [raw]):
                try:
                    parsed = list(AuthorizedKey.parse_all(line))
                except ValueError as e:
                    LOGGER.warning(
                        f"Skipping malformed key line from {src_name} for {uid}: {e}"
                    )
                    continue
                for key in parsed:
                    if sanitize:
                        key = sanitize(src_name, uid, key)
                        if not key:
                            continue
                    keys.append(key)
        return keys

    def _resolve_source_user(
        self, src_name: str, src: "Source", usr: str, uid: str
    ) -> "List[AuthorizedKey]":
        """Resolve one source for one user, with the cache guarded by ``self._lock``.

        The lock guards only the cache read and write -- NOT the upstream fetch --
        so one slow/hung source cannot stall other users' logins (esp. concurrent
        ``serve`` requests). Two threads may fetch a cold key concurrently; that is
        correctness-safe (last write wins). Returns a fully-materialized list; the
        caller yields outside any lock.
        """
        cache_key = (uid, src_name)
        src_ttl = getattr(src, "expire", None)
        use_cache = bool(self.cache and src.cached)
        if use_cache:
            cached = self._cached_keys(cache_key, ttl=src_ttl)
            if cached is not None:
                LOGGER.info(f"Using cached source: {src_name} for {usr} -> {uid}")
                return cached

        try:
            LOGGER.info(f"Using source: {src_name} for {usr} -> {uid}")
            keys = self._parse_source_lines(
                src_name, uid, src.backend.authorized_keys(uid), src.sanitize
            )
        except Exception as e:
            LOGGER.error(f"Error while loading keys for {usr} from {src_name}\n{e}")
            if self.use_expired_on_error and self.cache:
                expired = self._cached_keys(cache_key, include_expired=True)
                if expired:
                    LOGGER.warning(
                        f"Falling back to expired keys for {src_name}: "
                        f"{usr} -> {uid}"
                    )
                    return expired
            return []

        # The cache only saves work: a failed write must not cost the keys.
        if use_cache:
            try:
                with self._lock:
                    self.cache[cache_key] = "\n".join(str(k) for k in keys)
            except Exception as e:
                LOGGER.warning(f"Could not cache keys for {uid} from {src_name}: {e}")
        return keys

    def _cached_keys(
        self, cache_key: "tuple", **options
    ) -> "Optional[List[AuthorizedKey]]":
        """Read and parse one cache entry; an unreadable entry is a miss."""
        try:
            with self._lock:
                cached = self.cache.get(cache_key, **options)
            if cached is None:
                return None
            return list(AuthorizedKey.parse_all(cached))
        except Exception as e:
            LOGGER.warning(f"Ignoring unreadable cache entry {cache_key!r}: {e}")
            return None

    def authorized_keys(self, username: str) -> "Iterable[AuthorizedKey]":
        usr_config = self.users.get(username) or UserConfig([username])
        # Dedup on (options, type, key) -- NOT the whole tuple -- so the same
        # public key coming from two sources (with different per-source
        # comments) is emitted once, keeping the first comment seen. An
        # option-bearing key (e.g. `command="...",no-pty ssh-rsa AAAA`) is
        # kept distinct from the bare form of the same key, since the options
        # materially change what the key is allowed to do.
        seen: "set" = set()

        for src_name, src in self.sources.items():
            if not src.enabled or src.backend is None:
                continue
            for usr in usr_config.authorized_users:
                uid = self.usermap(usr, src_name, src)
                for key in self._resolve_source_user(src_name, src, usr, uid):
                    identity = (key.options, key.type, key.key)
                    if identity not in seen:
                        seen.add(identity)
                        yield key
