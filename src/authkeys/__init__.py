"""authkeys: pluggable ``AuthorizedKeysCommand`` provider for OpenSSH.

Resolves a user's authorized SSH keys from one or more configured *sources*
(local files, an HTTP endpoint, LDAP certificates, ...), with optional TTL
caching and user/group aliasing. Designed to be driven either from the CLI as an
``AuthorizedKeysCommand`` or as a long-running key server (``authkeys serve``).
"""

import threading
from argparse import Namespace
from configparser import SectionProxy
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional, Union

from duho import logging

from . import groupmembers, usermaps, utils
from .cache import AuthKeysCache, AuthKeysCacheBackend
from .config import AuthkeysConfig

__version__ = "0.1.1"

LOGGER = logging.getLogger("authkeys")


class AuthorizedKey(NamedTuple):
    type: str
    key: str
    comment: str

    def __repr__(self) -> str:
        if self.comment:
            return f"{self.type} {self.key} {self.comment}"
        return f"{self.type} {self.key}"

    @classmethod
    def parse(cls, authorized_key: str, comment: "Optional[str]" = None) -> "AuthorizedKey":
        parts = authorized_key.split(" ", maxsplit=2)
        if len(parts) < 2:
            raise ValueError(authorized_key)
        if len(parts) == 3 and comment is None:
            comment = parts[2]
        return cls(parts[0], parts[1], comment or "")

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


class AuthkeysSource:
    """Base class for key sources. Subclasses yield raw ``authorized_keys`` lines."""

    def __init__(self, conf: SectionProxy, globals: dict) -> None:
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


class Source(Namespace):
    cached: bool
    enabled: bool
    backend: "Optional[AuthkeysSource]"
    sanitize: "Optional[Sanitizer]"

    @classmethod
    def from_config(
        cls, config: SectionProxy, globals: dict, defaults: "Source"
    ) -> "Source":
        cached = config.getboolean("cached", defaults.cached)
        enabled = config.getboolean("enabled", defaults.enabled)
        backend = config.get("backend")
        sanitize = config.get("sanitize")
        if enabled and backend:
            backend = utils.call(backend, config, globals)
        if isinstance(sanitize, str):
            sanitize = utils.import_module_object(sanitize)
        elif sanitize is None:
            sanitize = defaults.sanitize
        return cls(cached=cached, enabled=enabled, backend=backend, sanitize=sanitize)


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
            cached=True, enabled=True, backend=None, sanitize=default_sanitize
        )
        # Guards the per-(uid, source) cache miss -> compute -> store section so
        # the threaded key server (ThreadingHTTPServer) doesn't race on the
        # shared cache backend (esp. the file backend's read/write).
        self._lock = threading.RLock()

    def load_config(self, config: AuthkeysConfig) -> None:
        for section in config.sections():
            if not section.startswith("source:"):
                continue
            name = section[len("source:"):]
            src_config = config[section]
            LOGGER.info(f"Registering source {name}")
            self.sources[name] = Source.from_config(
                src_config, self.globals, self.source_defaults
            )

        self.usermap = utils.import_module_object(
            config["globals"].get("usermap") or "authkeys.usermaps.none"
        )
        self.groupmembers = utils.import_module_object(
            config["globals"].get("groupmembers")
            or "authkeys.groupmembers.system_groupmembers"
        )

        cache_conf = config["cache"]
        cache_backend = utils.import_module_object(
            cache_conf.get("backend") or "authkeys.cache.AuthKeysCacheMemBackend"
        )
        # Parse the TTL independently: a malformed `expire` should fall back to
        # the default, not disable caching entirely (and not mask a genuine
        # backend construction error below).
        try:
            ttl = int(cache_conf.get("expire", 300))
        except (TypeError, ValueError):
            LOGGER.error(
                f"Invalid cache 'expire' value {cache_conf.get('expire')!r}; "
                f"falling back to default TTL 300"
            )
            ttl = 300
        try:
            self.cache = AuthKeysCache(
                backend=cache_backend.from_config(cache_conf), ttl=ttl
            )
        except Exception as e:
            LOGGER.error(f"Could not load cache due to\n{e}")
            self.cache = None

        self.use_expired_on_error = utils.parse_bool(
            cache_conf.get("expired_on_error")
        )

    def user_config_path(self, username: str):
        """Return a user's ``~/.ssh/authkeys.conf`` path, or None if unknown.

        POSIX-only (uses ``pwd``); returns None when the user has no local
        account, so the caller can fall back to resolving the literal username.
        """
        from pathlib import Path

        from . import config as _config

        try:
            user = utils.get_user(username)
        except Exception:
            return None
        return Path(user.pw_dir) / _config.USER_CONF_PATH

    def resolve(
        self, username: str, *, load_delegation: bool = True
    ) -> "List[AuthorizedKey]":
        """Load per-user delegation (if any) and resolve keys, atomically.

        Used by both the CLI and the HTTP server so ``[authorized]``
        user/group delegation behaves identically for each. Returns a
        fully-materialized list (the shared-state mutation in
        ``load_user_config`` and the resolution both run under ``self._lock``).
        """
        with self._lock:
            if load_delegation:
                path = self.user_config_path(username)
                try:
                    user_conf = AuthkeysConfig.from_config(path) if path else None
                    if user_conf is not None:
                        self.load_user_config(username, user_conf)
                except Exception as e:
                    LOGGER.error(
                        f"Could not load delegation config for {username}: {e}"
                    )
            return list(self.authorized_keys(username))

    def load_user_config(self, username: str, parser: AuthkeysConfig) -> None:
        config = UserConfig()
        authorized = parser["authorized"] if parser.has_section("authorized") else None
        groups = authorized.getlist("groups", []) if authorized else []
        if not authorized or "users" not in authorized:
            config.authorized_users = [username]
        else:
            config.authorized_users = authorized.getlist("users", [])
        config.authorized_groups = list(groups)
        LOGGER.info(f"Authorized Users: {config.authorized_users}")
        LOGGER.info(f"Authorized Groups: {groups}")
        for groupname in groups:
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

    def _resolve_source_user(
        self, src_name: str, src: "Source", usr: str, uid: str
    ) -> "List[AuthorizedKey]":
        """Resolve one source for one user, cached under ``self._lock``.

        The lock makes the cache miss -> compute -> store sequence atomic so the
        threaded key server does not run duplicate upstream fetches or race on
        the file cache backend. Returns a fully-materialized list; the caller
        yields outside the lock so no lock is held across ``yield``.
        """
        cache_key = (uid, src_name)
        with self._lock:
            cached = (
                self.cache.get(cache_key) if self.cache and src.cached else None
            )
            if cached is not None:
                LOGGER.info(f"Using cached source: {src_name} for {usr} -> {uid}")
                return list(AuthorizedKey.parse_all(cached))
            try:
                LOGGER.info(f"Using source: {src_name} for {usr} -> {uid}")
                keys: "List[AuthorizedKey]" = []
                for raw in src.backend.authorized_keys(uid):
                    for key in AuthorizedKey.parse_all(raw):
                        if src.sanitize:
                            key = src.sanitize(src_name, uid, key)
                            if not key:
                                continue
                        keys.append(key)
                if self.cache and src.cached:
                    self.cache[cache_key] = "\n".join(str(k) for k in keys)
                return keys
            except Exception as e:
                LOGGER.error(
                    f"Error while loading keys for {usr} from {src_name}\n{e}"
                )
                if self.use_expired_on_error and self.cache:
                    expired = self.cache.get(cache_key, include_expired=True)
                    if expired:
                        LOGGER.warning(
                            f"Falling back to expired keys for {src_name}: "
                            f"{usr} -> {uid}"
                        )
                        return list(AuthorizedKey.parse_all(expired))
                return []

    def authorized_keys(self, username: str) -> "Iterable[AuthorizedKey]":
        usr_config = self.users.get(username) or UserConfig([username])
        yielded: "List[AuthorizedKey]" = []

        for src_name, src in self.sources.items():
            if not src.enabled or src.backend is None:
                continue
            for usr in usr_config.authorized_users:
                uid = self.usermap(usr, src_name, src)
                for key in self._resolve_source_user(src_name, src, usr, uid):
                    if key not in yielded:
                        yielded.append(key)
                        yield key
