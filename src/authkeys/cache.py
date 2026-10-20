"""TTL cache for resolved authorized keys.

Entries are keyed by ``(uid, source_name)`` and store the serialized keys plus a
timestamp. :class:`AuthKeysCache` applies the TTL; backends only persist and
retrieve ``(value, timestamp)`` pairs.
"""

import os
from pathlib import Path
from time import time
from typing import Iterable, Optional, Set, Tuple

from duho import logging

LOGGER = logging.getLogger("authkeys.cache")

# (uid, source_name)
CacheKey = Tuple[str, str]
# (serialized_keys, stored_at_epoch)
CacheEntry = Tuple[str, float]


class AuthKeysCacheBackend:
    """Persist ``(value, timestamp)`` pairs keyed by :data:`CacheKey`.

    Enumeration/deletion (``keys``/``__delitem__``/``sweep``) are optional; a
    backend that can't support them (e.g. an in-memory one across processes)
    raises ``NotImplementedError`` so the ``authkeys cache`` subcommand can report
    the limitation gracefully.
    """

    @classmethod
    def from_config(cls, config) -> "AuthKeysCacheBackend":
        return cls()

    def __getitem__(self, key: CacheKey) -> "Optional[CacheEntry]":  # pragma: no cover
        raise NotImplementedError

    def __setitem__(self, key: CacheKey, value: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def keys(self) -> "Iterable[CacheKey]":  # pragma: no cover
        raise NotImplementedError

    def __delitem__(self, key: CacheKey) -> None:  # pragma: no cover
        raise NotImplementedError

    def sweep(
        self, *, max_age: "Optional[float]" = None, max_entries: "Optional[int]" = None
    ) -> int:
        """Evict expired/excess entries; return the number removed."""
        removed = 0
        entries = [(k, self[k]) for k in self.keys()]
        entries = [(k, e) for k, e in entries if e]
        if max_age is not None:
            cutoff = time() - max_age
            for k, e in list(entries):
                if e[1] < cutoff:
                    del self[k]
                    removed += 1
                    entries.remove((k, e))
        if max_entries is not None and len(entries) > max_entries:
            # Drop the oldest first.
            entries.sort(key=lambda ke: ke[1][1])
            for k, _e in entries[: len(entries) - max_entries]:
                del self[k]
                removed += 1
        return removed


class AuthKeysCacheMemBackend(AuthKeysCacheBackend):
    def __init__(self) -> None:
        self.db: "dict[CacheKey, CacheEntry]" = {}

    def __getitem__(self, key: CacheKey) -> "Optional[CacheEntry]":
        return self.db.get(key)

    def __setitem__(self, key: CacheKey, value: str) -> None:
        self.db[key] = (value, time())

    def keys(self) -> "Iterable[CacheKey]":
        return list(self.db.keys())

    def __delitem__(self, key: CacheKey) -> None:
        self.db.pop(key, None)


def _check_component(what: str, name: str) -> None:
    """Refuse a key part that is not exactly one plain path component.

    The uid can come from a ``serve`` request or a user's delegation file, so
    ``..``, a separator or a drive (``C:x`` on Windows) must not leave the cache.
    """
    if (
        not name
        or name in (".", "..")
        or any(c in name for c in ("/", "\\", ":", "\x00"))
    ):
        raise ValueError(f"cache {what} is not a plain name: {name!r}")


class AuthKeysCacheFileBackend(AuthKeysCacheBackend):
    """Cache keys under ``<path>/<source>/<uid>``; mtime is the timestamp.

    On POSIX an entry, its source directory or the root that is not owned by the
    running user, or that group or others may write, is ignored: whoever can
    write there could plant keys for any user.
    """

    def __init__(self, path: "str | Path") -> None:
        self.path = Path(path)
        self._warned: "Set[str]" = set()

    def _trusted(self, path: Path) -> bool:
        if not hasattr(os, "geteuid"):
            return True
        try:
            st = path.stat()
        except FileNotFoundError:
            return True
        if st.st_uid == os.geteuid() and not st.st_mode & 0o022:
            return True
        if str(path) not in self._warned:
            self._warned.add(str(path))
            LOGGER.warning(
                f"Ignoring cache path {path}: not owned by this user or "
                f"writable by group or others"
            )
        return False

    def _within_root(self, path: Path) -> bool:
        root = os.path.abspath(self.path)
        return os.path.commonpath([root, os.path.abspath(path)]) == root

    @classmethod
    def from_config(cls, config) -> "AuthKeysCacheFileBackend":
        for path in config.getlist("path", []):
            path = Path(path)
            if path.exists():
                return cls(path)
        raise FileNotFoundError(
            "No existing cache 'path' configured for the file cache backend"
        )

    def cached_entry_path(self, key: CacheKey) -> "Optional[Path]":
        """Return the entry's path, creating its source directory.

        Raises ``ValueError`` for a uid or source that is not a plain name, and
        returns ``None`` when the cache root is missing or not trusted.
        """
        uid, src = key
        _check_component("uid", uid)
        _check_component("source", src)
        if not (self.path and self.path.exists()) or not self._trusted(self.path):
            return None
        src_cache = self.path / src
        if not self._within_root(src_cache / uid):
            raise ValueError(f"cache entry escapes the cache root: {key!r}")
        # Cache entries reveal which principals a host trusts -> keep them private.
        src_cache.mkdir(exist_ok=True)
        try:
            src_cache.chmod(0o700)
        except OSError:
            pass
        return src_cache / uid

    def __getitem__(self, key: CacheKey) -> "Optional[CacheEntry]":
        cached = self.cached_entry_path(key)
        if (
            cached
            and cached.exists()
            and self._trusted(cached.parent)
            and self._trusted(cached)
        ):
            return cached.read_text(), cached.stat().st_mtime
        return None

    def __setitem__(self, key: CacheKey, value: str) -> None:
        cached = self.cached_entry_path(key)
        if not cached or not self._trusted(cached.parent):
            return
        # Write atomically (temp file in the same dir + os.replace) so a concurrent
        # reader -- including a separate sshd-spawned process, which the in-process
        # lock does not cover -- never sees a truncated entry.
        import tempfile

        fd, tmp = tempfile.mkstemp(dir=str(cached.parent), prefix=".tmp-")
        try:
            os.write(fd, value.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, str(cached))

    def keys(self) -> "Iterable[CacheKey]":
        if not (self.path and self.path.exists()):
            return []
        found = []
        for src_dir in self.path.iterdir():
            if src_dir.is_dir():
                for entry in src_dir.iterdir():
                    if entry.is_file() and not entry.name.startswith(".tmp-"):
                        found.append((entry.name, src_dir.name))
        return found

    def __delitem__(self, key: CacheKey) -> None:
        cached = self.cached_entry_path(key)
        if cached and cached.exists():
            cached.unlink()


# Marker distinguishing a cached "this (uid, source) genuinely has no keys"
# (negative hit) from a cached key set. It must never be a valid key line.
_NEGATIVE_MARKER = "\x00authkeys:empty"


class AuthKeysCache:
    """TTL cache with a distinct (shorter) TTL for negative (empty) results.

    ``ttl`` is the positive TTL. ``negative_ttl`` (defaults to ``ttl``) bounds a
    cached "no keys" result so a newly-added key appears sooner. An *errored*
    resolution is never stored here -- only genuine results -- so
    ``expired_on_error`` never resurrects an outage as "empty".
    """

    def __init__(
        self,
        backend: AuthKeysCacheBackend,
        ttl: int = 1,
        negative_ttl: "Optional[int]" = None,
    ) -> None:
        self.ttl = ttl
        self.negative_ttl = ttl if negative_ttl is None else negative_ttl
        self.backend = backend

    def _fresh(self, stored_at: float, ttl: int) -> bool:
        return (time() - ttl) <= stored_at

    def get(
        self,
        key: CacheKey,
        *,
        include_expired: bool = False,
        ttl: "Optional[int]" = None,
    ) -> "Optional[str]":
        result = self.backend[key]
        if not result:
            return None
        value, stored_at = result
        is_negative = value == _NEGATIVE_MARKER
        effective = self.negative_ttl if is_negative else (
            self.ttl if ttl is None else ttl
        )
        if include_expired or self._fresh(stored_at, effective):
            return "" if is_negative else value
        return None

    def set(self, key: CacheKey, value: str, *, negative: bool = False) -> None:
        self.backend[key] = _NEGATIVE_MARKER if negative else value

    def __getitem__(self, key: CacheKey) -> "Optional[str]":
        return self.get(key, include_expired=False)

    def __setitem__(self, key: CacheKey, value: str) -> None:
        # Empty string => negative (known-empty) entry with the negative TTL.
        self.set(key, value, negative=(value == ""))
