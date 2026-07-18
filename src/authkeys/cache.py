"""TTL cache for resolved authorized keys.

Entries are keyed by ``(uid, source_name)`` and store the serialized keys plus a
timestamp. :class:`AuthKeysCache` applies the TTL; backends only persist and
retrieve ``(value, timestamp)`` pairs.
"""

from pathlib import Path
from time import time
from typing import Optional, Tuple

# (uid, source_name)
CacheKey = Tuple[str, str]
# (serialized_keys, stored_at_epoch)
CacheEntry = Tuple[str, float]


class AuthKeysCacheBackend:
    """Persist ``(value, timestamp)`` pairs keyed by :data:`CacheKey`."""

    @classmethod
    def from_config(cls, config) -> "AuthKeysCacheBackend":
        return cls()

    def __getitem__(self, key: CacheKey) -> "Optional[CacheEntry]":  # pragma: no cover
        raise NotImplementedError

    def __setitem__(self, key: CacheKey, value: str) -> None:  # pragma: no cover
        raise NotImplementedError


class AuthKeysCacheMemBackend(AuthKeysCacheBackend):
    def __init__(self) -> None:
        self.db: "dict[CacheKey, CacheEntry]" = {}

    def __getitem__(self, key: CacheKey) -> "Optional[CacheEntry]":
        return self.db.get(key)

    def __setitem__(self, key: CacheKey, value: str) -> None:
        self.db[key] = (value, time())


class AuthKeysCacheFileBackend(AuthKeysCacheBackend):
    """Cache keys under ``<path>/<source>/<uid>``; mtime is the timestamp."""

    def __init__(self, path: "str | Path") -> None:
        self.path = Path(path)

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
        uid, src = key
        if not (self.path and self.path.exists()):
            return None
        src_cache = self.path / src
        src_cache.mkdir(exist_ok=True)
        return src_cache / uid

    def __getitem__(self, key: CacheKey) -> "Optional[CacheEntry]":
        cached = self.cached_entry_path(key)
        if cached and cached.exists():
            return cached.read_text(), cached.stat().st_mtime
        return None

    def __setitem__(self, key: CacheKey, value: str) -> None:
        cached = self.cached_entry_path(key)
        if cached:
            cached.write_text(value)


class AuthKeysCache:
    def __init__(self, backend: AuthKeysCacheBackend, ttl: int = 1) -> None:
        self.ttl = ttl
        self.backend = backend

    @property
    def max_valid_time(self) -> float:
        return time() - self.ttl

    def get(
        self, key: CacheKey, *, include_expired: bool = False
    ) -> "Optional[str]":
        result = self.backend[key]
        if result and (include_expired or self.max_valid_time <= result[1]):
            return result[0]
        return None

    def __getitem__(self, key: CacheKey) -> "Optional[str]":
        return self.get(key, include_expired=False)

    def __setitem__(self, key: CacheKey, value: str) -> None:
        self.backend[key] = value
