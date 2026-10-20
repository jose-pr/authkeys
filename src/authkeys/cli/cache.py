"""``authkeys cache``: show, purge or warm the resolved-keys cache."""

import time
import typing as _ty

from duho import Arg, Choice, Cmd, CommandError, LoggingArgs

from ._common import build


class Cache(LoggingArgs, Cmd):
    """Inspect, purge, or warm the resolved-keys cache."""

    _parsername_ = "cache"
    _logger_name_ = "authkeys"

    action: "Arg[str, Choice('show', 'purge', 'warm')]" = "show"
    "One of: show, purge, warm"
    ("action",)

    user: _ty.Optional[str] = None
    "Limit purge to this user (uid), or warm this user"
    ("--user", "-u")

    source: _ty.Optional[str] = None
    "Limit purge to this source"
    ("--source", "-s")

    expired: bool = False
    "purge: only remove expired entries"
    ("--expired",)

    all: bool = False
    "purge: remove every entry"
    ("--all",)

    dry_run: bool = False
    "purge: list what would be removed, remove nothing"
    ("--dry-run", "-n")

    users: _ty.List[str] = []
    "warm: users to pre-resolve into the cache"
    ("users",)

    def __call__(self) -> "int | None":
        auth = build(self)
        if auth.cache is None:
            raise CommandError("No cache configured", 3)
        backend = auth.cache.backend
        try:
            if self.action == "show":
                for uid, src in sorted(backend.keys()):
                    entry = backend[(uid, src)]
                    age = int(time.time() - entry[1]) if entry else "?"
                    print(f"{src}\t{uid}\tage={age}s")
                return 0
            if self.action == "purge":
                return self._purge(auth.cache)
            targets = self.users or ([self.user] if self.user else [])
            for username in targets:
                keys = auth.resolve(username)
                self._logger_.info(f"Warmed {username}: {len(keys)} key(s)")
            return 0
        except NotImplementedError:
            raise CommandError(
                "The configured cache backend does not support this action "
                "(in-memory caches are per-process).",
                3,
            ) from None

    def _purge(self, cache) -> int:
        backend = cache.backend
        if self.expired:
            cutoff = time.time() - cache.ttl
            doomed = [k for k in backend.keys() if (backend[k] or ("", 0))[1] < cutoff]
        else:
            doomed = [
                (uid, src)
                for uid, src in backend.keys()
                if self.all
                or not (
                    (self.user and uid != self.user)
                    or (self.source and src != self.source)
                )
            ]
        for uid, src in sorted(doomed):
            if self.dry_run:
                print(f"would remove {src}\t{uid}")
            else:
                del backend[(uid, src)]
        verb = "Would purge" if self.dry_run else "Purged"
        self._logger_.info(f"{verb} {len(doomed)} cache entr(y/ies)")
        return 0
