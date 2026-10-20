# Configuration

authkeys reads, in order, `/etc/authkeys.conf`, `/etc/authkeys/authkeys.conf`,
`/etc/ssh/authkeys.conf`, or a colon-separated list passed with `--config`. The
first existing path wins. See
[`examples/authkeys.conf`](https://github.com/jose-pr/authkeys/blob/main/examples/authkeys.conf)
for a fully commented example.

## Cache

```ini
[cache]
backend = authkeys.cache.AuthKeysCacheMemBackend
expire = 3600
negative_expire = 60
expired_on_error = 1
```

- `AuthKeysCacheMemBackend` — per-process, in-memory (default).
- `AuthKeysCacheFileBackend` — on-disk under `path`, shared across invocations;
  entries are written atomically (temp file + rename) with `0600` perms under a
  `0700` directory.

Behaviors:

- **`expire`** — the positive TTL. A malformed value falls back to the default
  rather than disabling caching.
- **`negative_expire`** — a separate (usually shorter) TTL for a cached "this user
  has no keys" result, so a keyless principal isn't re-fetched every login but a
  newly-added key still appears quickly. Defaults to `expire`.
- **`expired_on_error`** — on a source *error* (an exception or a non-2xx HTTP
  status), fall back to the last-known (expired) cached keys instead of returning
  nothing, so a transient LDAP/HTTP outage doesn't block logins. A merely *empty*
  result is not an error and never triggers the fallback (and an errored fetch is
  never cached as "empty").
- **`max_stale`** — seconds an entry may be past its TTL and still be served by
  `expired_on_error` (unset: no limit). Bounds how long revoked keys keep working
  while a source is failing.
- **Per-source TTL** — any `[source:*]` may set its own `expire` (`0` = don't
  cache that source), overriding `[cache] expire`.

### Inspecting and purging the cache

```bash
authkeys cache show                 # list entries with ages
authkeys cache purge --expired      # drop expired entries
authkeys cache purge --user alice   # drop one user (or --source, --all)
authkeys cache warm alice bob       # pre-resolve users (e.g. from cron)
```

`show`/`purge` need an on-disk backend (an in-memory cache is per-process).

The on-disk cache directory must be owned by, and writable only by, the account
that runs authkeys: on POSIX an entry, source directory or root that another
user owns or that group or others can write is ignored with a WARNING, since
whoever can write there could plant keys for any user.

## Per-user delegation

A per-user `~/.ssh/authkeys.conf` may grant other principals' keys. Both
`authkeys resolve` and `authkeys serve` honor it:

```ini
[authorized]
users =
    alice
    bob
groups =
    admins
```

The file is written by the user it delegates for, so authkeys treats it as
untrusted:

- `${env:NAME}` is **not** expanded in it (only in the system configuration);
- like `~/.ssh/authorized_keys` it is read only when it is a regular file (not a
  symbolic link) of at most 1 MiB, and it and every directory up to the home are
  owned by the user or root and not writable by group or others (sshd's
  StrictModes rules). A file that fails is skipped with a WARNING;
- a missing file is normal and logs nothing; a removed or broken one ends the
  grant it made, also in a running `serve`.

## User and group mapping

`[globals]` can point `usermap` and `groupmembers` at custom callables (loaded by
fully-qualified name) to translate a username into a source-specific id or to
resolve group membership from somewhere other than the local system group
database.

```ini
[globals]
usermap = mypkg.usermaps.some_map
groupmembers = mypkg.groupmembers.some_resolver
```
