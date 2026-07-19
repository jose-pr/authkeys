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
expired_on_error = 1
```

- `AuthKeysCacheMemBackend` — per-process, in-memory (default).
- `AuthKeysCacheFileBackend` — on-disk under `path`, shared across invocations.

With `expired_on_error = 1`, a source failure falls back to the last-known
(expired) cached keys instead of returning nothing — useful when an SSH login
must not be blocked by a transient LDAP/HTTP outage. A malformed `expire` value
falls back to the default TTL rather than disabling caching.

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
