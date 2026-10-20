# Configuration

authkeys reads one TOML file. Which one, highest first:

1. the file named with `--config FILE` (`-c`), which must exist;
2. the file named by `AUTHKEYS_CONFIG` (set but empty means no file);
3. `/etc/authkeys.cfg`.

When the chosen file is `/etc/authkeys.cfg` and it does not exist, authkeys logs
a warning and resolves with an empty configuration (exit status 0: "no keys" is
a valid answer for sshd). A file that does not parse is an error (status 3). See
[`examples/authkeys.cfg`](https://github.com/jose-pr/authkeys/blob/main/examples/authkeys.cfg)
for a fully commented example.

The file is read with [anycfg](https://github.com/jose-pr/anycfg): TOML, unless
its first line names another format (`#!json`, `#!yaml`). Two rules apply to
everything below:

- **`${env.NAME}`** is replaced by the environment variable `NAME` (empty when
  unset), so a secret need not be written in the file:
  `api_key = "${env.AUTHKEYS_APIKEY}"`.
- **Values are typed.** Lists are TOML arrays, flags are `true`/`false`, numbers
  are numbers. A key authkeys does not know, or a value of the wrong type, is
  logged as one WARNING naming the key (never the value) and ignored, so a typo
  does not silently look like it worked.

## Sources

One `[source.<name>]` table per source; the name is yours, `backend` says what
kind of source it is:

```toml
[source.files]
backend = "file"
paths = ["authorized_keys", "authorized_keys2"]
```

Every source takes `enabled` and `cached` (both default `true`), `expire` (a
per-source TTL in seconds, `0` = do not cache it) and `sanitize` (the dotted path
of a callable that rewrites or drops keys). The rest are the source's own
options; see [Key sources](sources.md).

## Cache

```toml
[cache]
backend = "memory"      # or "file"
expire = 3600
negative_expire = 60
expired_on_error = true
```

- `memory` — per-process, in-memory (default).
- `file` — on disk under `path` (a directory, or a list of them: the first that
  exists is used), shared across invocations; entries are written atomically
  (temp file + rename) with `0600` permissions under a `0700` directory.

Behaviors:

- **`expire`** — the positive TTL, seconds (default 300).
- **`negative_expire`** — a separate (usually shorter) TTL for a cached "this user
  has no keys" result, so a keyless principal isn't re-fetched every login but a
  newly-added key still appears quickly. Defaults to `expire`.
- **`expired_on_error`** — on a source *error* (an exception, a non-2xx HTTP
  status, a refused LDAP search), fall back to the last-known (expired) cached
  keys instead of returning nothing, so a transient outage doesn't block logins.
  A merely *empty* result is not an error and never triggers the fallback (and an
  errored fetch is never cached as "empty").
- **`max_stale`** — seconds an entry may be past its TTL and still be served by
  `expired_on_error` (unset: no limit). Bounds how long revoked keys keep working
  while a source is failing.

### Inspecting and purging the cache

```bash
authkeys cache show                       # list entries with ages
authkeys cache purge --expired            # drop expired entries
authkeys cache purge --user alice         # drop one user (or --source, --all)
authkeys cache purge --all --dry-run      # list what would go, remove nothing
authkeys cache warm alice bob             # pre-resolve users (e.g. from cron)
```

`show`/`purge` need an on-disk backend (an in-memory cache is per-process).

The on-disk cache directory must be owned by, and writable only by, the account
that runs authkeys: on POSIX an entry, source directory or root that another
user owns or that group or others can write is ignored with a WARNING, since
whoever can write there could plant keys for any user.

## Per-user delegation

A user's `~/.ssh/authkeys.cfg` may grant other principals' keys to that user's
account. Both `authkeys resolve` and `authkeys serve` honor it:

```toml
[authorized]
users = ["alice", "bob"]
groups = ["admins"]
```

Without `users`, the user's own keys are included, plus the members of `groups`.
The file is written by the user it delegates for, so authkeys treats it as
untrusted:

- it is TOML only: no `#!` format line, no includes, and `${env.NAME}` is **not**
  expanded (only in the system configuration);
- like `~/.ssh/authorized_keys` it is read only when it is a regular file (not a
  symbolic link) of at most 1 MiB, and it and every directory up to the home are
  owned by the user or root and not writable by group or others (sshd's
  StrictModes rules). A file that fails is skipped with a WARNING;
- a missing file is normal and logs nothing; a removed or broken one ends the
  grant it made, also in a running `serve`.

## User and group mapping

`[globals]` can point `usermap` and `groupmembers` at custom callables (loaded by
dotted path) to translate a username into a source-specific id or to resolve
group membership from somewhere other than the local system group database.

```toml
[globals]
usermap = "mypkg.usermaps.some_map"
groupmembers = "mypkg.groupmembers.some_resolver"
```

## Plugins

A distribution can add a source or a cache backend under a name of its own
through the `authkeys.sources` or `authkeys.caches` entry-point group:

```toml
# the plugin's pyproject.toml
[project.entry-points."authkeys.sources"]
vault = "mypkg.vault:VaultSource"   # a subclass of authkeys.KeySource
```

`backend = "vault"` then selects it. A plugin cannot take a built-in name, and
one that fails to load is skipped with a WARNING.
