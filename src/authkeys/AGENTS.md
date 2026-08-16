# `authkeys` — package header

Header-style reference for the `authkeys` package: every public export with its
signature, arguments, contract, and gotchas, so this package can be consumed
without a source dive. Kept current with the public API. For the project
overview and code layout, see the shipped `README.md`, or <https://github.com/jose-pr/authkeys>.

POSIX-only at runtime (`pwd`/`grp` imported lazily) — noted per entry below.

## Core (`authkeys`)

- **`AuthorizedKey`** — `NamedTuple(type, key, comment, options="")`. `__repr__`
  renders the OpenSSH line (`options` prefix + `type key comment`; `options`/
  `comment` omitted when empty).
  - `AuthorizedKey.parse(line, comment=None) -> AuthorizedKey` — parses one
    `authorized_keys` line. Splits off a leading **options prefix** (a first
    token containing `=`, or not matching `^(ssh-|ecdsa-|sk-)`) before
    `type key [comment]`; raises `ValueError` if fewer than 2 tokens remain.
    The options token is **quote-aware**, per sshd(8): a space ends it only
    outside double quotes, and `\"` escapes a quote within a quoted value, so
    `command="/usr/bin/tunnel -n 5",no-pty ssh-ed25519 AAAA bob` keeps its real
    `type`/`key`/`comment`. An unterminated quote consumes the rest of the line
    and therefore raises `ValueError` rather than yielding shifted fields.
  - `AuthorizedKey.parse_all(keys: str | Iterable[AuthorizedKey | str] | None) ->
    Iterable[AuthorizedKey]` — a string is split on lines; blank/`#`-comment
    lines are skipped; already-parsed entries pass through unchanged.
- **`AuthkeysSource`** — base class for key sources. `__init__(self, conf:
  SectionProxy, globals: dict)`; override `authorized_keys(username) ->
  Iterable[str]` (base implementation returns nothing). Subclassed by every
  built-in in `authkeys.sources.*`.
- **`Source`** — `@dataclass(cached, enabled, backend, sanitize, expire)`.
  `Source.from_config(config: SectionProxy, globals, defaults: Source) ->
  Source` builds one from a `[source:*]` section; `expire` is a per-source TTL
  override (`None` -> use `[cache] expire`); an invalid `expire` logs and
  falls back to `None`.
- **`UserConfig`** — `(authorized_users: list[str] = [], authorized_groups:
  list[str] = [])`.
- **`Usermap = Callable[[name, source_name, source], str]`**;
  **`Sanitizer = Callable[[source_name, uid, AuthorizedKey], AuthorizedKey |
  None]`** (return `None` to drop the key). **`default_sanitize`** fills a
  missing `comment` with `f"{uid}(src={src})"`.
- **`AuthKeys`** — the resolution engine.
  - `load_config(config) -> None` — populates `self.sources` from every
    `[source:*]` section, `self.usermap`/`self.groupmembers` from `[globals]`
    (a dotted path; default `authkeys.usermaps.none` /
    `authkeys.groupmembers.system_groupmembers`), and `self.cache` from
    `[cache]` (`backend` dotted path, default the in-memory backend; `expire`
    default `300`; `negative_expire` default = `expire`). A cache backend
    construction error is logged and leaves `self.cache = None` (caching is
    silently disabled, not fatal). `self.use_expired_on_error` comes from
    `[cache] expired_on_error`.
  - `resolve(username, *, load_delegation=True) -> list[AuthorizedKey]` —
    loads a per-user delegation config (if the user has a local account and
    the file exists) under an internal lock, then resolves keys **outside**
    the lock so one slow source can't stall concurrent callers (e.g. the HTTP
    server's request threads). This is the entry point the CLI and the HTTP
    server both call.
  - `authorized_keys(username) -> Iterable[AuthorizedKey]` — generator; walks
    enabled sources for every principal in the resolved `UserConfig`, dedups
    on `(options, type, key)` (keeps the first comment seen; an
    options-bearing key is kept distinct from its bare form).
  - `user_config_path(username) -> Path | None` — POSIX-only; `None` if the
    user has no local account.
  - `load_user_config(username, parser) -> None` — applies an `[authorized]
    users=`/`groups=` section, expanding `groups` via `self.groupmembers`.
  - Attributes: `globals: dict`, `sources: dict[str, Source]`, `usermap`,
    `users: dict[str, UserConfig]`, `cache: AuthKeysCache | None`,
    `use_expired_on_error: bool`, `groupmembers`, `source_defaults: Source`.
- **`__version__`** — read from installed package metadata; `"0+unknown"` in a
  bare source checkout.

## Config (`authkeys.config`)

- **`AuthkeysConfig`** — `configparser.ConfigParser` subclass.
  - `getlist(section, option, **kwargs) -> list[str]` — newline-separated
    value split (blank lines filtered); a non-`str` fallback (e.g. a default
    list) is returned as a shallow copy, untouched.
  - `AuthkeysConfig.from_config(config: str | bytes | Path | dict |
    Iterable[...] | None = None) -> AuthkeysConfig` — accepts a
    colon-separated path list (a plain `str`; a Windows drive letter like
    `C:\...` is preserved), a single `Path`/`bytes`/`dict`, or an iterable
    mix; `None` defaults to `CONF_PATHS` (`./authkeys.conf`). Path lookups
    take the **first existing** path and stop; `bytes`/`dict` items are
    always merged in. `${env:VAR}` in file text/bytes is interpolated from
    `os.environ` (a missing variable expands to an empty string) before
    parsing. If **path** candidates were given and **none** existed, one
    `WARNING` is logged to the `authkeys` logger naming every path searched,
    and an empty config is still returned — callers must keep exiting 0, since
    "no keys" is a valid `AuthorizedKeysCommand` answer. `bytes`/`dict`
    sources never trigger the warning.
- **`SYSTEM_CONF_PATHS`** — the built-in system config search path.
  **`USER_CONF_PATH`** — `.ssh/authkeys.conf`, relative to a user's home.

## Cache (`authkeys.cache`)

- **`AuthKeysCacheBackend`** — persists `(value, timestamp)` keyed by `(uid,
  source_name)`. `__getitem__`/`__setitem__` must be implemented;
  `keys()`/`__delitem__` are optional (raise `NotImplementedError` when
  unsupported — the cache management subcommand reports this instead of
  crashing). `sweep(*, max_age=None, max_entries=None) -> int` (returns the
  evicted count) is implemented in terms of the above. `from_config(config)`
  classmethod builds one from `[cache]`.
- **`AuthKeysCacheMemBackend`** — per-process `dict`; `from_config` takes no
  options.
- **`AuthKeysCacheFileBackend(path)`** — one file per `(uid, source)` under
  `<path>/<source>/<uid>`; file mtime is the timestamp. Writes are atomic
  (tempfile + rename); directories/files are chmod'd to owner-only
  (best-effort — an `OSError` is swallowed, e.g. on a non-POSIX filesystem).
  `from_config` reads `path` (first existing entry wins) — raises
  `FileNotFoundError` if none exist.
- **`AuthKeysCache(backend, ttl=1, negative_ttl=None)`** — `negative_ttl`
  defaults to `ttl`. `get(key, *, include_expired=False, ttl=None) -> str |
  None`; `__getitem__` is `get(include_expired=False)`. `set(key, value, *,
  negative=False)`; `__setitem__` treats an **empty string** value as a
  negative (known-empty) entry stored under `negative_ttl`. An errored
  resolution is never stored here — only genuine results.

## Sources (`authkeys.sources`)

Aliases usable as `backend = authkeys.sources.<alias>` in a `[source:*]`
section; each is also importable directly as its real class.

- **`authorizedkeys`** (`sources/file.py`) — reads `~/.ssh/<paths>` for the
  target user (`paths` config, default `authorized_keys, authorized_keys2`);
  `#`-comment/blank lines skipped. POSIX-only (`pwd.getpwnam`); yields nothing
  for an unknown user.
- **`http`** (`sources/http.py`) — GETs `address` (a `{username}`-templated
  format string, percent-encoded), one key per response line. Config:
  `timeout` (default `10.0`), `credentials = cert.pem,key.pem` (mutual TLS),
  `verify` (a bool-like string toggles TLS verification; anything else is
  treated as a CA-bundle path). Raises on a non-2xx response, so a transient
  failure routes through the resolver's error/`expired_on_error` path instead
  of being cached as "no keys". Requires `requests` (`authkeys[http]`),
  imported lazily.
- **`ldap`** (`sources/ldap.py`) — an LDAPS search (`server`, `basedn`,
  `username_attr`, default `uid`) for `cert_attr` (default `userCertificate`)
  X.509 certs, serialized to OpenSSH public-key format. `tls_cert`/`tls_key`
  are the **client** mTLS credentials; `tls_verify` controls **server**
  verification: `none` (insecure, warns), `system`/unset (OS trust store —
  verification is **on** by default), or a file/dir path (CA bundle/dir).
  The username is filter-escaped against LDAP injection. Optional
  `cert_filter: (username, cert) -> bool | str` (a dotted path or callable)
  — `False` drops the cert, a `str` supplies its comment; the default filter
  keeps certs whose key usage permits digital signatures. Requires `ldap3` +
  `cryptography` (`authkeys[ldap]`), imported lazily.
- **`github`** (`sources/github.py`) — GETs a forge's plain-text `.keys`
  endpoint (`url`, `{username}`-templated, default GitHub's; point it at
  another forge with the same convention to reuse this source). No comments
  in the source data. `timeout` default `10.0`. Requires `requests`
  (`authkeys[http]`), imported lazily.
- **`register_source(alias, cls) -> cls`** / **`get_source(alias) -> type`** —
  the alias registry. Additive: `backend =` resolution always accepts a
  fully-qualified dotted path regardless of registration.

## CLI (`authkeys.cli`)

Built on `duho`; see that project's own package header for the `Cli`/`Cmd`
model this builds on.

- **`run(argv: Sequence[str] | None = None) -> int | None`** — the console
  script entry point. Inserts the default `resolve` subcommand when `argv`
  names none (so `authkeys %u` behaves like `authkeys resolve %u`), unless
  `-h`/`--help`/`--version` is present or a bare `--` precedes every token.
- **`Authkeys`** — the CLI root; subcommands `resolve` (alias `keys`),
  `serve`, `cache`, `check`, `completion`.
- **`resolve`** / **`check`** — never let an exception cross this boundary:
  any error is logged to stderr and the command exits `3` (config/internal
  error); `0` on success, including "no keys found" (by design — sshd reads
  empty stdout as deny, not error). `--format {authorized_keys,json}`
  (default `authorized_keys`, the sshd wire format; `json` is a list of
  `{type,key,comment,options}` objects). `check` additionally forces its
  logger to debug level so the resolution engine's per-source tracing
  reaches stderr.
- **`serve`** — builds the HTTP server from `[serve]` config
  (`bind`/`port`/`path`/`api_key`/`max_usernames`) or CLI
  `--bind`/`--port` overrides, then blocks until interrupted. Exits with an
  error if `[serve] api_key` is present but resolves to an empty string
  (fail closed rather than starting unauthenticated by surprise).
- **`cache`** — `action` positional, one of `show` (list each entry with its
  age), `purge` (`--expired` sweeps by TTL, `--all` clears everything, else
  filter by `--user`/`--source`), `warm` (positional `users` or `--user`,
  pre-resolves into the cache). Exits `3` if no cache is configured, or if
  the backend doesn't support the requested action (e.g. enumeration on a
  backend that can't list its entries).
- **`completion`** — prints a shell completion script for `--shell
  {bash,zsh,fish}`.

## HTTP server (`authkeys.server`)

- **`KeyServer(authkeys: AuthKeys, *, bind="127.0.0.1", port=8090,
  api_key=None, path="/keys", max_usernames=16, require_auth=False)`** — a
  threaded HTTP server. Raises `ValueError` at construction if
  `require_auth=True` but `api_key` is falsy (fail closed; used by the CLI
  when `[serve] api_key` is present but resolved empty).
  `check_auth(provided: list[str]) -> bool` — `True` if `api_key` is unset
  (auth disabled), else constant-time-compares against every provided key.
- **`GET <path>?username=<u>[&username=<u2>...]&apikey=<key>`** — one or more
  `username` params (bounded by `max_usernames`, else `400`); each is
  resolved through the full delegation-and-cache path and concatenated as
  sshd-wire-format lines. `401` on a missing/invalid `apikey` when auth is
  enabled; `400` on a missing or excess `username`; `404` off the configured
  path.
- **`serve(server: KeyServer) -> None`** — blocks until interrupted, then
  closes the socket. Logs a loud warning on start if `api_key` is unset
  (authentication disabled).

## Usermaps / group members / utils

- **`authkeys.usermaps.none(name, src_name, src) -> str`** — identity map
  (the built-in default usermap).
- **`authkeys.groupmembers.system_groupmembers(name, globals) -> list[str]`**
  — resolves local system group membership (POSIX-only, lazy import; the
  built-in default group resolver).
- **`authkeys.utils`**: `parse_bool(val) -> bool` (`"1"/"true"/"enabled"/
  "yes"/"on"`, case-insensitive); `get_user(username=None)` -> a passwd-entry
  object (current uid if omitted; POSIX-only, lazy); `get_groupmembers(name)
  -> list[str]` (POSIX-only, lazy); `import_module_object("pkg.mod.attr") ->
  Any`; `try_import(fqdn) -> Any | None` (swallows any exception);
  `call(target: str | Callable, *a, **kw) -> Any` (resolves a dotted-path
  target first).
