# `authkeys` — package header

Header-style reference for the `authkeys` package: every public export with its
signature, arguments, contract, and gotchas, so this package can be consumed
without a source dive. Kept current with the public API. For the project
overview and code layout, see the shipped `README.md`, or <https://github.com/jose-pr/authkeys>.

POSIX-only at runtime (`pwd`/`grp` imported lazily) — noted per entry below.
Every public module declares `__all__`; modules starting with `_` are private.
`pip install authkeys` brings anycfg and duho.

## Configuration file

One TOML file, read with anycfg's `cfg` format (TOML unless a `#!<format>`
first line names another, e.g. `#!json`). Which file, highest first:
`--config FILE` (must exist), `AUTHKEYS_CONFIG` (empty means none),
`/etc/authkeys.cfg` (skipped with one WARNING when absent).

```toml
[cache]                      # backend = "memory" (default) | "file" | a plugin name
backend = "file"
path = "/var/cache/authkeys" # file backend: a path or a list (first existing wins)
expire = 300                 # positive TTL, seconds
negative_expire = 60         # TTL of a cached "no keys"; default = expire
expired_on_error = true      # serve expired keys when a source fails
max_stale = 86400            # ...but not more than this past their TTL; unset = no bound

[globals]
usermap = "authkeys.usermaps.none"                        # dotted path
groupmembers = "authkeys.groupmembers.system_groupmembers"

[serve]                      # serve's options (see CLI) plus:
api_key = "${env.AUTHKEYS_APIKEY}"

[source.files]               # one table per source; the name is free
backend = "file"             # a registered source name (see Sources)
enabled = true               # default true
cached = true                # default true
expire = 60                  # per-source TTL; default = [cache] expire
sanitize = "pkg.mod.func"    # dotted path; default authkeys.default_sanitize
paths = ["authorized_keys"]  # the source's own options
```

- `${env.NAME}` is replaced from the environment (an unset variable gives an
  empty value). Values are typed: TOML strings, integers, booleans, lists.
- A key nothing reads, or a value of the wrong type, logs one WARNING naming the
  key (never the value) and is ignored, so the default applies. A file that does
  not parse is a `ConfigError` (CLI: status 3).
- A user's `~/.ssh/authkeys.cfg` delegates: `[authorized] users = [...]`,
  `groups = [...]` (`users` unset means the user alone). It is read as TOML with
  no includes and no `${env.}` expansion, and only when it passes the user-file
  checks (`utils.read_user_file`).

## Core (`authkeys`)

- **`AuthorizedKey`** — `NamedTuple(type, key, comment, options="")`. `__repr__`
  renders the OpenSSH line (`options` prefix + `type key comment`; `options`/
  `comment` omitted when empty).
  - `AuthorizedKey.parse(line, comment=None) -> AuthorizedKey` — parses one
    `authorized_keys` line. Splits off a leading **options prefix** (a first
    token containing `=`, or not matching `^(ssh-|ecdsa-|sk-)`) before
    `type key [comment]`; raises `ValueError` if fewer than 2 tokens remain
    or the type is not an OpenSSH key type (`ssh-*`, `ecdsa-*`, `sk-*`).
    The options token is **quote-aware**, per sshd(8): a space ends it only
    outside double quotes, and `\"` escapes a quote within a quoted value, so
    `command="/usr/bin/tunnel -n 5",no-pty ssh-ed25519 AAAA bob` keeps its real
    `type`/`key`/`comment`. An unterminated quote consumes the rest of the line
    and therefore raises `ValueError` rather than yielding shifted fields.
  - `AuthorizedKey.parse_all(keys: str | Iterable[AuthorizedKey | str] | None) ->
    Iterable[AuthorizedKey]` — a string is split on lines; blank/`#`-comment
    lines are skipped; already-parsed entries pass through unchanged.
- **`KeySource`** — base class for key sources. `options: ClassVar[frozenset[str]]`
  names the keys it reads from its `[source.<name>]` table (others warn).
  `__init__(self, options: Mapping[str, Any], globals: dict)`; override
  `authorized_keys(username) -> Iterable[str]` (base returns nothing). Register a
  subclass with `authkeys.sources.register_source` or the `authkeys.sources`
  entry-point group.
- **`Source`** — `@dataclass(cached, enabled, backend: KeySource | None,
  sanitize, expire)`: a configured source as the resolver runs it.
- **`Settings`**, **`load_settings`** — re-exported from `authkeys.config`.
- **`UserConfig`** — `(authorized_users: list[str] = [], authorized_groups:
  list[str] = [])`.
- **`Usermap = Callable[[name, source_name, source], str]`**;
  **`Sanitizer = Callable[[source_name, uid, AuthorizedKey], AuthorizedKey |
  None]`** (return `None` to drop the key). **`default_sanitize`** fills a
  missing `comment` with `f"{uid}(src={src})"`.
- **`AuthKeys`** — the resolution engine.
  - `load_config(settings: Settings) -> None` — builds `self.sources` (each
    enabled source's backend found by name: `ConfigError` for an unknown one),
    `self.usermap`/`self.groupmembers` (dotted paths), and `self.cache` from
    `[cache]`. A cache backend that cannot be built is logged and leaves
    `self.cache = None`. `self.use_expired_on_error` from `[cache]`.
  - `resolve(username, *, load_delegation=True) -> list[AuthorizedKey]` —
    loads the user's delegation file (if the user has a local account, the file
    exists and passes the user-file checks; a previous grant is dropped first)
    under an internal lock, then resolves keys **outside** the lock so one slow
    source can't stall concurrent callers. The CLI and the HTTP server call this.
  - `authorized_keys(username) -> Iterable[AuthorizedKey]` — generator; walks
    enabled sources for every principal in the resolved `UserConfig`, dedups
    on `(options, type, key)` (keeps the first comment seen). A source that
    raises is logged and, with `expired_on_error`, its expired cache entry
    (bounded by `max_stale`) is served; a cache read or write failure never costs
    the keys a source returned.
  - `user_config_path(username) -> Path | None` — `~/.ssh/authkeys.cfg`;
    POSIX-only; `None` if the user has no local account.
  - `load_user_config(username, delegation: authkeys.config.Delegation) -> None`
    — applies a delegation, expanding `groups` via `self.groupmembers`.
  - Attributes: `globals: dict`, `sources: dict[str, Source]`, `usermap`,
    `users: dict[str, UserConfig]`, `cache: AuthKeysCache | None`,
    `use_expired_on_error: bool`, `groupmembers`, `source_defaults: Source`.
- **`AuthKeysError`**, **`ConfigError`**, **`SourceError`** — re-exported from
  `authkeys.exceptions`.
- **`__version__`** — read from installed package metadata; `"0+unknown"` in a
  bare source checkout.

## Exceptions (`authkeys.exceptions`)

- **`AuthKeysError(Exception)`** — base of authkeys' own errors.
- **`ConfigError(AuthKeysError, ValueError)`** — unusable configuration: a file
  that does not parse, an unknown backend name, a setting a backend refuses. The
  message names the file or setting, never a value.
- **`SourceError(AuthKeysError, RuntimeError)`** — a source could not answer (a
  refused or ambiguous LDAP search); the resolver's error path handles it.

## Config (`authkeys.config`)

- **`SYSTEM_CONFIG = Path("/etc/authkeys.cfg")`**, **`USER_CONFIG =
  Path(".ssh/authkeys.cfg")`** (relative to a home), **`CONFIG_ENV =
  "AUTHKEYS_CONFIG"`**.
- **`load_settings(path: str | PathLike | None) -> Settings`** — `None`: empty
  settings; a missing file: one WARNING and empty settings (exit 0 stays right
  for sshd); a broken file: `ConfigError`.
- **`read_document(path) -> dict`** — the raw document (anycfg `Loader(
  interpolate="vars", inject_env=True)`, format `cfg`); `ConfigError` on failure.
- **`duho_loader(path, source="default") -> dict`** — the CLI's
  `_config_loader_`: the document, or `{}` when it does not parse (the command
  then reports the error itself).
- **`chosen_path(argument) -> Path | None`** — the file in force: `argument`,
  else `AUTHKEYS_CONFIG` (empty: `None`), else `SYSTEM_CONFIG`. Reads the
  environment at the call, never at import.
- **`Settings(cache, globals, sources, serve, path)`** — frozen;
  `Settings.from_mapping(data, *, path=None)` builds and validates (warnings as
  above). **`CacheSettings(backend="memory", expire=300, negative_expire=None,
  expired_on_error=False, max_stale=None, options={})`**, **`GlobalSettings(
  usermap, groupmembers)`**, **`SourceSettings(name, backend, enabled=True,
  cached=True, sanitize=None, expire=None, options={})`** — `options` holds the
  backend's own keys.
- **`Delegation(users: list[str] | None = None, groups: list[str] = [])`**;
  **`parse_delegation(text, *, where="authkeys.cfg") -> Delegation`** — TOML
  only, includes refused, no interpolation; `ConfigError` names the position, not
  the text.
- **`typed(table, key, types, default, where)`** and **`warn_unknown(table,
  known, where)`** — the validation helpers sources use for their own options.

## Cache (`authkeys.cache`)

- **`CacheBackend`** — persists `(value, timestamp)` keyed by `(uid,
  source_name)`. `options: ClassVar[frozenset[str]]` (its `[cache]` keys);
  `from_config(options: Mapping) -> CacheBackend` classmethod.
  `__getitem__`/`__setitem__` must be implemented; `keys()`/`__delitem__` are
  optional (`NotImplementedError`: `authkeys cache` reports it, status 3).
  `sweep(*, max_age=None, max_entries=None) -> int`.
- **`MemoryCache`** (`memory`) — per-process `dict`.
- **`FileCache(path)`** (`file`) — one file per `(uid, source)` under
  `<path>/<source>/<uid>`; file mtime is the timestamp. A uid or source that
  is not one plain name (empty, `.`, `..`, or holding `/`, `\`, `:`, NUL) raises
  `ValueError`; on POSIX a root, source directory or entry not owned by the
  running user or writable by group/other is ignored (one WARNING). Writes are
  atomic (tempfile + rename), owner-only. `from_config` reads `path` (a path or a
  list; first existing wins) — `ConfigError` if none exist.
- **`register_cache(name, cls) -> cls`** (a name taken by another class is a
  `ValueError`), **`cache_names() -> tuple[str, ...]`**, **`get_cache(name) ->
  type`** (`ConfigError` listing the names). Plugins: entry-point group
  `authkeys.caches`.
- **`AuthKeysCache(backend, ttl=1, negative_ttl=None, max_stale=None)`** —
  `negative_ttl` defaults to `ttl`; `max_stale` bounds how far past its TTL an
  entry is returned with `include_expired=True`. `get(key, *,
  include_expired=False, ttl=None) -> str | None`; `set(key, value, *,
  negative=False)`; `__setitem__` treats `""` as a negative entry. An errored
  resolution is never stored.

## Sources (`authkeys.sources`)

`backend = "<name>"` in a `[source.<name>]` table. Optional dependencies are
imported inside each source, so a missing extra fails only when that source is
built.

- **`file`** — **`FileSource`**: reads `~/.ssh/<paths>` for the target user
  (`paths`, default `["authorized_keys", "authorized_keys2"]`) through
  `utils.read_user_file`; `#`-comment/blank lines skipped. POSIX-only; yields
  nothing for an unknown user.
- **`http`** — **`HTTPSource(options, globals, *, ssl_context=None)`**: GETs
  `url` (a `{username}` template, the name percent-encoded), one key per line. A
  status other than 2xx raises `SourceError` (the error path, not "no keys");
  error messages give scheme, host and path, never the query.
- **`github`** — **`GitHubSource(options, globals, *, ssl_context=None)`**: GETs a
  forge's plain-text `.keys` endpoint (`url`, default
  `https://github.com/{username}.keys`). With the default identity usermap local
  account `X` trusts the forge account `X`, which for `root`, `admin`, `git`
  belongs to someone else: use a `usermap`.
  Client options (both): `timeout` (seconds per wait, default 10), `deadline`
  (seconds for the whole request, default 15), `retries` (default 0), `verify`
  (a boolean or a CA-bundle path; default: the OS trust store, offering no OS
  client certificate), `certificate`/`key` (mutual TLS, through sslcontext),
  `proxy` (a proxy URL or `"direct"`; unset: the system's proxy configuration —
  proxy variables, else WinHTTP/macOS/libproxy, PAC and WPAD), `token_env` (the
  variable whose value is sent as `Authorization: Bearer`). A reply over 8 MiB
  is an error; with a certificate or token, a redirect is an error rather than
  followed. Programmatic `ssl_context=` replaces the TLS options. Both need `authkeys[http]` (syshttp).
- **`ldap`** — **`LDAPSource(options, globals, *, ssl_context=None)`**: reads the
  one entry whose `username_attr` (default `uid`; Active Directory:
  `sAMAccountName`) equals the username (escaped per RFC 4515) under `basedn`,
  and turns each value of `cert_attr` (default `userCertificate`, any attribute
  options and case) into an OpenSSH key, comment `user(subject)` without spaces.
  - `server`: `ldaps://host[:port]` or a bare host (LDAPS), or `ldap://` only
    with `starttls = true` or `auth = "gssapi"` (a sealed session); otherwise
    `ConfigError`.
  - `client`: `auto` (default: python-ldap when it imports and neither
    `ssl_context` nor `principal` asks for ldap3; else ldap3), `python-ldap`,
    `ldap3` (2.10.2rc4+). Neither available: `ConfigError` naming `authkeys[ldap]`.
  - `auth`: `gssapi` (default: Kerberos with the host's machine credentials —
    `keytab`, default `/etc/krb5.keytab`, exported as `KRB5_CLIENT_KTNAME` when
    unset and readable; the session sealed (SSF ≥ 56) unless TLS already
    protects it; `principal` picks a keytab entry, ldap3 on POSIX only; on
    Windows ldap3 uses the process's own credentials), `simple` (`bind_dn` and
    `password_env`, the variable holding the password; needs TLS), `external`
    (SASL EXTERNAL with `tls_cert`/`tls_key`), `anonymous`.
  - TLS: `tls_verify` (`system`/unset: the platform store; a CA file or
    directory; `none`: no verification, warns), `tls_cert`/`tls_key` (client
    certificate). ldap3 wraps the socket with an `SSLContext` (the caller's
    `ssl_context`, else one from sslcontext) with host-name checking on;
    python-ldap uses libldap's OpenSSL options and refuses an `ssl_context`.
  - Results: a refused bind or search (result other than 0/32) or more than one
    matching entry raises `SourceError`; referrals are ignored, not followed.
  - `cert_filter` (dotted path; `none` disables) — default
    **`only_auth_keys(username, cert) -> bool`**: keeps a cert within its
    validity period, not self-signed, KeyUsage (if present) with
    digitalSignature, EKU (if present) with clientAuth or anyExtendedKeyUsage.
    `issuer_ca` (a PEM file) also keeps only certificates directly issued by one
    of its certificates.
  - Needs `authkeys[ldap]` (ldap3, cryptography) or python-ldap plus
    cryptography; Kerberos through ldap3 also needs `authkeys[kerberos]`
    (gssapi on POSIX, winkerberos on Windows).
- **`register_source(name, cls) -> cls`** (a name taken by another class is a
  `ValueError`), **`source_names() -> tuple[str, ...]`**, **`get_source(name)
  -> type`** (`ConfigError` listing the names). Plugins: entry-point group
  `authkeys.sources` (`name = "pkg.mod:Class"`); a plugin cannot take a built-in
  name, and one that fails to load is skipped with a WARNING.

## CLI (`authkeys.cli`)

Built on duho (`ConfigArgs` root, `_default_subcommand_ = "resolve"`,
`_completion_command_`).

- **`main(argv: Sequence[str] | None = None) -> int`** — the console script
  (`authkeys`); returns the status. `resolve` is inserted when the first token
  after the root's options names no command: `authkeys %u` and
  `authkeys -c FILE %u` both resolve. Not inserted for no argument at all, or an
  option after the user (`authkeys alice -c F`): those are usage errors (2).
- **`AuthKeysCLI`** — the root: `--config/-c FILE`, `-v`/`-q`/`--loglevel`,
  `--version`; commands `resolve` (alias `keys`), `check`, `serve`, `cache`,
  `completion`. Exit statuses: 0 success (including "no keys"), 1 `serve`
  refused to start, 2 usage error, 3 configuration or internal error, 130
  interrupted.
- **`resolve [user]`** / **`check [user]`** — never let an exception cross:
  any error is one line on stderr and status 3. `--format
  {authorized_keys,json}` (`json`: a list of `{type,key,comment,options}`).
  `check` raises its logger to DEBUG so per-source tracing reaches stderr.
- **`serve`** — `--listen/-l` (a netimps listen specification, default
  `127.0.0.1:8090`: `host:port`, `[v6]:port`, `:port` (all IPv4 addresses), an
  interface name, several comma-separated), `--certificate`/`--key` (PEM; serve
  HTTPS), `--path` (`/keys`), `--max-usernames` (16), `--request-timeout` (10),
  `--max-connections` (64); each also from `AUTHKEYS_SERVE_<OPTION>` and from the
  `[serve]` table (CLI > variable > file > default). The API key only from
  `[serve] api_key`; a present `api_key` that resolved empty refuses to start
  (status 1). A bad listen spec or a socket that cannot be bound is one line,
  status 3. Logs a WARNING for a non-loopback address served without TLS.
- **`cache {show,purge,warm}`** — `show` lists entries with their age; `purge`
  (`--expired` by TTL, `--all`, else `--user`/`--source`; `--dry-run/-n` lists
  without removing); `warm` (positional `users` or `--user`). Status 3 when no
  cache is configured or the backend cannot do the action.
- **`completion {bash,zsh,fish,powershell}`** — prints a completion script.

## HTTP server (`authkeys.server`)

- **`KeyServer(authkeys: AuthKeys, listen="127.0.0.1:8090", *, api_key=None,
  path="/keys", max_usernames=16, require_auth=False, request_timeout=10.0,
  max_connections=64, ssl_context=None)`** — a threaded HTTP server on ONE
  socket bound through `netimps.bind` for one listen entry (a str naming several
  is `ValueError`; port 8090 by default; `OSError`, e.g.
  `netimps.AddressInUseError`, when it cannot bind). `ssl_context` (server side,
  e.g. `sslcontext.create_context("server", certificate=..., key=...)`) serves
  HTTPS; the handshake runs in the connection's thread under its timeout.
  `url` property: `http(s)://host:port/path`, IPv6 in brackets. A
  connection idle for `request_timeout` seconds is closed; past
  `max_connections` concurrent requests a connection gets `503`. Requests are
  logged (logger `authkeys.server`, INFO) as method, path without query,
  status. `ValueError` at construction if `require_auth=True` but `api_key` is
  falsy. `check_auth(provided: list[str]) -> bool` — `True` if `api_key` is
  unset, else a constant-time compare against every provided key.
- **`GET <path>?username=<u>[&username=<u2>...]&apikey=<key>`** (or the key as
  `Authorization: Bearer <key>`) — each `username` (at most `max_usernames`,
  else `400`) resolved through the delegation-and-cache path, sshd wire format.
  `401` on a missing/invalid key when auth is on; `400` on a missing `username`;
  `404` off the path.
- **`bind_servers(authkeys, listen="127.0.0.1:8090", **options) ->
  list[KeyServer]`** — one server per listen entry, all bound before it
  returns; on a failure the ones already bound are closed and the error raised.
- **`serve(servers: KeyServer | Sequence[KeyServer]) -> None`** — runs them
  until interrupted (the first in the calling thread), then shuts all down and
  closes them; warns when `api_key` is unset and for a non-loopback address
  without TLS.
- **`DEFAULT_PORT = 8090`**.

## Usermaps / group members / utils

- **`authkeys.usermaps.none(name, src_name, src) -> str`** — identity map
  (the default usermap).
- **`authkeys.groupmembers.system_groupmembers(name, globals) -> list[str]`**
  — local system group membership (POSIX-only; the default group resolver).
- **`authkeys.utils`**: `get_user(username=None)` -> a passwd entry (current
  uid if omitted; POSIX-only); `get_groupmembers(name) -> list[str]`
  (POSIX-only); `read_user_file(path, owner_uid, home) -> str | None` (sshd
  StrictModes-style: a regular file, not a symlink, at most
  `MAX_USER_FILE_BYTES` = 1 MiB, it and each directory up to `home` owned by
  `owner_uid` or root and not group/other-writable; `None` when absent or
  refused, a refusal logs one WARNING; the mode checks apply on POSIX only);
  `import_module_object("pkg.mod.attr") -> Any`.

## Environment variables

| Variable | Sets | Default |
| --- | --- | --- |
| `AUTHKEYS_CONFIG` | the configuration file (empty: none) | `/etc/authkeys.cfg` |
| `AUTHKEYS_SERVE_LISTEN`, `_CERTIFICATE`, `_KEY`, `_PATH`, `_MAX_USERNAMES`, `_REQUEST_TIMEOUT`, `_MAX_CONNECTIONS` | the `serve` options of the same name | the `[serve]` table, else the option's default |
| `AUTHKEYS_MCP` | `stdio` serves the commands as MCP tools (duho) | unset |
| the ldap source's `password_env` | the simple-bind password (**secret**) | none |
| `KRB5_CLIENT_KTNAME` | the keytab Kerberos reads; the ldap source sets it to `keytab` when unset | `/etc/krb5.keytab` via `keytab` |
| the http/github source's `token_env` | that source's bearer token (**secret**) | none |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `CA_BUNDLE`, `SYSHTTP_*` | read by syshttp for the http/github sources when `proxy`/`verify` are unset | the system's configuration |
| any name in `${env.NAME}` | that value in the system configuration (often a **secret**: `api_key`) | empty |
