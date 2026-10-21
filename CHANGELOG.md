# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-10-21

This release changes the configuration file, the command line and the Python
API. A configuration written for 0.4 does not load: convert it as below.

### Changed
- **The configuration is one TOML file, `/etc/authkeys.cfg`**, read with anycfg
  (a new dependency). `/etc/authkeys.conf`, `/etc/authkeys/authkeys.conf` and
  `/etc/ssh/authkeys.conf` are no longer read. Name another file with
  `--config FILE` or the new `AUTHKEYS_CONFIG` variable (empty: no file).
  A key authkeys does not know, or a value of the wrong type, is now a WARNING
  naming the key; a file that does not parse is an error (status 3).
- **The per-user delegation file is `~/.ssh/authkeys.cfg`**, TOML, with no
  includes and no `${env.}` expansion.
- **Sources and cache backends are chosen by name** (`backend = "file"`,
  `"http"`, `"github"`, `"ldap"`; `[cache] backend = "memory"` or `"file"`).
  Dotted import paths no longer work as `backend`. Other distributions add names
  through the `authkeys.sources` and `authkeys.caches` entry-point groups.
- **`--config`/`-c` and the logging options go before the command**:
  `authkeys -c FILE resolve %u` or `authkeys -c FILE %u`, not
  `authkeys resolve -c FILE %u`. `--config` takes one file, and a file named
  there must exist (status 2). `authkeys` with no argument, and an option after
  the user (`authkeys alice -c FILE`), are usage errors; `authkeys resolve`
  resolves the current user.
- **`serve` listens where `--listen` says** (`[serve] listen`), a netimps listen
  specification such as `127.0.0.1:8090`, `[::1]:8090`, `:8090` or several
  comma-separated: IPv6 works, and each entry is its own socket. `--bind` and
  `--port` (`[serve] bind`, `port`) are gone; `listen = "0.0.0.0:8090"` replaces
  them. A bad specification, a port out of range or a port in use is one line on
  stderr with status 3 instead of a traceback.
- **`serve` can speak HTTPS**: `--certificate` and `--key` (`[serve]
  certificate`, `key`), through sslcontext. Without TLS on a non-loopback
  address it logs a warning.
- `serve` also takes `--path`, `--max-usernames`, `--request-timeout` and
  `--max-connections`, and each option can come from `AUTHKEYS_SERVE_<OPTION>`
  (command line > variable > `[serve]` > default). A malformed value is a
  one-line usage error (status 2) instead of a traceback.
- `authkeys.server.KeyServer(authkeys, listen, *, ..., ssl_context=None)` binds
  one socket through netimps (was `bind=`/`port=`); `bind_servers()` builds one
  per listen entry and `serve()` takes one server or a list. netimps and
  sslcontext are new dependencies.
- **The http and github sources use syshttp instead of requests** (the `http`
  extra now installs syshttp). The OS trust store verifies servers (truststore
  on Python 3.10+, instead of certifi); the system's proxy configuration (proxy
  variables, else WinHTTP/macOS/libproxy, PAC, WPAD) routes requests unless the
  source sets `proxy` (a URL or `"direct"`); a reply is limited to 8 MiB; a
  `deadline` (default 15 s) bounds the whole request and `retries` defaults to 0.
  The http source's `address` is now `url`, `credentials` is now `certificate`
  and `key`, and both sources take `token_env` for a bearer token. With a client
  certificate or a token, a redirect is an error instead of being followed (it
  would carry the credential to another host). Error messages name the URL
  without its query string.
- **The ldap source is rewritten.** It uses python-ldap when installed (as many
  distributions and appliances ship it) and ldap3 otherwise (`client`), and it
  authenticates: `auth = "gssapi"` (the default) binds with the host's machine
  Kerberos credentials, sealing the session, which also makes `ldap://` on port
  389 work against an Active Directory that requires signing; `simple`
  (`bind_dn`, `password_env`), `external` (client certificate) and `anonymous`
  are the others. Before, every bind was anonymous, so a directory that refuses
  anonymous reads (Active Directory) returned nothing. **A configuration that
  relied on the anonymous bind must now say `auth = "anonymous"`.**
- The ldap source reads the certificate attribute under any options and case
  (`userCertificate;binary`, as OpenLDAP returns it); before, OpenLDAP entries
  gave no keys. `tls_cert`/`tls_key` no longer default to the host's server
  certificate and key, and the files need not exist unless used; `starttls`
  enables StartTLS on `ldap://`; `issuer_ca` keeps only certificates its CA
  issued; the key comment no longer contains spaces. With ldap3 the TLS context
  is an `SSLContext` built with sslcontext (host-name checking on), or the one
  given to `LDAPSource(..., ssl_context=...)`.
- The `ldap` extra requires `ldap3>=2.10.2rc4,<2.11` (signed and sealed SASL)
  and `cryptography>=40.0.0,<51`; the new `kerberos` extra adds gssapi (POSIX)
  or winkerberos (Windows) for Kerberos through ldap3.
- `completion` needs the shell (`bash`, `zsh`, `fish`, or the new `powershell`).
- `cache` gains `purge --dry-run` (`-n`); an unknown action is a usage error.
- The console script calls `authkeys.cli:main` (was `authkeys.cli:run`).
- **The `duho` requirement moves to its 0.7.x series: `>=0.7.4,<0.8.0`** (was
  `>=0.6.0,<0.7.0`). The floor is 0.7.4 because the entry now uses
  `duho.run(..., exit=False)` and the root's `_report_error_`, both added in
  that patch.
- The `authkeys` entry (`authkeys.cli.main`, the console script) goes through
  `duho.run(..., exit=False)` and always returns an `int`. Exit statuses and
  output are unchanged, with three differences: Ctrl-C outside `resolve`,
  `check` and `serve` (which handle it themselves) ends with status 130 and no
  traceback; a broken pipe there ends with status 1, quietly; and `serve`'s
  refusal to start without a usable `api_key` is returned as status 1 with the
  same message on stderr instead of raised as `SystemExit`.
- `authkeys cache` reports "No cache configured", an unsupported backend action
  and an unknown action as `CommandError`s (statuses 3, 3 and 2). The log record
  is the same: logger `authkeys`, level `ERROR`, the same message. With
  `DUHO_TRACEBACK` set the error is now raised instead of logged.
- **Python API**, renamed with no aliases kept:

  | 0.4 | 0.5 |
  | --- | --- |
  | `authkeys.AuthkeysSource`, constructor `(conf: SectionProxy, globals)` | `authkeys.KeySource`, constructor `(options: Mapping, globals)` and an `options` class attribute |
  | `authkeys.sources.authorizedkeys` / `AuthorizedKeysFiles` | `authkeys.sources.FileSource` (`file`) |
  | `authkeys.sources.http` / `HttpAuthorizedKeys` | `authkeys.sources.HTTPSource` (`http`) |
  | `authkeys.sources.github` / `GithubKeys` | `authkeys.sources.GitHubSource` (`github`) |
  | `authkeys.sources.ldap` / `LdapAuthorizedKeys` | `authkeys.sources.LDAPSource` (`ldap`) |
  | `authkeys.sources.ldap.only_auth_keys` | `authkeys.sources.only_auth_keys` |
  | `authkeys.cache.AuthKeysCacheBackend` / `AuthKeysCacheMemBackend` / `AuthKeysCacheFileBackend` | `authkeys.cache.CacheBackend` / `MemoryCache` (`memory`) / `FileCache` (`file`); `from_config(options: Mapping)` |
  | `AuthKeys.load_config(AuthkeysConfig)` | `AuthKeys.load_config(Settings)`, with `authkeys.load_settings(path)` |
  | `AuthKeys.load_user_config(username, parser)` | `AuthKeys.load_user_config(username, Delegation)` |
  | `authkeys.cli.Authkeys`, `authkeys.cli.run` | `authkeys.cli.AuthKeysCLI`, `authkeys.cli.main` |

  Errors raised on purpose derive from `authkeys.exceptions.AuthKeysError`:
  `ConfigError` (was `ValueError`/`FileNotFoundError` from the sources and the
  file cache) and `SourceError` (was `RuntimeError` from the ldap source).

### Removed
- `authkeys.config.AuthkeysConfig` and its `getlist`, `SYSTEM_CONF_PATHS`,
  `USER_CONF_PATH`, `AuthkeysConfig.CONF_PATHS`, the colon-separated `--config`
  list, `Source.from_config`, `authkeys.utils.parse_bool`, `try_import` and
  `call`, and the `sources` attribute aliases.

### Migrating a configuration

| 0.4 (`/etc/authkeys.conf`, INI) | 0.5 (`/etc/authkeys.cfg`, TOML) |
| --- | --- |
| `[source:files]` | `[source.files]` |
| `backend = authkeys.sources.authorizedkeys` | `backend = "file"` (`"http"`, `"github"`, `"ldap"`) |
| `[cache] backend = authkeys.cache.AuthKeysCacheFileBackend` | `[cache] backend = "file"` (or `"memory"`) |
| `paths =` + one value per line | `paths = ["authorized_keys", "authorized_keys2"]` |
| `enabled = 0`, `expired_on_error = 1` | `enabled = false`, `expired_on_error = true` |
| `expire = 3600` | `expire = 3600` (a number, unquoted) |
| `api_key = ${env:AUTHKEYS_APIKEY}` | `api_key = "${env.AUTHKEYS_APIKEY}"` |
| `[serve] bind = 0.0.0.0` and `port = 8090` | `[serve] listen = "0.0.0.0:8090"` |
| `[source:ldap]` with no credentials (anonymous) | `[source.ldap]` with `auth = "anonymous"` (the default is now `"gssapi"`) |
| `authkeys serve --bind H --port P` | `authkeys serve --listen H:P` |
| `[source:http] address = https://...` | `[source.http] url = "https://..."` |
| `credentials = cert.pem,key.pem` | `certificate = "cert.pem"` and `key = "key.pem"` |
| `verify = false` | `verify = false` (a boolean) or `verify = "/path/ca.pem"` |
| `~/.ssh/authkeys.conf`: `users =` + lines | `~/.ssh/authkeys.cfg`: `[authorized]` `users = ["alice", "bob"]` |

Strings are quoted. `max_age` and `max_entries`, shown in the 0.4 example's
`[cache]`, were never read: drop them (0.5 warns about unknown keys).

### Security
- **The file cache no longer reads or writes outside its directory.** A username
  or source name that is not one plain path component (empty, `.`, `..`, or
  holding `/`, `\`, `:` or NUL) is refused, so a username such as `../../etc/x`
  from `serve` or from a user's `[authorized] users` can no longer read another
  file as keys or overwrite it with a cache entry.
- On POSIX the file cache ignores its root, a source directory or an entry that is
  not owned by the user running authkeys or that group or others can write, and
  logs one WARNING naming the path. Make the cache directory owned by, and
  writable only by, the account that runs authkeys.
- **A user's `~/.ssh/authkeys.cfg` does not expand `${env.NAME}`.** It is
  written by the user it delegates for, so it could read the resolver's
  environment (under `serve`, the API key) into a username that was logged and
  sent to every source. `${env.NAME}` still works in `/etc/authkeys.cfg`.
- `~/.ssh/authorized_keys*` (file source) and `~/.ssh/authkeys.cfg` are read
  under sshd's StrictModes rules on POSIX: the file must be a regular file, not a
  symbolic link, of at most 1 MiB, and it and every directory up to the home
  must be owned by the user or root and not writable by group or others. A file
  that fails is skipped with one WARNING naming the path and the reason.
- **`serve` no longer logs the API key.** Each request is logged as the method,
  the path without its query string, and the status. Before, the whole request
  line, `apikey=` included, was logged at INFO, wrong guesses too.
- `serve` closes a connection that sends nothing for `[serve] request_timeout`
  seconds (default 10) and serves at most `[serve] max_connections` requests at
  once (default 64); a connection over the limit gets `503` and is closed.
- **A refused LDAP search is an error, not "no keys".** ldap3 returns the same
  `False` for "no match" and for a search the server refused (a missing bind,
  an expired password, missing rights); the source now checks the result code,
  so a refusal goes through the error path and `expired_on_error` instead of
  being cached over the user's last good keys as an empty result.
- **The ldap source no longer searches in clear text.** ldap3 let the URL's
  scheme override `use_ssl`, so `ldap://` silently sent the search unencrypted
  and ignored `tls_verify`. `ldap://` is now accepted only with `auth = "gssapi"`
  (a sealed session) or `starttls = true`; otherwise use `ldaps://` or a bare
  host name.
- **The ldap source applies a certificate filter by default.** Before, no filter
  ran unless `cert_filter` was set, and every certificate in the attribute
  became a key, encryption and recovery certificates included. The default is
  now `authkeys.sources.only_auth_keys`, which keeps a certificate only when
  it is within its validity period, is not self-signed, its KeyUsage (if any)
  allows digital signature and its ExtendedKeyUsage (if any) includes clientAuth
  or anyExtendedKeyUsage. `cert_filter = none` keeps every certificate.

### Fixed
- A cache entry that cannot be read or parsed is treated as a miss and logged,
  instead of aborting the whole resolution with exit status 3.
- A failed cache write (a full or read-only disk) is a WARNING; the keys the
  source returned are still printed. Before, they were discarded and the
  resolver fell back to expired keys or to none.
- The ldap source reads only directory entries from a search answer: an Active
  Directory search returns referrals beside the entries, and a referral first in
  the list raised `KeyError` for every unknown user. A search matching more than
  one entry is now an error rather than the first entry's keys.
- No "No config file found" WARNING is logged for a user without
  `~/.ssh/authkeys.cfg`; that file is optional.
- A delegation that stops existing stops working: when a user's
  `~/.ssh/authkeys.cfg` is removed or no longer parses, a long-running `serve`
  no longer keeps the users and groups it granted before.
- A broken delegation file is logged by error type and line number; the file's
  text is no longer copied into the log.
- `%` in a configuration value (an API key, a password, an `${env.NAME}`
  expansion) is read as written. Before, it raised `InterpolationSyntaxError`:
  `serve` exited 1 with a traceback and `resolve` exited 3.
- A key line whose type is not an OpenSSH key type (`ssh-*`, `ecdsa-*`, `sk-*`,
  after any options) is malformed and skipped with a WARNING, instead of being
  returned as a key. The WARNING gives the reason, not the line.

### Added
- `[cache] max_stale` (seconds): with `expired_on_error`, an entry is served
  after a source error only while it is at most `max_stale` seconds past its
  TTL. Unset (the default) keeps today's unbounded fallback.
- `serve` accepts the API key as `Authorization: Bearer <key>` as well as the
  `apikey` query parameter, so a client can keep it out of URLs.
- `[serve] request_timeout` and `[serve] max_connections` (see Security).

### Documentation
- The README and docs recommend a dedicated `AuthorizedKeysCommandUser` instead
  of `nobody`: with the on-disk cache, whatever runs as that account can write
  cache entries, and so keys.
- The github source's docs warn that with the default identity usermap local
  account `X` trusts the forge account `X`, which for `root`, `admin` or `git`
  belongs to someone else.
- The shipped API header documents `completion` with its positional shell
  argument, and when `resolve` is inserted before a `--`.

## [0.4.5] - 2026-10-03

Enables duho's MCP launch trigger, which 0.4.4 had turned off. No other change.

### Changed
- **MCP is enabled.** With `AUTHKEYS_MCP=stdio` set, `authkeys` now serves
  its commands (`resolve`, `check`, `serve`, `cache`, `completion`) as MCP
  tools over stdio, which is duho's default launch trigger. 0.4.4 opted the
  whole CLI out. These tools return real `authorized_keys` content, and
  `serve` starts a listener, so only set the variable for an MCP client you
  trust. Without the variable, the CLI behaves exactly as before.

## [0.4.4] - 2026-09-28

Maintenance release: follows duho's 0.6.x ceiling bump and opts the CLI out
of duho's new MCP auto-launch by default — no other change to authkeys' own
behavior or public API.

### Changed
- **The `duho` requirement moves to its 0.6.x series: `>=0.6.0,<0.7.0`** (was
  `>=0.5.0,<0.6.0`). Ceiling-following bump, not a floor raise for a feature
  authkeys uses: the entire duho surface it imports — `AUTO`, `Arg`, `Args`,
  `Choice`, `Cli`, `Cmd`, `LoggingArgs`, `app`, `main`, `print_completion` and
  `duho.logging` — is unchanged by 0.6.0. The full test suite passes against
  the installed `duho==0.6.0` wheel on Python 3.9 and 3.14.

### Added
- **Opted the whole CLI out of duho's MCP auto-launch.** duho 0.6.0 makes
  every `app()`/`main()` call check `AUTHKEYS_MCP=stdio` and, when set,
  serve MCP tools instead of running the requested command. `Authkeys` (the
  CLI root) now declares `_mcp_ = False`, disabling that env trigger for the
  whole app: `authkeys` never listens for `AUTHKEYS_MCP` and always runs as
  a normal CLI. authkeys is a credentials tool — an MCP-exposed `resolve`/
  `check` would hand a caller a user's real `authorized_keys` content, and
  MCP-exposed `serve` would start a listener as the side effect of a single
  tool call — neither is a safe default here.

## [0.4.3] - 2026-08-16

Maintenance release — a dependency-range change only, with no change to
authkeys' own behavior or API.

### Changed
- **The `duho` requirement is now scoped to its minor series:
  `>=0.5.0,<0.6.0`** (was `>=0.5.1,<0.6.0`). The ceiling is unchanged and the
  floor moves down to the start of the series, because nothing authkeys uses
  postdates it: the entire duho surface it imports — `AUTO`, `Arg`, `Args`,
  `Choice`, `Cli`, `Cmd`, `LoggingArgs`, `app`, `main`, `print_completion` and
  `duho.logging` — is present in 0.5.0. The old 0.5.1 floor recorded which duho
  happened to be current when the pin was written rather than anything authkeys
  requires; 0.5.1's only change was a `getclsdef` fix for modules whose
  `__file__` is not on disk (a zipapp), which a normally installed authkeys
  never reaches. The full test suite passes against both ends of the range,
  duho 0.5.0 and 0.5.4, on Python 3.9 and 3.14.

## [0.4.2] - 2026-08-16

Bug-fix release with small additions — no breaking changes.

### Added
- **A warning when no config file is found.** If `--config` (or the system
  search path) names only paths that do not exist, `AuthkeysConfig.from_config`
  now logs one warning listing every path it searched. The exit code stays `0`
  and stdout stays empty — sshd's `AuthorizedKeysCommand` contract does not
  allow failing a login over this — but a typo'd `--config` is no longer
  indistinguishable from a user who genuinely has no keys. A `bytes`/`dict`
  config never triggers it.
- The exit-code convention is now documented in the CLI guide: `0` on success
  **including "no keys"**, `3` on a config or internal error (`cache` also uses
  `2` for an unknown action).

### Fixed
- **Options containing quoted spaces were misparsed.** `AuthorizedKey.parse`
  ended the options token at the first space, so an sshd-legal line such as
  `command="/usr/bin/tunnel -n 5",no-pty ssh-ed25519 AAAA bob` was split at the
  wrong offsets — `type`, `key`, `comment` and `options` all held fragments of
  the wrong fields. The options token is now scanned quote-aware (a space ends
  it only outside double quotes; `\"` escapes a quote inside a quoted value).
  A line with an unterminated quote is now rejected as malformed instead of
  yielding shifted fields.

  This was invisible in the default `authorized_keys` output, which rejoins the
  fields with single spaces and so round-tripped anyway; it corrupted
  `--format json`, the `(options, type, key)` dedup identity used across
  sources, and the comment injected by `default_sanitize`.

## [0.4.1] - 2026-07-28

Maintenance release.

### Changed
- Pinned `duho` dependency to `>=0.5.1,<0.6.0` to ensure stability against future minor updates.
- Migrated the CLI to `duho`'s updated `Cli`/`Cmd` model, using `app()` as the multi-command runner.
- Polished agent documentation in `AGENTS.md` to reflect the latest `duho` API usage.

## [0.4.0] - 2026-07-20

Feature release with fixes — no breaking changes.

### Fixed
- **`--config` with a Windows absolute path was silently ignored.** The
  colon-separated path list was split naively, so `C:\path\authkeys.conf` became
  `["C", "\path\authkeys.conf"]` and the file was never read — the caller got an
  empty config with no error. For `authkeys serve` this also skipped the
  fail-closed `api_key` check and left the server running unauthenticated.
  Drive-letter prefixes are now preserved; POSIX `a.conf:b.conf` lists still split.
- CI reliability (test-only, no runtime code changed):
  - The HTTP key-server tests now bypass any proxy configured in the environment
    (GitHub's Windows runners set `HTTP(S)_PROXY`), which otherwise routed the
    localhost test requests through an unreachable proxy and hung.
  - A concurrency test joined its worker threads without a timeout; the join is
    now bounded and the threads are daemons.
  - A hard per-test `timeout` (via `pytest-timeout`) is configured so any future
    socket/thread stall fails fast with a traceback instead of hanging the job.

### Added
- **Options-prefixed `authorized_keys` lines are now preserved verbatim.** A
  real-world line like `command="...",no-pty ssh-rsa AAAA bob` was previously
  misparsed (the options list was read as the key type). `AuthorizedKey` gains
  an `options: str = ""` field; `parse` now detects an options prefix (a first
  token containing `=`, or not matching a recognized key-type prefix) and
  keeps it separate from `type`/`key`/`comment`, round-tripping byte-for-byte
  through `resolve`/`serve` output. Deduplication now keys on
  `(options, type, key)`, so an option-bearing key is kept distinct from the
  bare form of the same key.
- **`--format authorized_keys|json`** on `authkeys resolve` and
  `authkeys check`. `authorized_keys` (default) is unchanged; `json` prints a
  single JSON array of `{"type", "key", "comment", "options"}` objects instead,
  for scripting/tooling consumers. `serve` is unaffected (always sshd wire
  format).
- **`examples/authkeys-serve.service`**: a template systemd unit for running
  `authkeys serve`, with hardening directives (`DynamicUser=`,
  `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, a minimal
  `RestrictAddressFamilies=`, dropped capabilities) and both ways to supply
  `AUTHKEYS_APIKEY` without putting it in `authkeys.conf`. Documented in
  `docs/guide/server.md`, including why `ProtectHome=` is `read-only` rather
  than stricter (the service needs to read users' `~/.ssh`).

### Changed
- **Internal refactor**: `Source` is now a `@dataclass` instead of an
  `argparse.Namespace` subclass. Same fields (`cached`/`enabled`/`backend`/
  `sanitize`/`expire`), same `from_config` signature, no behavior change.

## [0.3.0] - 2026-07-19

Additive feature release — no breaking changes.

### Added
- **`authkeys.sources.github`**: fetch a user's public keys from GitHub's
  plain-text `.keys` endpoint (`https://github.com/{username}.keys` by
  default). The `url` template can be overridden to point at any forge with
  the same convention (e.g. GitLab), so no separate source class is needed.
  Uses the existing `[http]` extra (`requests`); no new extra.
- **`authkeys check <user>`**: a debugging counterpart to `resolve` that
  prints the same resolved keys to stdout while surfacing the per-source
  resolution trace (which source served/cached which key) on stderr.
- **`authkeys completion [bash|zsh|fish]`**: prints a self-contained shell
  completion script (generated from the CLI's own argument parser via
  `duho`'s completion support) for the given shell.
- **Source registry**: `authkeys.sources.register_source(alias, cls)` and
  `get_source(alias)` for programmatic lookup of source classes by short
  name. The four built-in sources (`authorizedkeys`, `http`, `github`,
  `ldap`) are registered through it; existing `backend =
  authkeys.sources.<alias>` config resolution is unchanged.

### Changed
- `KeyServer.__init__` gained a `require_auth: bool = False` parameter: when
  `True` and `api_key` is falsy, construction raises `ValueError` instead of
  silently starting with authentication disabled. `authkeys serve` now passes
  `require_auth=True` whenever `[serve]` configures an `api_key`, in addition
  to its existing friendly `SystemExit` message — the user-facing CLI
  behavior is unchanged, but the fail-closed invariant now also holds for
  direct `KeyServer` construction (e.g. embedding authkeys as a library).

## [0.2.0] - 2026-07-19

A security and robustness release from a second review pass. **One breaking
change** in the LDAP source (see below).

### Security
- **LDAP now verifies the server certificate by default** (breaking). Previously
  the LDAPS connection trusted any peer certificate. A new `tls_verify` option
  controls it: unset/`system` verifies against the OS trust store (default), a
  path verifies against that CA file/directory, and `none` disables verification
  (insecure; logs a warning). **Deployments that relied on no verification must
  set `tls_verify = none`.** `tls_cert`/`tls_key` are now documented as the client
  mutual-TLS credentials, not server verification.
- The HTTP key server no longer 500s (with a traceback) on a non-ASCII `apikey`;
  it returns a clean 401.
- `authkeys serve` caps the number of `?username=` parameters per request
  (`max_usernames`, default 16), bounding the work an unauthenticated request can
  force.

### Fixed
- A single malformed line in a source (e.g. a corrupt `authorized_keys`) is now
  skipped and logged instead of discarding **all** of that user's keys — which,
  with `expired_on_error`, could previously serve stale/revoked keys.
- The HTTP source now raises on a non-2xx status, so a transient 5xx/403 routes
  through `expired_on_error` (stale fallback) instead of being cached as "this
  user has no keys". Errored fetches are never cached as empty.
- The resolve path never emits a traceback: on a config/internal error it logs one
  line to stderr and exits non-zero (exit 3), keeping `auth.log` clean.
- Bounded LDAP connection/receive timeouts, and the resolver no longer holds its
  lock across the upstream fetch, so one slow/hung source can't stall other
  logins (or, in `serve`, other concurrent requests).
- Emitted keys are deduplicated by `(type, key)`, so the same public key coming
  from two sources is no longer emitted twice with different comments.

### Added
- **Negative caching** with its own `negative_expire` TTL for keyless principals.
- **Per-source `expire`** overriding `[cache] expire` (`0` = don't cache a source).
- **Atomic file-cache writes** (temp file + rename) with `0600`/`0700` perms.
- **`authkeys cache`** subcommand: `show`, `purge` (`--user`/`--source`/
  `--expired`/`--all`), and `warm <users...>`; plus optional `max_age`/
  `max_entries` eviction bounds for the file backend.

### Changed
- `authkeys.__version__` is now read from the installed distribution metadata
  (single source of truth with `pyproject.toml`).

## [0.1.1] - 2026-07-18

Hardening release from a code-review pass. No API breaks.

### Security
- LDAP source now escapes the username in the search filter
  (`escape_filter_chars`), preventing LDAP filter injection when the username is
  attacker-controlled (e.g. via the HTTP key server).
- HTTP source percent-encodes the username before templating it into the request
  URL, preventing path/query tampering of the upstream key service.
- `authkeys serve` now fails closed: if `[serve] api_key` is present but resolves
  empty (e.g. an unset `${env:...}`), it refuses to start instead of silently
  disabling authentication. A truly absent `api_key` still runs unauthenticated
  with a warning.

### Fixed
- HTTP source `verify` now interprets bool-like values (`true`/`false`/...) as a
  boolean; other values remain a CA-bundle path. Previously `verify = false` was
  passed to requests as the string `"false"` (a CA path) and did not disable
  verification.
- The key server (`ThreadingHTTPServer`) now resolves under a lock, so concurrent
  requests no longer race on the shared cache backend or issue duplicate upstream
  fetches for the same key.
- A malformed cache `expire` value falls back to the default TTL instead of
  disabling caching entirely (and no longer masks genuine backend errors).

### Changed
- `authkeys serve` now honors each user's `~/.ssh/authkeys.conf` user/group
  delegation, matching `authkeys resolve` (both go through the new
  `AuthKeys.resolve()`).
- `authkeys <user>` default-command insertion is more robust: a leading flag
  before a bare username (`authkeys -v alice`) is routed to the `resolve`
  subparser instead of erroring.

## [0.1.0] - 2026-07-18

Initial packaged release: a `src/` layout, a `duho`-based CLI, and a published
`authkeys` console script.

### Added
- Declarative CLI (`authkeys resolve` / `authkeys serve`) built on `duho`, with
  `--verbose`/`--quiet`/`--loglevel` and `--version`. `resolve` is the default
  command so `authkeys %u` works directly as an `AuthorizedKeysCommand`.
- Config-driven HTTP key server (`authkeys serve`): bind/port/path/API key from a
  `[serve]` section, constant-time API-key comparison, threaded server with clean
  shutdown, and `${env:VAR}` interpolation to keep secrets off disk.
- `file`, `http`, and `ldap` key sources with lazy imports of their optional
  dependencies (`requests`, `ldap3`, `cryptography`); `http` gains request
  timeouts and configurable TLS verification.
- Packaging: `pyproject.toml` with `http`/`ldap`/`all`/`dev` extras, `py.typed`,
  MIT license, and PyPI classifiers. Supports Python 3.9–3.14.

### Fixed
- In-memory and file cache backends now store and retrieve entries by
  `(uid, source)` and carry a timestamp, so cache lookups actually hit and the
  TTL is honored (the previous mem backend never returned a cached value).
- `Source.from_config` is a real `classmethod`; source defaults (e.g. the default
  sanitizer) are applied when a section omits them.
- Group resolution failures during user-config loading are logged and skipped
  instead of aborting key resolution.
- Blank lines in `authorized_keys` files are no longer emitted as empty keys.

### Changed
- Replaced the shell `bin/authkeys` wrapper and standalone `keygrabber` script
  with the unified `authkeys` CLI and `authkeys serve` subcommand.
