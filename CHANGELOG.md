# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
