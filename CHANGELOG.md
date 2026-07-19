# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
