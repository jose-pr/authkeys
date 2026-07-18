# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
