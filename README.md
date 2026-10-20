# authkeys

[![PyPI version](https://img.shields.io/pypi/v/authkeys.svg)](https://pypi.org/project/authkeys/)
[![Python versions](https://img.shields.io/pypi/pyversions/authkeys.svg)](https://pypi.org/project/authkeys/)
[![Documentation](https://img.shields.io/badge/docs-jose--pr.github.io%2Fauthkeys-blue.svg)](https://jose-pr.github.io/authkeys/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/jose-pr/authkeys/blob/main/LICENSE)

A pluggable OpenSSH [`AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand)
provider. It resolves a user's authorized SSH keys from one or more configured
**sources** — local key files, an HTTP endpoint, a GitHub-style `.keys`
endpoint, or LDAP-stored X.509 certificates — with optional TTL caching,
user/group aliasing, and a small unattended HTTP key server for hosts that
fetch keys centrally.

Built on the [duho](https://github.com/jose-pr/duho) declarative CLI framework.

## Install

```bash
pip install authkeys            # core (file source only)
pip install authkeys[http]      # + HTTP source (requests)
pip install authkeys[ldap]      # + LDAP cert source (ldap3, cryptography)
pip install authkeys[all]       # everything
```

> authkeys targets POSIX systems (it reads the system user/group databases via
> `pwd`/`grp`). The package imports on any platform for testing, but resolution
> requires a POSIX host.

## Usage

```bash
authkeys resolve alice          # print alice's authorized keys
authkeys alice                  # 'resolve' is the default command
authkeys -c /etc/authkeys.cfg serve --bind 127.0.0.1 --port 8090
```

Wire it into `sshd_config`:

```
AuthorizedKeysCommand /usr/bin/authkeys resolve %u
AuthorizedKeysCommandUser authkeys
```

Run the command as a dedicated account that does nothing else (here `authkeys`),
as sshd_config(5) recommends: with the on-disk cache, whatever runs as that
account can write cache entries, and so keys.

Alongside those, `authkeys check` resolves a user with per-source tracing on
stderr (which source produced which key), `authkeys cache show|purge|warm`
inspects and manages the on-disk cache, and `authkeys completion bash|zsh|fish|powershell`
prints a shell completion script. `resolve` and `check` also take
`--format authorized_keys|json`, where `json` emits one object per key with
`type`, `key`, `comment`, and `options` for scripting. See the
[CLI guide](https://jose-pr.github.io/authkeys/guide/cli/) for details.

`resolve` and `check` exit `0` on success — including when no keys were found,
which sshd reads as "no keys" — `2` on a usage error and `3` on a configuration
or internal error, never a traceback.

## Configuration

authkeys reads one TOML file: `/etc/authkeys.cfg`, or the file named with
`--config` (`-c`, before the command) or `AUTHKEYS_CONFIG`. `${env.NAME}` is
replaced from the environment, and a key authkeys does not know is logged as a
warning instead of being silently ignored. See
[`examples/authkeys.cfg`](https://github.com/jose-pr/authkeys/blob/main/examples/authkeys.cfg)
for a fully commented example.

```toml
[cache]
backend = "memory"
expire = 3600
expired_on_error = true

[source.files]
backend = "file"
paths = ["authorized_keys", "authorized_keys2"]

[source.ldap]
backend = "ldap"
server = "ldaps://ldap.example.com:636"
basedn = "o=Example,c=US"
```

### Sources

| `backend` | Reads keys from                              | Extra |
| --------- | -------------------------------------------- | ----- |
| `file`    | `~/.ssh/authorized_keys*` files              | —     |
| `http`    | an HTTP URL (`{username}` templated)         | `authkeys[http]` |
| `github`  | a GitHub (or similar) `.keys` endpoint       | `authkeys[http]` |
| `ldap`    | X.509 certs in an LDAP directory             | `authkeys[ldap]` |

Each `[source.<name>]` table supports `enabled` and `cached` (both default
`true`) and an optional `sanitize` callable to rewrite or drop keys. Other
distributions can add sources through the `authkeys.sources` entry-point group.

### Caching

- `memory` — per-process, in-memory (default).
- `file` — on disk under `path`, shared across invocations.

With `expired_on_error = true`, a source failure falls back to the last-known
(expired) cached keys instead of returning nothing — useful when the SSH login
must not be blocked by a transient LDAP/HTTP outage.

### User / group aliasing

A user's `~/.ssh/authkeys.cfg` may grant other principals' keys to that user's
account:

```toml
[authorized]
users = ["alice", "bob"]
groups = ["admins"]
```

## HTTP key server (`authkeys serve`)

For hosts that can't run the command locally, `authkeys serve` exposes the same
resolution over HTTP:

```
GET /keys?username=alice&apikey=<key>
```

Bind address, port, path and the limits come from the `[serve]` table, from
`AUTHKEYS_SERVE_<OPTION>` or from the command line; the API key only from
`[serve] api_key`. It is compared in constant time and may also be sent as
`Authorization: Bearer <key>`; pull it from the environment with
`api_key = "${env.AUTHKEYS_APIKEY}"` to keep it off disk. If
no API key is configured, authentication is disabled — only bind to a trusted
interface in that case.

## License

MIT — see [LICENSE](https://github.com/jose-pr/authkeys/blob/main/LICENSE).
