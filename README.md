# authkeys

A pluggable OpenSSH [`AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand)
provider. It resolves a user's authorized SSH keys from one or more configured
**sources** — local key files, an HTTP endpoint, or LDAP-stored X.509
certificates — with optional TTL caching, user/group aliasing, and a small
unattended HTTP key server for hosts that fetch keys centrally.

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
authkeys serve --bind 0.0.0.0 --port 8090
```

Wire it into `sshd_config`:

```
AuthorizedKeysCommand /usr/bin/authkeys resolve %u
AuthorizedKeysCommandUser nobody
```

## Configuration

authkeys reads (in order) `/etc/authkeys.conf`,
`/etc/authkeys/authkeys.conf`, `/etc/ssh/authkeys.conf`, or a colon-separated
list passed with `--config`. A per-user `~/.ssh/authkeys.conf` may authorize
additional users/groups. See [`examples/authkeys.conf`](examples/authkeys.conf)
for a fully commented example.

```ini
[cache]
backend = authkeys.cache.AuthKeysCacheMemBackend
expire = 3600
expired_on_error = 1

[source:files]
backend = authkeys.sources.authorizedkeys
paths =
    authorized_keys
    authorized_keys2

[source:ldap]
enabled = 1
backend = authkeys.sources.ldap
server = ldaps://ldap.example.com:636
basedn = o=Example,c=US
```

### Sources

| Alias (`backend =`)                | Reads keys from                              | Extra dep |
| ---------------------------------- | -------------------------------------------- | --------- |
| `authkeys.sources.authorizedkeys`  | `~/.ssh/authorized_keys*` files              | —         |
| `authkeys.sources.http`            | an HTTP URL (`{username}` templated)         | `requests` |
| `authkeys.sources.ldap`            | X.509 certs in an LDAP directory             | `ldap3`, `cryptography` |

Each `[source:<name>]` section supports `enabled` and `cached` (both default
`true`) and an optional `sanitize` callable to rewrite/drop keys.

### Caching

- `AuthKeysCacheMemBackend` — per-process, in-memory (default).
- `AuthKeysCacheFileBackend` — on-disk under `path`, shared across invocations.

With `expired_on_error = 1`, a source failure falls back to the last-known
(expired) cached keys instead of returning nothing — useful when the SSH login
must not be blocked by a transient LDAP/HTTP outage.

### User / group aliasing

A per-user `~/.ssh/authkeys.conf` may grant other principals' keys:

```ini
[authorized]
users =
    alice
    bob
groups =
    admins
```

## HTTP key server (`authkeys serve`)

For hosts that can't run the command locally, `authkeys serve` exposes the same
resolution over HTTP:

```
GET /keys?username=alice&apikey=<key>
```

Bind address, port, path, and API key come from the `[serve]` config section
(or `--bind`/`--port`). The API key is compared in constant time; pull it from
the environment with `api_key = ${env:AUTHKEYS_APIKEY}` to keep it off disk. If
no API key is configured, authentication is disabled — only bind to a trusted
interface in that case.

## License

MIT — see [LICENSE](LICENSE).
