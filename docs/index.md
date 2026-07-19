# authkeys

**authkeys** is a pluggable OpenSSH
[`AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand)
provider. It resolves a user's authorized SSH keys from one or more configured
**sources** — local key files, an HTTP endpoint, or LDAP-stored X.509
certificates — with optional TTL caching, user/group aliasing, and a small
unattended HTTP key server for hosts that fetch keys centrally.

Built on the [duho](https://github.com/jose-pr/duho) declarative CLI framework.

## Why authkeys

- **Pluggable sources.** Point sshd at one command; resolve keys from files,
  HTTP, or LDAP certificates behind it, mixed and matched per host.
- **Resilient.** TTL caching with an opt-in *serve-stale-on-error* fallback keeps
  logins working through a transient LDAP/HTTP outage.
- **Delegation.** A per-user `~/.ssh/authkeys.conf` can authorize other users' or
  groups' keys.
- **Unattended serving.** `authkeys serve` exposes the same resolution over HTTP
  for hosts that can't run the command locally.

!!! note
    authkeys targets POSIX systems (it reads the system user/group databases via
    `pwd`/`grp`). The package imports on any platform for testing, but resolution
    requires a POSIX host.

## Install

```bash
pip install authkeys            # core (file source only)
pip install authkeys[http]      # + HTTP source (requests)
pip install authkeys[ldap]      # + LDAP cert source (ldap3, cryptography)
pip install authkeys[all]       # everything
```

## Use it

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

## Where to next

- **[Configuration](guide/configuration.md)** — config paths, cache, and per-user
  delegation.
- **[Key sources](guide/sources.md)** — the file, HTTP, and LDAP sources.
- **[HTTP key server](guide/server.md)** — running and securing `authkeys serve`.
- **[API Reference](api/reference.md)** — generated from the source docstrings.
