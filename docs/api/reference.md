# API Reference

Generated from docstrings, organized by module:

- **[authkeys](authkeys.md)** — the core `AuthKeys` resolver, `AuthorizedKey`,
  `KeySource`, `Source`, and the usermap/groupmembers/utils helpers.
- **[Config](config.md)** — loading and validating `/etc/authkeys.cfg` and the
  per-user delegation file.
- **[Sources](sources.md)** — the built-in file, HTTP, GitHub and LDAP sources
  and the source registry.
- **[Cache](cache.md)** — the TTL cache, its memory and file backends, and the
  cache registry.
- **[Server](server.md)** — the `authkeys serve` HTTP key server.
- **[CLI](cli.md)** — the `authkeys` command.
- **[Exceptions](exceptions.md)** — `AuthKeysError`, `ConfigError`, `SourceError`.
