# Key sources

A source is declared as a `[source:<name>]` section. `enabled` and `cached` both
default to `true`. An optional `sanitize` callable can rewrite or drop each key.

| Alias (`backend =`)                | Reads keys from                        | Extra dep |
| ---------------------------------- | -------------------------------------- | --------- |
| `authkeys.sources.authorizedkeys`  | `~/.ssh/authorized_keys*` files        | —         |
| `authkeys.sources.http`            | an HTTP URL (`{username}` templated)   | `requests` |
| `authkeys.sources.github`          | GitHub (or similar) `.keys` endpoint   | `requests` |
| `authkeys.sources.ldap`            | X.509 certs in an LDAP directory       | `ldap3`, `cryptography` |

## File

```ini
[source:files]
backend = authkeys.sources.authorizedkeys
paths =
    authorized_keys
    authorized_keys2
```

Reads the listed files under each user's `~/.ssh/`, skipping blank and comment
lines.

A line that starts with an OpenSSH options prefix (e.g.
`command="...",no-pty ssh-rsa AAAA... bob`) is preserved verbatim: the options
are kept alongside the key rather than being misparsed as the key type, and
they round-trip byte-for-byte through `resolve`/`serve` output. An
option-bearing key is treated as distinct from the same key without options
for deduplication purposes, since the options materially change what the key
is allowed to do.

## HTTP

```ini
[source:http]
backend = authkeys.sources.http
address = https://keys.example.com/{username}
# credentials = client.crt,client.key   ; optional mutual TLS
# verify = /etc/pki/tls/certs/ca.crt     ; true/false, or a CA-bundle path
```

`{username}` is percent-encoded before it is substituted, so a username can never
alter the request path or query. `verify` accepts a bool-like value
(`true`/`false`) to toggle TLS verification, or a path to a CA bundle.

## GitHub

```ini
[source:github]
backend = authkeys.sources.github
# {username} is substituted per lookup. Defaults to GitHub; point at another
# forge with the same `.keys` convention (e.g. GitLab) by overriding `url`:
# url = https://gitlab.com/{username}.keys
```

Fetches `https://github.com/{username}.keys` by default — GitHub's plain-text
list of a user's public keys, one per line, without comments. `{username}` is
percent-encoded before it is substituted. Since the fetched keys have no
comment, the default `sanitize` still adds `uid(src=...)` as usual. Uses the
same optional `requests` dependency as the `http` source (`pip install
authkeys[http]`); no separate extra.

## LDAP

```ini
[source:ldap]
backend = authkeys.sources.ldap
server = ldaps://ldap.example.com:636
basedn = o=Example,c=US
username_attr = uid
cert_attr = userCertificate
tls_verify = system
# cert_filter = authkeys.sources.ldap.only_auth_keys
```

Each matching entry's certificate is parsed and its public key serialized to
OpenSSH format. The username is escaped before it goes into the LDAP filter, so a
crafted username cannot inject additional filter clauses. An optional
`cert_filter` callable `(username, cert) -> bool | str` can drop a certificate or
supply a custom comment.

!!! warning "Server-certificate verification"
    The LDAPS channel decides who is allowed to log in, so authkeys **verifies the
    server certificate by default**. `tls_verify` controls it:

    | `tls_verify` | Behavior |
    | --- | --- |
    | unset / `system` | Verify against the OS trust store (default) |
    | a file path | Verify against that CA bundle |
    | a directory path | Verify against that CA directory |
    | `none` | **Do not verify** — insecure, testing only (logs a warning) |

    `tls_cert`/`tls_key` are the *client* mutual-TLS credentials, not server
    verification. `timeout` (seconds) bounds a hung server.
