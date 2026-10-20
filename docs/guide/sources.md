# Key sources

A source is declared as a `[source.<name>]` table whose `backend` names its
kind. `enabled` and `cached` both default to `true`. An optional `sanitize`
callable (a dotted path) can rewrite or drop each key.

| `backend` | Reads keys from                        | Extra |
| --------- | -------------------------------------- | ----- |
| `file`    | `~/.ssh/authorized_keys*` files        | —     |
| `http`    | an HTTP URL (`{username}` templated)   | `authkeys[http]` |
| `github`  | GitHub (or similar) `.keys` endpoint   | `authkeys[http]` |
| `ldap`    | X.509 certs in an LDAP directory       | `authkeys[ldap]` |

A plugin distribution can add more names; see
[Configuration → Plugins](configuration.md#plugins).

## File

```toml
[source.files]
backend = "file"
paths = ["authorized_keys", "authorized_keys2"]
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

```toml
[source.http]
backend = "http"
url = "https://keys.example.com/{username}"
# certificate = "/etc/pki/tls/certs/client.crt"   # optional mutual TLS
# key = "/etc/pki/tls/private/client.key"
# verify = "/etc/pki/tls/certs/ca.crt"           # true/false, or a CA-bundle path
# proxy = "direct"                               # or a proxy URL; unset: the system's
# token_env = "KEYSERVER_TOKEN"                  # sent as Authorization: Bearer
# timeout = 10    deadline = 15    retries = 0
```

`{username}` is percent-encoded before it is substituted, so a username can never
alter the request path or query. Requests go through
[syshttp](https://github.com/jose-pr/syshttp):

- **TLS**: by default the operating system's trust store verifies the server
  (and no client certificate is offered); `verify` is `false` to turn
  verification off or the path of a CA bundle, and `certificate`/`key` add a
  client certificate.
- **Proxies**: unset `proxy` follows the system — the proxy variables when set,
  else the OS configuration (WinHTTP, macOS, libproxy, PAC and WPAD).
  `proxy = "direct"` connects directly; a URL uses that proxy.
- **Bounds**: `timeout` limits each wait (default 10 s), `deadline` the whole
  request (default 15 s); `retries` defaults to 0, since a login waits on it. A
  reply larger than 8 MiB is an error.
- **Credentials**: `token_env` names a variable whose value is sent as
  `Authorization: Bearer <value>`, so a token need not sit in the URL. With a
  token or a client certificate, a redirect is an error instead of being followed.

A status other than 2xx is a source error: `expired_on_error` applies, and the
log names the scheme, host and path, never the query string.

## GitHub

```toml
[source.github]
backend = "github"
# {username} is substituted per lookup. Defaults to GitHub; point at another
# forge with the same `.keys` convention (e.g. GitLab) by overriding `url`:
# url = "https://gitlab.com/{username}.keys"
```

!!! warning "Map local names to forge accounts"
    With the default identity usermap, local account `X` trusts whoever owns the
    GitHub account `X`. For `root`, `admin`, `git`, `ubuntu` and other common
    names that is a stranger. Set `[globals] usermap` to a callable that maps
    each local user to their own forge account (and returns a name that matches
    no forge account for everyone else).

Fetches `https://github.com/{username}.keys` by default — GitHub's plain-text
list of a user's public keys, one per line, without comments. `{username}` is
percent-encoded before it is substituted. Since the fetched keys have no
comment, the default `sanitize` still adds `uid(src=...)` as usual. It takes the
same client options as the `http` source and the same extra (`pip install
authkeys[http]`).

## LDAP

```toml
[source.ldap]
backend = "ldap"
server = "ldaps://ldap.example.com:636"
basedn = "o=Example,c=US"
username_attr = "uid"
cert_attr = "userCertificate"
tls_verify = "system"
# cert_filter = "authkeys.sources.only_auth_keys"   # the default; "none" disables it
```

Each matching entry's certificate is parsed and its public key serialized to
OpenSSH format. The username is escaped before it goes into the LDAP filter, so a
crafted username cannot inject additional filter clauses.

`server` must be an `ldaps://` URL or a bare host name; `ldap://` is refused,
because it would send the search in clear text. A search the server refuses (no
bind, missing rights) is an error, so `expired_on_error` applies to it, and a
search that matches more than one entry is an error too; referrals in the answer
are ignored.

`cert_filter` is a callable `(username, cert) -> bool | str` that drops a
certificate (`False`) or supplies its comment (a string). The default,
`authkeys.sources.only_auth_keys`, keeps a certificate only when it is within
its validity period, is not self-signed, its KeyUsage (if present) allows digital
signature, and its ExtendedKeyUsage (if present) includes clientAuth or
anyExtendedKeyUsage: directories keep encryption, e-mail and recovery
certificates in the same attribute. `cert_filter = none` keeps every certificate.

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
