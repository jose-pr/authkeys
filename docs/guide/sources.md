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
auth = "anonymous"          # or "gssapi" (default), "simple", "external"
tls_verify = "/etc/pki/tls/certs/ca.pem"
# cert_filter = "authkeys.sources.only_auth_keys"   # the default; "none" disables it
# issuer_ca = "/etc/pki/tls/certs/user-ca.pem"      # keep only certs this CA issued
```

The one entry whose `username_attr` equals the username is read, and each
certificate in its `cert_attr` becomes an OpenSSH key. The username is escaped
before it goes into the search filter, so a crafted username cannot inject
filter clauses. A refused bind or search is an error (so `expired_on_error`
applies), so is a search matching more than one entry, and referrals are ignored.

### Clients

Two LDAP libraries can do the work, chosen by `client`:

- `auto` (default) uses **python-ldap** when it is installed — many distributions
  and appliances ship it, so nothing needs installing — and **ldap3** otherwise;
- `python-ldap` or `ldap3` to choose.

`pip install authkeys[ldap]` installs ldap3 (2.10.2rc4 or later) and
cryptography. Kerberos through ldap3 also needs `authkeys[kerberos]` (gssapi on
POSIX, which builds against the system's krb5; winkerberos on Windows);
python-ldap uses the system's Cyrus SASL GSSAPI module.

### Authentication

| `auth` | How | Needs |
| --- | --- | --- |
| `gssapi` (default) | Kerberos with the host's machine credentials | a joined host's keytab (`keytab`, default `/etc/krb5.keytab`) |
| `simple` | `bind_dn` with the password in the variable `password_env` | TLS |
| `external` | SASL EXTERNAL: the client certificate is the identity | `tls_cert`, `tls_key` |
| `anonymous` | no bind | a directory that allows anonymous reads |

With `gssapi` the session is sealed by Kerberos (security strength 56 or more),
so `ldap://` on port 389 is accepted; any other `auth` over `ldap://` needs
`starttls = true`. `principal` chooses another keytab entry (ldap3 on POSIX only;
python-ldap uses the keytab's first entry, the computer account). On Windows the
ldap3 client uses the credentials of the process: run as SYSTEM for the computer
account.

The host keytab is readable by root only. When authkeys runs as another account
(an `AuthorizedKeysCommandUser`), give that account the machine credentials
through [gssproxy](https://github.com/gssapi/gssproxy) rather than loosening the
keytab: authkeys then leaves `KRB5_CLIENT_KTNAME` alone and Kerberos asks
gssproxy.

### Active Directory

```toml
[source.ad]
backend = "ldap"
server = "ldap://dc1.example.com"     # sealed Kerberos on 389
basedn = "DC=example,DC=com"
username_attr = "sAMAccountName"
# auth = "gssapi"                     # the default: the computer account
```

AD requires signed binds on port 389, which a sealed Kerberos session satisfies;
it works without a domain-controller certificate. LDAPS (`ldaps://`, or
`external` with a client certificate) needs the DC to have a certificate. AD's
`userCertificate` also holds encryption and recovery certificates; the default
filter keeps only the ones made for client authentication.

### TLS and certificates

| `tls_verify` | Behavior |
| --- | --- |
| unset / `system` | verify against the platform's trust store (default) |
| a file path | verify against that CA bundle |
| a directory path | verify against that CA directory |
| `none` | **do not verify** — insecure, testing only (logs a warning) |

`tls_cert`/`tls_key` are the *client* certificate (for `external`, or a server
that asks for one). With ldap3 the connection uses a Python `SSLContext` — one
authkeys builds with [sslcontext](https://github.com/jose-pr/sslcontext), or
yours when you build `LDAPSource(..., ssl_context=...)` in code — with host-name
checking on; python-ldap configures libldap's OpenSSL instead and cannot take an
`SSLContext`. `timeout` (seconds) bounds a hung server.

`cert_filter` is a callable `(username, cert) -> bool | str` that drops a
certificate (`False`) or supplies its comment (a string). The default,
`authkeys.sources.only_auth_keys`, keeps a certificate only when it is within
its validity period, is not self-signed, its KeyUsage (if present) allows digital
signature, and its ExtendedKeyUsage (if present) includes clientAuth or
anyExtendedKeyUsage. `cert_filter = "none"` keeps every certificate.
`issuer_ca` (a PEM file of one or more CA certificates) additionally keeps only
the certificates one of them issued.
