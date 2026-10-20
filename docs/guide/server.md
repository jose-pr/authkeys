# HTTP key server

For hosts that can't run the command locally, `authkeys serve` exposes the same
resolution over HTTP or HTTPS:

```
GET /keys?username=alice&apikey=<key>
GET /keys?username=alice          (with the header  Authorization: Bearer <key>)
```

The options come from the `[serve]` table, from `AUTHKEYS_SERVE_<OPTION>`
variables, or from the command line (`--listen`, `--certificate`, `--key`,
`--path`, `--max-usernames`, `--request-timeout`, `--max-connections`); the
command line wins, then the variable, then the file. The API key comes only from
the file:

```toml
[serve]
listen = "127.0.0.1:8090"
path = "/keys"
api_key = "${env.AUTHKEYS_APIKEY}"
certificate = "/etc/authkeys/tls.pem"   # with key: serve HTTPS
key = "/etc/authkeys/tls.key"
request_timeout = 10    # seconds a connection may stay idle
max_connections = 64    # requests served at once; more get 503
```

```bash
authkeys -c /etc/authkeys.cfg serve --listen "[::]:8443,0.0.0.0:8443"
```

## Where it listens

`listen` is a [netimps](https://github.com/jose-pr/netimps) listen
specification: `host:port`, `[v6]:port`, `:port` (every IPv4 address), an
interface name (`eth1:8090`), or several of them separated by commas — one socket
each. A missing port is 8090. A specification that names no address, a port out
of range or a port already in use stops `serve` with one line on stderr (status
3).

## TLS

With `certificate` and `key` (PEM files; the certificate file may hold the chain)
`serve` speaks HTTPS. Without TLS the keys and the API key cross the network in
clear text, and whoever sits in the middle decides who logs in on the hosts that
fetch keys: `serve` logs a warning when it listens on a non-loopback address
without TLS. Either configure a certificate or keep `serve` on loopback behind a
TLS proxy.

## Security

- The API key is compared in **constant time**. Pull it from the environment with
  `api_key = "${env.AUTHKEYS_APIKEY}"` to keep it off disk.
- **Fail closed.** If the `api_key` line is present but resolves empty (for
  example an unset environment variable), `authkeys serve` refuses to start rather
  than silently running unauthenticated. Remove the line entirely to intentionally
  run without authentication — and then listen only on a trusted interface.
- The server resolves concurrently; the cache read/write is locked but the
  upstream fetch is not, so one slow/hung source can't stall other requests.
- `max_usernames` (default 16) caps how many `?username=` params a single request
  may carry, bounding the work an unauthenticated request can force.
- Requests are logged as the method, the path without its query string and the
  status, so the `apikey` parameter never reaches the log. Prefer the
  `Authorization: Bearer` header anyway: proxies log URLs.
- A connection idle for `request_timeout` seconds (default 10) is closed, and at
  most `max_connections` (default 64) requests run at once; the rest get `503`.

## Delegation

`authkeys serve` honors each user's `~/.ssh/authkeys.cfg` delegation, exactly as
`authkeys resolve` does — a request for `alice` returns the keys of everyone
`alice` has authorized.

## Running under systemd

[`examples/authkeys-serve.service`](https://github.com/jose-pr/authkeys/blob/main/examples/authkeys-serve.service)
is a template unit for running `authkeys serve` as a systemd service. It sets
`DynamicUser=` for an unprivileged, unique identity and a broad set of other
hardening directives (`NoNewPrivileges=`, `ProtectSystem=strict`,
`PrivateTmp=`, a minimal `RestrictAddressFamilies=`, dropped capabilities,
...), and shows both ways to supply `AUTHKEYS_APIKEY` without putting it in
`authkeys.cfg` (`Environment=`/`EnvironmentFile=`).

One directive is intentionally *not* at its strictest: `ProtectHome=read-only`
rather than fully hiding home directories. `authkeys serve` needs to read
each delegating user's `~/.ssh` (for file-backed sources and
`~/.ssh/authkeys.cfg` delegation), so home directories must stay readable —
this is a deliberate trade-off, documented in the unit file itself, not an
oversight.

Copy the unit to `/etc/systemd/system/authkeys-serve.service`, adjust the
config path and identity for your install, then:

```bash
systemctl daemon-reload
systemctl enable --now authkeys-serve
```
