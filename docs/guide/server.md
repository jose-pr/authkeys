# HTTP key server

For hosts that can't run the command locally, `authkeys serve` exposes the same
resolution over HTTP:

```
GET /keys?username=alice&apikey=<key>
GET /keys?username=alice          (with the header  Authorization: Bearer <key>)
```

Bind address, port, path, and API key come from the `[serve]` config section (or
`--bind`/`--port`):

```ini
[serve]
bind = 127.0.0.1
port = 8090
path = /keys
api_key = ${env:AUTHKEYS_APIKEY}
request_timeout = 10    # seconds a connection may stay idle
max_connections = 64    # requests served at once; more get 503
```

## Security

- The API key is compared in **constant time**. Pull it from the environment with
  `api_key = ${env:AUTHKEYS_APIKEY}` to keep it off disk.
- **Fail closed.** If the `api_key` line is present but resolves empty (for
  example an unset environment variable), `authkeys serve` refuses to start rather
  than silently running unauthenticated. Remove the line entirely to intentionally
  run without authentication — and then bind only to a trusted interface.
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

`authkeys serve` honors each user's `~/.ssh/authkeys.conf` delegation, exactly as
`authkeys resolve` does — a request for `alice` returns the keys of everyone
`alice` has authorized.

## Running under systemd

[`examples/authkeys-serve.service`](https://github.com/jose-pr/authkeys/blob/main/examples/authkeys-serve.service)
is a template unit for running `authkeys serve` as a systemd service. It sets
`DynamicUser=` for an unprivileged, unique identity and a broad set of other
hardening directives (`NoNewPrivileges=`, `ProtectSystem=strict`,
`PrivateTmp=`, a minimal `RestrictAddressFamilies=`, dropped capabilities,
...), and shows both ways to supply `AUTHKEYS_APIKEY` without putting it in
`authkeys.conf` (`Environment=`/`EnvironmentFile=`).

One directive is intentionally *not* at its strictest: `ProtectHome=read-only`
rather than fully hiding home directories. `authkeys serve` needs to read
each delegating user's `~/.ssh` (for file-backed sources and
`~/.ssh/authkeys.conf` delegation), so home directories must stay readable —
this is a deliberate trade-off, documented in the unit file itself, not an
oversight.

Copy the unit to `/etc/systemd/system/authkeys-serve.service`, adjust the
config path and identity for your install, then:

```bash
systemctl daemon-reload
systemctl enable --now authkeys-serve
```
