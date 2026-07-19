# HTTP key server

For hosts that can't run the command locally, `authkeys serve` exposes the same
resolution over HTTP:

```
GET /keys?username=alice&apikey=<key>
```

Bind address, port, path, and API key come from the `[serve]` config section (or
`--bind`/`--port`):

```ini
[serve]
bind = 127.0.0.1
port = 8090
path = /keys
api_key = ${env:AUTHKEYS_APIKEY}
```

## Security

- The API key is compared in **constant time**. Pull it from the environment with
  `api_key = ${env:AUTHKEYS_APIKEY}` to keep it off disk.
- **Fail closed.** If the `api_key` line is present but resolves empty (for
  example an unset environment variable), `authkeys serve` refuses to start rather
  than silently running unauthenticated. Remove the line entirely to intentionally
  run without authentication — and then bind only to a trusted interface.
- The server resolves under a lock, so concurrent requests share the cache safely
  and never issue duplicate upstream fetches for the same key.

## Delegation

`authkeys serve` honors each user's `~/.ssh/authkeys.conf` delegation, exactly as
`authkeys resolve` does — a request for `alice` returns the keys of everyone
`alice` has authorized.
