# CLI commands

```text
authkeys [-c FILE] [-v|-q] [resolve] [user]     # the AuthorizedKeysCommand
authkeys [-c FILE] check [user]
authkeys [-c FILE] serve [options]
authkeys [-c FILE] cache {show,purge,warm} [options]
authkeys completion {bash,zsh,fish,powershell}
```

`--config`/`-c` and the logging options belong to `authkeys` itself, so they go
**before** the command. `resolve` is the default command: `authkeys alice` and
`authkeys -c /etc/authkeys.cfg alice` resolve `alice`. An option after the user
(`authkeys alice -c FILE`) or no argument at all is a usage error; write
`authkeys resolve` to resolve the current user.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Success — **including "no keys"**. An empty stdout is a valid answer; sshd reads it as "this user has no authorized keys" and denies the login. |
| `1`  | `serve` refused to start (an `api_key` that resolved empty). |
| `2`  | Usage error: an unknown option or command, a `--config` file that does not exist, a malformed `serve` option. |
| `3`  | Configuration or internal error (a file that does not parse, an unknown `backend`, no cache configured for `cache`). One line is logged to stderr; stdout stays empty and no traceback is printed, so nothing lands in `auth.log`. |
| `130` | Interrupted. |

Because "resolved nothing" is a success, a missing `/etc/authkeys.cfg` would
otherwise be indistinguishable from a user with no keys: authkeys logs a warning
naming the path — the exit code stays `0` and stdout stays empty, since sshd's
contract does not allow failing the login over it.

## `check`

```bash
authkeys -c /etc/authkeys.cfg check alice
```

Resolves a user's keys exactly like `resolve` — same output, same exit codes —
but for debugging: the per-source trace ("Using source: ... for alice -> alice",
"Using cached source: ...") is shown on stderr, so you can see which source(s)
produced (or failed to produce) a user's keys without editing the configuration.

## `--format`

Both `resolve` and `check` accept `--format authorized_keys|json` (default
`authorized_keys`):

```bash
authkeys resolve alice --format json
```

`authorized_keys` is the sshd wire format, one key per line — what
`AuthorizedKeysCommand` expects and what `serve` always returns. `json` prints
one JSON array instead, one object per key with `type`, `key`, `comment` and
`options`, for scripts that want structured output.

## `cache`

```bash
authkeys cache show                       # list entries with ages
authkeys cache purge --expired            # drop expired entries
authkeys cache purge --user alice         # drop one user (or --source, --all)
authkeys cache purge --all --dry-run      # list what would go, remove nothing
authkeys cache warm alice bob             # pre-resolve users (e.g. from cron)
```

`show` and `purge` need an on-disk backend — an in-memory cache lives only inside
the process that created it, so those actions exit `3` rather than reporting an
empty cache. `warm` pre-resolves users into the cache and works with any backend
(with an in-memory one it accomplishes nothing beyond that process). See
[Configuration → Cache](configuration.md#cache).

## `completion`

```bash
authkeys completion bash > /etc/bash_completion.d/authkeys   # or zsh, fish, powershell
```

Prints a self-contained completion script for the named shell, generated from
the installed command line by [duho](https://github.com/jose-pr/duho), so it
always matches it.

## Environment variables

| Variable | Sets |
| --- | --- |
| `AUTHKEYS_CONFIG` | the configuration file (empty: none) |
| `AUTHKEYS_SERVE_<OPTION>` | a `serve` option, e.g. `AUTHKEYS_SERVE_PORT` |
| `AUTHKEYS_MCP` | `stdio` serves the commands as MCP tools |
| any `${env.NAME}` in the configuration | that value, e.g. the API key |
