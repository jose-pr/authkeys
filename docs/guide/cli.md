# CLI commands

Besides `resolve` (the default) and `serve`, a few small commands help with
debugging, cache management, and shell integration.

## `check`

```bash
authkeys check alice --config /etc/authkeys.conf
```

Resolves a user's keys exactly like `resolve` — same output, same exit codes
(0 / 3) — but for debugging: it's a thin wrapper around the same resolution
path (`AuthKeys.resolve`), and the per-source trace ("Using source: ... for
alice -> alice", "Using cached source: ...") that already gets logged during
resolution is visible on stderr at the default log level, letting you see
which source(s) produced (or failed to produce) a user's keys without editing
config.

## `--format`

Both `resolve` and `check` accept `--format authorized_keys|json` (default
`authorized_keys`):

```bash
authkeys resolve alice --format json --config /etc/authkeys.conf
```

`authorized_keys` (the default) is unchanged: one key per line, in the sshd
wire format — this is what `AuthorizedKeysCommand` expects and what `serve`
always returns. `json` prints a single JSON array instead, one object per key
with `type`, `key`, `comment`, and `options` fields, for scripting or tooling
that wants structured output rather than parsing the wire format itself.

## `cache`

```bash
authkeys cache show                 # list entries with ages
authkeys cache purge --expired      # drop expired entries
authkeys cache purge --user alice   # drop one user (or --source, --all)
authkeys cache warm alice bob       # pre-resolve users (e.g. from cron)
```

Inspects and manages the resolved-keys cache. `show` and `purge` need an
on-disk backend — an in-memory cache lives only inside the process that
created it, so there is nothing for a separate CLI invocation to see, and those
actions exit `3` rather than silently reporting an empty cache. `warm`
pre-resolves users into the cache and works with any backend (though with an
in-memory one it accomplishes nothing beyond that process).

See [Configuration → Cache](configuration.md#cache) for the `[cache]`
section itself: backends, `expire`, per-source TTL overrides, and
`expired_on_error`.

## `completion`

```bash
authkeys completion bash   # or zsh, fish
```

Prints a self-contained shell completion script to stdout for the given shell
(`bash` by default). Install it, for example:

```bash
authkeys completion bash > /etc/bash_completion.d/authkeys
```

The script is generated from authkeys's actual argument parser (via
[duho](https://github.com/jose-pr/duho)'s completion support), so it always
matches the installed CLI's commands and flags.
