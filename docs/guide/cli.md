# CLI commands

Besides `resolve` (the default) and `serve`, a few small commands help with
debugging and shell integration.

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
