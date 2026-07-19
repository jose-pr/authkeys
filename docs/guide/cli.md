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
