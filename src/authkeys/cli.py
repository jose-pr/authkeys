"""Command-line interface, built on the duho declarative CLI framework.

``authkeys resolve [user]`` prints a user's authorized keys (the
``AuthorizedKeysCommand`` entry point). ``authkeys serve`` runs the HTTP key
server. ``resolve`` is also the default command when none is given.
"""

import typing as _ty

from duho import AUTO, Arg, Args, Choice, Cmd, LoggingArgs, main, print_completion

from . import AuthKeys, config, utils
from .config import AuthkeysConfig


def _default_config_paths() -> str:
    return ":".join(str(p) for p in config.SYSTEM_CONF_PATHS)


def _build(cfg: str) -> AuthKeys:
    auth = AuthKeys()
    auth.load_config(AuthkeysConfig.from_config(cfg))
    return auth


class Resolve(LoggingArgs, Cmd):
    """Print the authorized SSH keys for a user (AuthorizedKeysCommand)."""

    _parsername_ = "resolve"
    _parseraliases_ = ["keys"]
    _logger_name_ = "authkeys"

    username: _ty.Optional[str] = None
    "User to resolve (defaults to the current user)"
    ("username",)

    config_paths: str = ""
    "Colon-separated config paths (defaults to system paths)"
    ("--config", "-c")

    def __call__(self) -> "int | None":
        # An AuthorizedKeysCommand must never dump a traceback into auth.log: on
        # any config/internal error, log one line to stderr and exit non-zero
        # (sshd reads a non-zero exit / empty stdout as "no keys" = deny).
        # Exit codes: 0 = success (including "no keys"); 3 = config/internal error.
        try:
            cfg = self.config_paths or _default_config_paths()
            auth = _build(cfg)
            username = self.username or utils.get_user().pw_name
            for key in auth.resolve(username):
                print(key)
            return 0
        except SystemExit:
            raise
        except BaseException as e:  # noqa: BLE001 - deliberate catch-all boundary
            self._logger_.error(f"authkeys resolve failed: {e}")
            return 3


class Check(LoggingArgs, Cmd):
    """Resolve a user's keys with per-source tracing on stderr (debugging)."""

    _parsername_ = "check"
    _logger_name_ = "authkeys"

    username: _ty.Optional[str] = None
    "User to resolve (defaults to the current user)"
    ("username",)

    config_paths: str = ""
    "Colon-separated config paths (defaults to system paths)"
    ("--config", "-c")

    def __call__(self) -> "int | None":
        # Thin wrapper around AuthKeys.resolve: same exit codes/no-traceback
        # contract as `resolve`, but bumps this command's own logger so the
        # existing per-source "Using source/Using cached source ... for X -> Y"
        # log lines (already emitted by AuthKeys) surface to stderr.
        self._logger_.setLevel("DEBUG")
        try:
            cfg = self.config_paths or _default_config_paths()
            auth = _build(cfg)
            username = self.username or utils.get_user().pw_name
            for key in auth.resolve(username):
                print(key)
            return 0
        except SystemExit:
            raise
        except BaseException as e:  # noqa: BLE001 - deliberate catch-all boundary
            self._logger_.error(f"authkeys check failed: {e}")
            return 3


class Serve(LoggingArgs, Cmd):
    """Run the unattended HTTP key server."""

    _parsername_ = "serve"
    _logger_name_ = "authkeys.server"

    config_paths: str = ""
    "Colon-separated config paths (defaults to system paths)"
    ("--config", "-c")

    bind: _ty.Optional[str] = None
    "Address to bind (overrides [serve] bind)"
    ("--bind", "-b")

    port: _ty.Optional[int] = None
    "Port to listen on (overrides [serve] port)"
    ("--port", "-p")

    def __call__(self) -> "int | None":
        from .server import KeyServer, serve

        cfg = self.config_paths or _default_config_paths()
        parsed = AuthkeysConfig.from_config(cfg)
        auth = AuthKeys()
        auth.load_config(parsed)

        serve_conf = parsed["serve"] if parsed.has_section("serve") else None

        def opt(name, default):
            return serve_conf.get(name, default) if serve_conf else default

        # Fail closed: if an api_key is configured but resolves empty (e.g. an
        # unset ${env:...} or a typo), refuse to start rather than silently
        # disabling authentication. A truly absent api_key still means
        # "auth disabled" (KeyServer warns loudly).
        api_key = opt("api_key", None)
        if serve_conf is not None and "api_key" in serve_conf and not api_key:
            raise SystemExit(
                "authkeys serve: 'api_key' is configured in [serve] but resolved "
                "to an empty value (unset ${env:...}?). Refusing to start with "
                "authentication silently disabled. Set the key, or remove the "
                "'api_key' line to run without authentication."
            )

        require_auth = serve_conf is not None and "api_key" in serve_conf
        server = KeyServer(
            auth,
            bind=self.bind or opt("bind", "127.0.0.1"),
            port=self.port or int(opt("port", 8090)),
            api_key=api_key,
            path=opt("path", "/keys"),
            max_usernames=int(opt("max_usernames", 16)),
            require_auth=require_auth,
        )
        serve(server)
        return 0


class Cache(LoggingArgs, Cmd):
    """Inspect, purge, or warm the resolved-keys cache."""

    _parsername_ = "cache"
    _logger_name_ = "authkeys"

    action: str = "show"
    "One of: show, purge, warm"
    ("action",)

    config_paths: str = ""
    "Colon-separated config paths (defaults to system paths)"
    ("--config", "-c")

    user: _ty.Optional[str] = None
    "Limit purge to this user (uid), or warm this user"
    ("--user", "-u")

    source: _ty.Optional[str] = None
    "Limit purge to this source"
    ("--source", "-s")

    expired: bool = False
    "purge: only remove expired entries"
    ("--expired",)

    all: bool = False
    "purge: remove every entry"
    ("--all",)

    users: _ty.List[str] = []
    "warm: users to pre-resolve into the cache"
    ("users",)

    def __call__(self) -> "int | None":
        cfg = self.config_paths or _default_config_paths()
        auth = _build(cfg)
        if auth.cache is None:
            self._logger_.error("No cache configured")
            return 3
        backend = auth.cache.backend
        try:
            if self.action == "show":
                for uid, src in sorted(backend.keys()):
                    entry = backend[(uid, src)]
                    age = int(__import__("time").time() - entry[1]) if entry else "?"
                    print(f"{src}\t{uid}\tage={age}s")
                return 0
            if self.action == "purge":
                removed = 0
                if self.expired:
                    removed = backend.sweep(max_age=auth.cache.ttl)
                elif self.all:
                    for k in list(backend.keys()):
                        del backend[k]
                        removed += 1
                else:
                    for uid, src in list(backend.keys()):
                        if (self.user and uid != self.user) or (
                            self.source and src != self.source
                        ):
                            continue
                        del backend[(uid, src)]
                        removed += 1
                self._logger_.info(f"Purged {removed} cache entr(y/ies)")
                return 0
            if self.action == "warm":
                targets = self.users or ([self.user] if self.user else [])
                for username in targets:
                    keys = auth.resolve(username)
                    self._logger_.info(f"Warmed {username}: {len(keys)} key(s)")
                return 0
        except NotImplementedError:
            self._logger_.error(
                "The configured cache backend does not support this action "
                "(in-memory caches are per-process)."
            )
            return 3
        self._logger_.error(f"Unknown cache action: {self.action}")
        return 2


class Completion(Cmd):
    """Print a shell completion script for the authkeys CLI."""

    _parsername_ = "completion"

    shell: "Arg[str, Choice('bash', 'zsh', 'fish')]" = "bash"
    "Shell to generate a completion script for"
    ("shell",)

    def __call__(self) -> "int | None":
        import sys

        # Delegate to duho's own completion machinery rather than hand-rolling
        # a shell script: it builds Authkeys's real parser tree (including
        # this subcommand tree) and walks it into a self-contained script.
        print_completion(Authkeys, self.shell, file=sys.stdout)
        return 0


class Authkeys(Args):
    """Pluggable AuthorizedKeysCommand provider for OpenSSH."""

    _parsername_ = "authkeys"
    _version_ = AUTO
    _distribution_ = "authkeys"
    _subcommands_ = [Resolve, Serve, Cache, Check, Completion]


_COMMANDS = {"resolve", "keys", "serve", "cache", "check", "completion"}


def _with_default_command(argv: "_ty.Sequence[str]") -> "list[str]":
    """Insert the default ``resolve`` command when none is given.

    Lets ``authkeys <user>`` behave like ``authkeys resolve <user>`` so the
    console script works as a drop-in OpenSSH ``AuthorizedKeysCommand``.

    A known subcommand anywhere in argv (before ``--``) is left untouched;
    otherwise ``resolve`` is prepended at the *front* so that subcommand flags
    (``-v``, ``-c``, ...) reach the ``resolve`` subparser rather than the root
    parser, which does not define them.
    """
    argv = list(argv)
    for token in argv:
        if token == "--":
            break  # everything after is passthrough, not a command
        if token in ("-h", "--help", "--version"):
            return argv
        if token in _COMMANDS:
            return argv
    return ["resolve"] + argv


def run(argv: "_ty.Sequence[str] | None" = None) -> "int | None":
    import sys

    if argv is None:
        argv = sys.argv[1:]
    return main(Authkeys, _with_default_command(argv))
