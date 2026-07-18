"""Command-line interface, built on the duho declarative CLI framework.

``authkeys resolve [user]`` prints a user's authorized keys (the
``AuthorizedKeysCommand`` entry point). ``authkeys serve`` runs the HTTP key
server. ``resolve`` is also the default command when none is given.
"""

import typing as _ty

from duho import AUTO, Args, Cmd, LoggingArgs, main

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
        cfg = self.config_paths or _default_config_paths()
        auth = _build(cfg)

        username = self.username or utils.get_user().pw_name
        for key in auth.resolve(username):
            print(key)
        return 0


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

        server = KeyServer(
            auth,
            bind=self.bind or opt("bind", "127.0.0.1"),
            port=self.port or int(opt("port", 8090)),
            api_key=api_key,
            path=opt("path", "/keys"),
        )
        serve(server)
        return 0


class Authkeys(Args):
    """Pluggable AuthorizedKeysCommand provider for OpenSSH."""

    _parsername_ = "authkeys"
    _version_ = AUTO
    _distribution_ = "authkeys"
    _subcommands_ = [Resolve, Serve]


_COMMANDS = {"resolve", "keys", "serve"}


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
