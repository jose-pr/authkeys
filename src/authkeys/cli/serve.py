"""``authkeys serve``: the HTTP key server."""

import typing as _ty

from duho import Arg, Cmd, CommandError, LoggingArgs, Meta

from .. import AuthKeys
from ._common import settings_for


class Serve(LoggingArgs, Cmd):
    """Run the unattended HTTP key server.

    Every option may also be set in the [serve] table of the configuration or
    through AUTHKEYS_SERVE_<OPTION>: the command line wins, then the variable,
    then the file. The API key comes only from [serve] api_key (use
    ${env.NAME}), never from the command line, where other users can read it.
    """

    _parsername_ = "serve"
    _logger_name_ = "authkeys.server"

    bind: "Arg[str, Meta(env='AUTHKEYS_SERVE_BIND')]" = "127.0.0.1"
    "Address to bind"
    ("--bind", "-b")

    port: "Arg[int, Meta(env='AUTHKEYS_SERVE_PORT')]" = 8090
    "Port to listen on"
    ("--port", "-p")

    path: "Arg[str, Meta(env='AUTHKEYS_SERVE_PATH')]" = "/keys"
    "URL path that serves keys"
    ("--path",)

    max_usernames: "Arg[int, Meta(env='AUTHKEYS_SERVE_MAX_USERNAMES')]" = 16
    "Most username parameters one request may carry"
    ("--max-usernames",)

    request_timeout: "Arg[float, Meta(env='AUTHKEYS_SERVE_REQUEST_TIMEOUT')]" = 10.0
    "Seconds a connection may stay idle"
    ("--request-timeout",)

    max_connections: "Arg[int, Meta(env='AUTHKEYS_SERVE_MAX_CONNECTIONS')]" = 64
    "Most requests served at once (more get 503)"
    ("--max-connections",)

    def __call__(self) -> "int | None":
        from ..server import KeyServer, serve

        settings = settings_for(self)
        auth = AuthKeys()
        auth.load_config(settings)
        # Fail closed: an api_key line that resolved empty (an unset ${env.NAME},
        # a typo) must not start the server with authentication disabled.
        has_key_line = "api_key" in settings.serve
        api_key = settings.serve.get("api_key") or None
        if has_key_line and not api_key:
            raise CommandError(
                "authkeys serve: 'api_key' is configured in [serve] but resolved to "
                "an empty value (unset ${env.NAME}?). Refusing to start with "
                "authentication silently disabled. Set the key, or remove the "
                "'api_key' line to run without authentication.",
                1,
            )
        server = KeyServer(
            auth,
            bind=self.bind,
            port=self.port,
            api_key=api_key,
            path=self.path,
            max_usernames=self.max_usernames,
            require_auth=has_key_line,
            request_timeout=self.request_timeout,
            max_connections=self.max_connections,
        )
        serve(server)
        return 0
