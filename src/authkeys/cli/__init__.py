"""Command line, built on duho.

``authkeys [-c FILE] resolve [user]`` prints a user's authorized keys (the
``AuthorizedKeysCommand`` entry point); ``resolve`` is the default command, so
``authkeys %u`` works in ``sshd_config``. ``check``, ``serve``, ``cache`` and
``completion`` are the other commands.
"""

import logging
import sys
import typing as _ty

from duho import AUTO, Cli, ConfigArgs, LoggingArgs
from duho import run as _duho_run

from .. import config as _config
from ..exceptions import ConfigError
from .cache import Cache
from .resolve import Check, Resolve
from .serve import Serve

__all__ = ["AuthKeysCLI", "Cache", "Check", "Resolve", "Serve", "main"]


def _report_error(message: str, code: int) -> None:
    # One ERROR record on logger `authkeys`, the bare message, no traceback.
    logging.getLogger("authkeys").error(message)


class AuthKeysCLI(ConfigArgs, LoggingArgs, Cli):
    """Pluggable AuthorizedKeysCommand provider for OpenSSH."""

    _parsername_ = "authkeys"
    _version_ = AUTO
    _distribution_ = "authkeys"
    _subcommands_ = [Resolve, Check, Serve, Cache]
    _default_subcommand_ = "resolve"
    _completion_command_ = True
    _config_ = str(_config.SYSTEM_CONFIG)
    _config_env_ = _config.CONFIG_ENV
    _config_loader_ = staticmethod(_config.duho_loader)
    _exit_codes_ = {3: "configuration or internal error"}
    _errors_ = {ConfigError: 3}
    _report_error_ = staticmethod(_report_error)


def main(argv: "_ty.Optional[_ty.Sequence[str]]" = None) -> int:
    """Run the CLI with ``argv`` (default ``sys.argv[1:]``) and return the status."""
    return _duho_run(
        AuthKeysCLI, list(sys.argv[1:] if argv is None else argv), exit=False
    )
