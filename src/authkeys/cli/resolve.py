"""``authkeys resolve`` (the AuthorizedKeysCommand) and ``authkeys check``."""

import typing as _ty

from duho import Arg, Choice, Cmd, LoggingArgs

from .. import utils
from ._common import build, print_keys


class Resolve(LoggingArgs, Cmd):
    """Print the authorized SSH keys for a user (AuthorizedKeysCommand)."""

    _parsername_ = "resolve"
    _parseraliases_ = ["keys"]
    _logger_name_ = "authkeys"
    _verb_ = "resolve"

    username: _ty.Optional[str] = None
    "User to resolve (defaults to the current user)"
    ("username",)

    format: "Arg[str, Choice('authorized_keys', 'json')]" = "authorized_keys"
    "Output format: authorized_keys (default, sshd wire format) or json"
    ("--format",)

    def __call__(self) -> "int | None":
        # An AuthorizedKeysCommand must never dump a traceback into auth.log: any
        # error is one line on stderr and status 3; sshd reads a non-zero status
        # or empty output as "no keys". Status 0 includes "no keys found".
        try:
            auth = build(self)
            username = self.username or utils.get_user().pw_name
            print_keys(list(auth.resolve(username)), self.format)
            return 0
        except SystemExit:
            raise
        except BaseException as e:  # noqa: BLE001 - deliberate catch-all boundary
            self._logger_.error(f"authkeys {self._verb_} failed: {e}")
            return 3


class Check(Resolve):
    """Resolve a user's keys with per-source tracing on stderr (debugging)."""

    _parsername_ = "check"
    _parseraliases_: "_ty.List[str]" = []
    _verb_ = "check"

    def __call__(self) -> "int | None":
        # The engine logs which source produced which key at INFO; raise this
        # command's logger so that tracing reaches stderr.
        self._logger_.setLevel("DEBUG")
        return super().__call__()
