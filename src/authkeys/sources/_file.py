"""File source: read keys from a user's ``~/.ssh/authorized_keys`` files."""

from pathlib import Path
from typing import Any, Iterable, Mapping

from .. import KeySource, utils
from ..config import typed

_DEFAULT_PATHS = ["authorized_keys", "authorized_keys2"]


class FileSource(KeySource):
    """Keys from the target user's own ``~/.ssh`` files."""

    options = frozenset({"paths"})

    def __init__(self, options: Mapping[str, Any], globals: dict) -> None:
        paths = typed(options, "paths", (list, str), _DEFAULT_PATHS, "file source")
        self.paths = [paths] if isinstance(paths, str) else [str(p) for p in paths]

    def authorized_keys(self, username: str) -> Iterable[str]:
        import pwd

        try:
            user = pwd.getpwnam(username)
        except KeyError:
            return
        home = Path(user.pw_dir)
        ssh_home = home / ".ssh"
        for path in self.paths:
            text = utils.read_user_file(ssh_home / path, user.pw_uid, home)
            for line in (text or "").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line
