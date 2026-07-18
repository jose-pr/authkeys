"""File source: read keys from a user's ``~/.ssh/authorized_keys`` files."""

from configparser import SectionProxy
from pathlib import Path
from typing import Iterable

from .. import AuthkeysSource


class AuthorizedKeysFiles(AuthkeysSource):
    def __init__(self, conf: SectionProxy, globals) -> None:
        self.paths = conf.getlist("paths", ["authorized_keys", "authorized_keys2"])

    def authorized_keys(self, username: str) -> Iterable[str]:
        import pwd

        try:
            user = pwd.getpwnam(username)
        except KeyError:
            return
        ssh_home = Path(user.pw_dir) / ".ssh"
        for path in self.paths:
            keyfile = ssh_home / path
            if keyfile.exists():
                for line in keyfile.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        yield line
