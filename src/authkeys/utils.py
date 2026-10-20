"""Small helpers: user/group lookups, dynamic imports, bool parsing.

The ``pwd``/``grp`` modules are POSIX-only and imported lazily so this package
stays importable (and unit-testable) on non-POSIX platforms; only the functions
that actually resolve system users/groups require them.
"""

import os
import stat
from importlib import import_module
from pathlib import Path
from typing import Any, List, Optional

from duho import logging

__all__ = [
    "MAX_USER_FILE_BYTES",
    "get_groupmembers",
    "get_user",
    "import_module_object",
    "read_user_file",
]

LOGGER = logging.getLogger("authkeys")

# A user file larger than this is refused: authorized_keys lines are short, and a
# symlink to /dev/zero must not exhaust memory.
MAX_USER_FILE_BYTES = 1024 * 1024

# Owner and mode checks need POSIX permissions; elsewhere every file passes.
_STRICT_MODES = os.name == "posix"


def _insecure(st: os.stat_result, owner_uid: int) -> "Optional[str]":
    if st.st_uid not in (owner_uid, 0):
        return "owned by another user"
    if st.st_mode & 0o022:
        return "writable by group or others"
    return None


def read_user_file(path: Path, owner_uid: int, home: Path) -> "Optional[str]":
    """Read a file in a user's home the way sshd's StrictModes would accept it.

    The file must be a regular file (not a symlink) of at most
    ``MAX_USER_FILE_BYTES``, and it and every directory up to ``home`` must be
    owned by the user or root and not writable by group or others. Returns the
    text, or ``None`` when the file is absent or refused (refusals log one WARNING
    naming the path and the reason, never the content).
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    reason = None
    if stat.S_ISLNK(st.st_mode):
        reason = "is a symbolic link"
    elif not stat.S_ISREG(st.st_mode):
        reason = "is not a regular file"
    elif st.st_size > MAX_USER_FILE_BYTES:
        reason = f"is larger than {MAX_USER_FILE_BYTES} bytes"
    elif _STRICT_MODES:
        reason = _insecure(st, owner_uid)
        directory = Path(path).parent
        while reason is None:
            reason = _insecure(os.stat(directory), owner_uid)
            if reason:
                reason = f"its directory {directory} is {reason}"
            if directory == home or directory.parent == directory:
                break
            directory = directory.parent
    if reason:
        LOGGER.warning(f"Ignoring {path}: {reason}")
        return None
    with open(path, "rb") as fh:
        data = fh.read(MAX_USER_FILE_BYTES + 1)
    if len(data) > MAX_USER_FILE_BYTES:
        LOGGER.warning(f"Ignoring {path}: is larger than {MAX_USER_FILE_BYTES} bytes")
        return None
    return data.decode("utf-8", "replace")


def get_user(username: "str | None" = None):
    """Return a ``pwd.struct_passwd`` for ``username`` (or the current uid)."""
    import pwd

    if username is None:
        return pwd.getpwuid(os.getuid())
    return pwd.getpwnam(username)


def import_module_object(fqdn: str) -> Any:
    """Import ``pkg.mod.attr`` and return ``attr``."""
    domain, name = fqdn.rsplit(".", maxsplit=1)
    module = import_module(domain)
    return getattr(module, name)


def get_groupmembers(name: str) -> "List[str]":
    import grp

    return list(grp.getgrnam(name).gr_mem)
