"""Group-membership resolvers: ``(group_name, globals) -> Iterable[str]``."""

from typing import List

from . import utils


def system_groupmembers(name: str, globals: dict) -> "List[str]":
    """Resolve members from the local system group database (``/etc/group``)."""
    return utils.get_groupmembers(name)
