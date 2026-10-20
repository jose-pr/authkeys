"""Entry-point discovery shared by the source and cache registries."""

from typing import Dict

from duho import logging

LOGGER = logging.getLogger("authkeys")


def _entry_points(group: str):
    from importlib.metadata import entry_points

    found = entry_points()
    if hasattr(found, "select"):
        return list(found.select(group=group))
    return list(found.get(group, []))  # Python 3.9: a dict of groups


def load_entry_points(group: str, registry: Dict[str, type], base: type) -> None:
    """Add every entry point of ``group`` to ``registry``.

    A name already registered (a built-in) is not replaced, and an entry point that
    fails to load or is not a ``base`` subclass is skipped with a WARNING, so one
    broken plugin never disables the others.
    """
    for ep in _entry_points(group):
        if ep.name in registry:
            LOGGER.warning(
                f"Ignoring {group} entry point {ep.name!r}: the name is taken"
            )
            continue
        try:
            cls = ep.load()
        except Exception as e:
            LOGGER.warning(
                f"Ignoring {group} entry point {ep.name!r}: {type(e).__name__}: {e}"
            )
            continue
        if not (isinstance(cls, type) and issubclass(cls, base)):
            LOGGER.warning(
                f"Ignoring {group} entry point {ep.name!r}: not a {base.__name__}"
            )
            continue
        registry[ep.name] = cls
