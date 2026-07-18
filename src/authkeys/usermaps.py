"""User-mapping callables: translate an authorized user into a source-specific id.

A usermap has the signature ``(name, source_name, source) -> str``.
"""


def none(name: str, src_name: str, src) -> str:
    """Identity map: use the username unchanged for every source."""
    return name
