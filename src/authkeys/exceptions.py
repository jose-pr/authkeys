"""Exceptions raised by authkeys.

Every error authkeys raises on purpose derives from :class:`AuthKeysError`.
"""

__all__ = ["AuthKeysError", "ConfigError", "SourceError"]


class AuthKeysError(Exception):
    """Base class of authkeys' own errors."""


class ConfigError(AuthKeysError, ValueError):
    """The configuration cannot be used: a malformed file, an unknown backend
    name, or a setting a backend refuses. The message names the file or the
    setting, never a value."""


class SourceError(AuthKeysError, RuntimeError):
    """A key source could not answer (a refused or ambiguous directory search).
    The resolver treats it like any other source failure (``expired_on_error``)."""
