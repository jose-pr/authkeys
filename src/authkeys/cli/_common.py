"""Shared by the commands: the configuration in force, the engine, key output."""

import json
from typing import Any, List

from .. import AuthKeys, AuthorizedKey
from .. import config as _config


def settings_for(command: Any) -> _config.Settings:
    """Load the settings for ``command``: its root's ``--config``, else
    ``AUTHKEYS_CONFIG``, else ``/etc/authkeys.cfg`` (``ConfigError`` if broken)."""
    return _config.load_settings(_config.chosen_path(getattr(command, "config", None)))


def build(command: Any) -> AuthKeys:
    """An :class:`AuthKeys` engine loaded with the settings ``command`` names."""
    auth = AuthKeys()
    auth.load_config(settings_for(command))
    return auth


def print_keys(keys: "List[AuthorizedKey]", format: str) -> None:
    """Print keys as sshd's wire format, or (``json``) one array of objects with
    ``type``, ``key``, ``comment`` and ``options``."""
    if format == "json":
        print(
            json.dumps(
                [
                    {
                        "type": key.type,
                        "key": key.key,
                        "comment": key.comment,
                        "options": key.options,
                    }
                    for key in keys
                ]
            )
        )
        return
    for key in keys:
        print(key)
