"""Configuration loading for authkeys.

``AuthkeysConfig`` is a thin :class:`configparser.ConfigParser` subclass with a
``getlist`` converter (newline-separated values) and a flexible ``from_config``
loader that accepts paths, colon-separated path lists, raw text, bytes, or dicts.
"""

import configparser
import os
from pathlib import Path
from typing import Iterable, List, Union

SYSTEM_CONF_PATHS = [
    Path("/etc/authkeys.conf"),
    Path("/etc/authkeys/authkeys.conf"),
    Path("/etc/ssh/authkeys.conf"),
]

USER_CONF_PATH = Path(".ssh/authkeys.conf")

ConfigSource = Union[str, bytes, Path, dict]


def _interpolate_env(text: str) -> str:
    """Expand ``${env:NAME}`` references from the process environment.

    Missing variables expand to an empty string. This keeps secrets (API keys,
    passwords) out of the config file on disk.
    """
    import re

    return re.sub(
        r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda m: os.environ.get(m.group(1), ""),
        text,
    )


def _split_path_list(value: str) -> "List[str]":
    """Split a colon-separated config-path list, preserving Windows drive letters.

    ``--config`` accepts ``a.conf:b.conf`` (POSIX ``PATH`` style), but a Windows
    absolute path such as ``C:\\etc\\authkeys.conf`` also contains a colon. A naive
    ``split(":")`` turns it into ``["C", "\\etc\\authkeys.conf"]`` so the file is
    never found -- and the caller silently gets an empty config. Re-join any
    single-letter fragment that is a drive prefix.
    """
    parts = value.split(":")
    if len(parts) == 1:
        return parts
    merged: "List[str]" = []
    i = 0
    while i < len(parts):
        part = parts[i]
        # A single alphabetic char followed by a path separator is a drive letter.
        if (
            len(part) == 1
            and part.isalpha()
            and i + 1 < len(parts)
            and parts[i + 1][:1] in ("\\", "/")
        ):
            merged.append(f"{part}:{parts[i + 1]}")
            i += 2
            continue
        merged.append(part)
        i += 1
    return [p for p in merged if p]


class AuthkeysConfig(configparser.ConfigParser):
    CONF_PATHS = [Path("./authkeys.conf")]

    def getlist(self, section, option, **kwargs) -> "List[str]":
        value = self.get(section, option, **kwargs)
        if not isinstance(value, str):
            # A non-string fallback (e.g. a default list) was returned because
            # the option is absent; return a copy so a caller mutating the result
            # can't corrupt the shared default object.
            return list(value) if value is not None else value
        return list(filter(None, (x.strip() for x in value.splitlines())))

    @classmethod
    def from_config(cls, config: "ConfigSource | Iterable[ConfigSource] | None" = None):
        conf = cls()
        conf.read_dict({"cache": {}, "globals": {}})

        if config is None:
            configs: Iterable = cls.CONF_PATHS
        elif isinstance(config, str):
            configs = _split_path_list(config)
        elif isinstance(config, (bytes, Path, dict)):
            configs = [config]
        else:
            configs = config

        for item in configs:
            if isinstance(item, str):
                item = Path(item)
            if isinstance(item, Path):
                if item.exists():
                    conf.read_string(_interpolate_env(item.read_text()))
                    break
            elif isinstance(item, bytes):
                conf.read_string(_interpolate_env(item.decode()))
            elif isinstance(item, dict):
                conf.read_dict(item)
        return conf
