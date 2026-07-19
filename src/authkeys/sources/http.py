"""HTTP source: fetch keys from a URL, one ``authorized_keys`` line per row.

The ``address`` is a format string receiving ``{username}``. Optional mutual-TLS
client credentials are given as ``credentials = cert.pem,key.pem``. Requires the
optional ``requests`` dependency (``pip install authkeys[http]``).
"""

import urllib.parse
from configparser import SectionProxy
from typing import Iterable

from .. import AuthkeysSource

_FALSY = ("0", "false", "no", "off", "disabled")
_TRUTHY = ("1", "true", "yes", "on", "enabled")


def _parse_verify(value: str) -> "bool | str":
    """Interpret the ``verify`` option.

    A bool-like string toggles TLS verification; anything else is treated as a
    CA-bundle path. Without this, ``verify = false`` would be passed to requests
    as the *string* ``"false"``, which requests reads as a CA path (and fails),
    silently NOT disabling verification.
    """
    lowered = value.strip().lower()
    if lowered in _FALSY:
        return False
    if lowered in _TRUTHY:
        return True
    return value


class HttpAuthorizedKeys(AuthkeysSource):
    def __init__(self, conf: SectionProxy, globals) -> None:
        import requests

        self.address = conf.get("address")
        if not self.address:
            raise ValueError("http source requires an 'address'")
        self.session = requests.Session()
        self.timeout = conf.getfloat("timeout", 10.0)
        self.options: dict = {}
        credentials = conf.get("credentials", None)
        if credentials:
            self.options["cert"] = tuple(c.strip() for c in credentials.split(","))
        verify = conf.get("verify", None)
        if verify is not None:
            self.options["verify"] = _parse_verify(verify)

    def authorized_keys(self, username: str) -> Iterable[str]:
        # Percent-encode the username: it may be attacker-controlled (via
        # `authkeys serve`) and must not alter the URL path/query.
        quoted = urllib.parse.quote(username, safe="")
        resp = self.session.get(
            self.address.format(username=quoted),
            timeout=self.timeout,
            **self.options,
        )
        # Raise on any non-success status so a transient 5xx/403 routes through
        # the resolver's error path (and expired_on_error) instead of being
        # silently cached as "this user has no keys".
        resp.raise_for_status()
        for line in resp.content.decode().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line
