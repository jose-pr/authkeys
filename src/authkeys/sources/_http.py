"""HTTP source: fetch keys from a URL, one ``authorized_keys`` line per row.

The ``address`` is a format string receiving ``{username}``. Optional mutual-TLS
client credentials are given as ``credentials = ["cert.pem", "key.pem"]``.
``verify`` is a boolean or a CA-bundle path. Requires the optional ``requests``
dependency (``pip install authkeys[http]``).
"""

import urllib.parse
from typing import Any, Iterable, Mapping

from .. import KeySource
from ..config import typed
from ..exceptions import ConfigError


class HTTPSource(KeySource):
    """Keys from an HTTP endpoint, one ``authorized_keys`` line per row."""

    options = frozenset({"address", "timeout", "credentials", "verify"})

    def __init__(self, options: Mapping[str, Any], globals: dict) -> None:
        import requests

        where = "http source"
        self.address = typed(options, "address", str, None, where)
        if not self.address:
            raise ConfigError("the http source needs an 'address'")
        self.session = requests.Session()
        self.timeout = float(typed(options, "timeout", (int, float), 10.0, where))
        self.request_options: dict = {}
        credentials = typed(options, "credentials", (list, str), None, where)
        if isinstance(credentials, str):
            credentials = credentials.split(",")
        if credentials:
            self.request_options["cert"] = tuple(str(c).strip() for c in credentials)
        verify = typed(options, "verify", (bool, str), None, where)
        if verify is not None:
            self.request_options["verify"] = verify

    def authorized_keys(self, username: str) -> Iterable[str]:
        # Percent-encode the username: it may be attacker-controlled (via
        # `authkeys serve`) and must not alter the URL path/query.
        quoted = urllib.parse.quote(username, safe="")
        resp = self.session.get(
            self.address.format(username=quoted),
            timeout=self.timeout,
            **self.request_options,
        )
        # Raise on any non-success status so a transient 5xx/403 routes through
        # the resolver's error path (and expired_on_error) instead of being
        # silently cached as "this user has no keys".
        resp.raise_for_status()
        for line in resp.content.decode().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line
