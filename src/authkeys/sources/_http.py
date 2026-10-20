"""HTTP source: fetch keys from a URL, one ``authorized_keys`` line per row.

``url`` is a format string receiving ``{username}`` (percent-encoded). Client
options: ``timeout``, ``deadline``, ``retries``, ``verify``, ``certificate``/``key``
(mutual TLS), ``proxy`` (a URL or ``"direct"``; unset: the system's proxy
configuration) and ``token_env`` (a variable holding a bearer token). Requires
the ``http`` extra (``pip install authkeys[http]``: syshttp).
"""

import ssl
import urllib.parse
from typing import Any, Iterable, Mapping, Optional

from .. import KeySource
from ..config import typed
from ..exceptions import ConfigError
from ._client import CLIENT_OPTIONS, KeyClient


class HTTPSource(KeySource):
    """Keys from an HTTP endpoint, one ``authorized_keys`` line per row.

    ``ssl_context`` (programmatic use) replaces the TLS options.
    """

    options = frozenset({"url"}) | CLIENT_OPTIONS

    def __init__(
        self,
        options: Mapping[str, Any],
        globals: dict,
        *,
        ssl_context: "Optional[ssl.SSLContext]" = None,
    ) -> None:
        self.url = typed(options, "url", str, None, "http source")
        if not self.url:
            raise ConfigError("the http source needs a 'url'")
        self.client = KeyClient(options, "http source", ssl_context=ssl_context)

    def authorized_keys(self, username: str) -> Iterable[str]:
        # Percent-encode the username: it may come from a `serve` request and
        # must not alter the URL path or query.
        quoted = urllib.parse.quote(username, safe="")
        return self.client.lines(self.url.format(username=quoted))
