"""GitHub ``.keys`` source: fetch a user's public keys from ``github.com``.

GitHub (and GitLab, and similar forges) publish a user's public SSH keys at a
plain-text ``.keys`` URL, one key per line, WITHOUT comments. The ``url``
template receives ``{username}`` and defaults to the GitHub endpoint; point it
at ``https://gitlab.com/{username}.keys`` (or any other forge with the same
convention) to reuse this source without a separate class. The client options
are those of the http source.
"""

import ssl
import urllib.parse
from typing import Any, Iterable, Mapping, Optional

from .. import KeySource
from ..config import typed
from ._client import CLIENT_OPTIONS, KeyClient

_DEFAULT_URL = "https://github.com/{username}.keys"


class GitHubSource(KeySource):
    """Keys from a forge's plain-text ``.keys`` endpoint."""

    options = frozenset({"url"}) | CLIENT_OPTIONS

    def __init__(
        self,
        options: Mapping[str, Any],
        globals: dict,
        *,
        ssl_context: "Optional[ssl.SSLContext]" = None,
    ) -> None:
        self.url = typed(options, "url", str, _DEFAULT_URL, "github source")
        self.client = KeyClient(options, "github source", ssl_context=ssl_context)

    def authorized_keys(self, username: str) -> Iterable[str]:
        # Percent-encode the username: it may come from a `serve` request and
        # must not alter the URL path or query.
        quoted = urllib.parse.quote(username, safe="")
        return self.client.lines(self.url.format(username=quoted))
