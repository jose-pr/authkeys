"""GitHub ``.keys`` source: fetch a user's public keys from ``github.com``.

GitHub (and GitLab, and similar forges) publish a user's public SSH keys at a
plain-text ``.keys`` URL, one key per line, WITHOUT comments. The ``url``
template receives ``{username}`` and defaults to the GitHub endpoint; point it
at ``https://gitlab.com/{username}.keys`` (or any other forge with the same
convention) to reuse this source without a separate class.
"""

import urllib.parse
from configparser import SectionProxy
from typing import Iterable

from .. import AuthkeysSource

_DEFAULT_URL = "https://github.com/{username}.keys"


class GithubKeys(AuthkeysSource):
    def __init__(self, conf: SectionProxy, globals) -> None:
        import requests

        self.url = conf.get("url", _DEFAULT_URL)
        self.session = requests.Session()
        self.timeout = conf.getfloat("timeout", 10.0)

    def authorized_keys(self, username: str) -> Iterable[str]:
        # Percent-encode the username: it may be attacker-controlled (via
        # `authkeys serve`) and must not alter the URL path/query.
        quoted = urllib.parse.quote(username, safe="")
        resp = self.session.get(
            self.url.format(username=quoted),
            timeout=self.timeout,
        )
        # Raise on any non-success status so a transient 5xx/403 routes through
        # the resolver's error path (and expired_on_error) instead of being
        # silently cached as "this user has no keys".
        resp.raise_for_status()
        for line in resp.content.decode().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line
