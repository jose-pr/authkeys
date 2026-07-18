"""HTTP source: fetch keys from a URL, one ``authorized_keys`` line per row.

The ``address`` is a format string receiving ``{username}``. Optional mutual-TLS
client credentials are given as ``credentials = cert.pem,key.pem``. Requires the
optional ``requests`` dependency (``pip install authkeys[http]``).
"""

from configparser import SectionProxy
from typing import Iterable

from .. import AuthkeysSource


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
            self.options["verify"] = verify

    def authorized_keys(self, username: str) -> Iterable[str]:
        resp = self.session.get(
            self.address.format(username=username),
            timeout=self.timeout,
            **self.options,
        )
        if resp.status_code == 200:
            for line in resp.content.decode().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line
