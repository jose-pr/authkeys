"""The HTTP client the http and github sources share, on syshttp and sslcontext."""

import os
import ssl
import urllib.parse
from typing import Any, Iterable, Mapping, Optional

from ..config import typed
from ..exceptions import ConfigError, SourceError

# The keys every HTTP-based source reads besides its own URL.
CLIENT_OPTIONS = frozenset(
    {
        "timeout",
        "deadline",
        "retries",
        "verify",
        "certificate",
        "key",
        "proxy",
        "token_env",
    }
)


def _where(url: str) -> str:
    # scheme://host/path: the query may carry a token and is never logged.
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}{parts.path}"


class KeyClient:
    """Fetch ``authorized_keys`` lines over HTTP(S) for one source.

    Built from the source's options: ``timeout`` (seconds per wait, default 10),
    ``deadline`` (seconds for the whole request, default 15), ``retries``
    (default 0), ``verify`` (a boolean, or a CA bundle path), ``certificate`` and
    ``key`` (mutual TLS), ``proxy`` (a proxy URL, or ``"direct"``; unset: the
    system's proxy configuration), ``token_env`` (the variable holding a bearer
    token). ``ssl_context`` replaces ``verify``/``certificate``/``key``.
    """

    def __init__(
        self,
        options: Mapping[str, Any],
        where: str,
        *,
        ssl_context: "Optional[ssl.SSLContext]" = None,
    ) -> None:
        from syshttp.client import HTTPClient

        self.where = where
        timeout = float(typed(options, "timeout", (int, float), 10.0, where))
        self.deadline = float(typed(options, "deadline", (int, float), 15.0, where))
        retries = typed(options, "retries", int, 0, where)
        self.token_env = typed(options, "token_env", str, None, where)
        certificate = typed(options, "certificate", str, None, where)
        key = typed(options, "key", str, None, where)
        verify = typed(options, "verify", (bool, str), True, where)
        if key and not certificate:
            raise ConfigError(f"{where}: 'key' needs a 'certificate'")

        client_options: dict = {}
        if ssl_context is None and certificate:
            import sslcontext

            ssl_context = sslcontext.create_context(
                verify=verify, certificate=certificate, key=key
            )
        if ssl_context is None and verify is True:
            from syshttp.tls import new_os_context

            # The OS verifier, but never a certificate picked from the OS store:
            # a key source must not present an identity nobody configured.
            ssl_context = new_os_context(client_certificates=False)
        if ssl_context is not None:
            client_options["ssl_context"] = ssl_context
        else:
            client_options["verify"] = verify

        proxy = typed(options, "proxy", str, None, where)
        if proxy is not None:
            from syshttp.proxy import proxy_map

            client_options["proxymap"] = proxy_map(
                proxy="" if proxy.strip().lower() in ("", "direct") else proxy
            )

        # Credentials must not follow a redirect to another host.
        self.allow_redirects = not (certificate or self.token_env)
        self.client = HTTPClient(timeout=timeout, retries=retries, **client_options)

    def lines(self, url: str) -> Iterable[str]:
        """GET ``url`` and return its non-blank, non-comment lines.

        Raises :class:`SourceError` for a status of 400 or more, and for a
        redirect when redirects are off; other failures raise as syshttp does.
        """
        auth = None
        if self.token_env:
            token = os.environ.get(self.token_env, "")
            if token:
                auth = f"Bearer {token}"
        resp = self.client.request(
            "GET",
            url,
            deadline=self.deadline,
            allow_redirects=self.allow_redirects,
            auth=auth,
        )
        if resp.status >= 300:
            # Anything else than a 2xx goes through the resolver's error path
            # (and expired_on_error) instead of being cached as "no keys".
            raise SourceError(f"{self.where}: HTTP {resp.status} from {_where(url)}")
        body = resp.content.decode("utf-8")
        return [
            line.strip()
            for line in body.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def close(self) -> None:
        self.client.close()
