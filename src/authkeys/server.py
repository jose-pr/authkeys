"""Unattended HTTP key server (the generalized ``keygrabber``).

Serves ``authorized_keys`` over HTTP so hosts that cannot run the
``AuthorizedKeysCommand`` locally (or want a shared, cached view) can fetch keys
from a central instance. Compared with the original prototype this version is
fully config-driven: bind address, port, and API key come from a ``[serve]``
config section (or CLI overrides); the API key is compared in constant time; and
there is no host-specific source toggling baked in.

Config (``[serve]`` section)::

    [serve]
    bind = 127.0.0.1
    port = 8090
    api_key = ${env:AUTHKEYS_APIKEY}    ; empty => auth disabled (bind locally!)
    path = /keys
    request_timeout = 10                ; seconds a connection may stay idle
    max_connections = 64                ; requests served at once; more get 503
"""

import hmac
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional

from duho import logging

from . import AuthKeys

LOGGER = logging.getLogger("authkeys.server")


class KeyServer(ThreadingHTTPServer):
    """Threaded HTTP server bound to an :class:`AuthKeys` instance."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        authkeys: AuthKeys,
        *,
        bind: str = "127.0.0.1",
        port: int = 8090,
        api_key: Optional[str] = None,
        path: str = "/keys",
        max_usernames: int = 16,
        require_auth: bool = False,
        request_timeout: float = 10.0,
        max_connections: int = 64,
    ) -> None:
        # Fail closed: when the caller asserts an api_key MUST be set (e.g. the
        # CLI, when `[serve] api_key` is present in config) but it resolved
        # empty (unset ${env:...}, typo), refuse construction rather than
        # silently starting with authentication disabled.
        if require_auth and not api_key:
            raise ValueError(
                "KeyServer: require_auth=True but api_key is empty; refusing "
                "to start with authentication silently disabled."
            )
        self.authkeys = authkeys
        self.api_key = api_key or None
        self.route = "/" + path.strip("/")
        self.max_usernames = max_usernames
        self.request_timeout = request_timeout
        # One thread per connection: bound them, so idle or slow clients cannot
        # exhaust the process.
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__((bind, port), KeyHandler)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def check_auth(self, provided: List[str]) -> bool:
        if not self.api_key:
            return True  # auth disabled
        # Compare bytes: hmac.compare_digest raises TypeError on non-ASCII str,
        # so a crafted ?apikey=<non-ascii> would otherwise 500 instead of 401.
        expected = self.api_key.encode("utf-8")
        return any(hmac.compare_digest(p.encode("utf-8"), expected) for p in provided)


class KeyHandler(BaseHTTPRequestHandler):
    server: KeyServer  # type: ignore[assignment]
    server_version = "authkeys"

    def setup(self) -> None:
        # StreamRequestHandler.setup applies self.timeout to the socket.
        self.timeout = self.server.request_timeout
        super().setup()

    def log_message(self, fmt, *args):  # route logging through duho
        LOGGER.info("%s - " + fmt, self.address_string(), *args)

    def log_request(self, code="-", size="-") -> None:
        # The query string can carry the API key: log the path only.
        path = urllib.parse.urlsplit(getattr(self, "path", "")).path
        LOGGER.info(f"{self.address_string()} - {self.command} {path} {code}")

    def _send(self, data: str, status: int = 200) -> None:
        payload = data.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.rstrip("/") != self.server.route.rstrip("/"):
            self._send("Not found", HTTPStatus.NOT_FOUND)
            return

        query = urllib.parse.parse_qs(parsed.query)
        provided = list(query.get("apikey", []))
        scheme, _, token = (self.headers.get("Authorization") or "").partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            provided.append(token.strip())
        if not self.server.check_auth(provided):
            LOGGER.warning("Rejected request with missing/invalid apikey")
            self._send("Not authorized", HTTPStatus.UNAUTHORIZED)
            return

        usernames = query.get("username", [])
        if not usernames:
            self._send("Missing 'username' parameter", HTTPStatus.BAD_REQUEST)
            return
        if len(usernames) > self.server.max_usernames:
            # Bound the work one request can force (matters most in the
            # auth-disabled mode -- an unauthenticated amplification vector).
            self._send("Too many 'username' parameters", HTTPStatus.BAD_REQUEST)
            return

        keys: List[str] = []
        for username in usernames:
            # resolve() loads any per-user ~/.ssh/authkeys.conf delegation (as
            # the CLI does) and runs under the AuthKeys lock, so concurrent
            # handler threads share the cache safely.
            keys.extend(str(k) for k in self.server.authkeys.resolve(username))
        self._send("\n".join(keys) + ("\n" if keys else ""), HTTPStatus.OK)


def serve(server: KeyServer) -> None:
    """Run ``server`` until interrupted (blocking)."""
    host, port = server.server_address[:2]
    LOGGER.info(f"Serving authorized keys on http://{host}:{port}{server.route}")
    if not server.api_key:
        LOGGER.warning(
            "No api_key configured: authentication is DISABLED. "
            "Only bind to a trusted interface."
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutting down (Ctrl-C)")
    finally:
        server.server_close()
