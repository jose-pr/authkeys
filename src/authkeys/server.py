"""Unattended HTTP key server (the generalized ``keygrabber``).

Serves ``authorized_keys`` over HTTP(S) so hosts that cannot run the
``AuthorizedKeysCommand`` locally (or want a shared, cached view) can fetch keys
from a central instance. Where it listens is a netimps listen specification
(``"127.0.0.1:8090"``, ``"[::1]:8090,192.0.2.10"``); the API key is compared in
constant time.

Config (``[serve]`` table)::

    [serve]
    listen = "127.0.0.1:8090"
    api_key = "${env.AUTHKEYS_APIKEY}"  # unset => auth disabled (listen locally!)
    path = "/keys"
    request_timeout = 10                # seconds a connection may stay idle
    max_connections = 64                # requests served at once; more get 503
    certificate = "/etc/authkeys/tls.pem"   # with key: serve HTTPS
    key = "/etc/authkeys/tls.key"
"""

import hmac
import socket
import ssl
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, List, Optional, Sequence, Union

from duho import logging

from . import AuthKeys

__all__ = ["DEFAULT_PORT", "KeyHandler", "KeyServer", "bind_servers", "serve"]

LOGGER = logging.getLogger("authkeys.server")

DEFAULT_PORT = 8090


def _addresses(listen: Any):
    import netimps

    return netimps.parse_listen(listen, default_ports=DEFAULT_PORT)


def _listening_socket(address, queue_size: int) -> socket.socket:
    """One TCP socket for one parsed listen entry, through netimps."""
    import netimps

    device = None
    if address.interfaces:
        if len(address.interfaces) > 1:
            raise ValueError(
                "serve: listen on one network interface per entry, or give an address"
            )
        device = address.interfaces[0]
    return netimps.bind(
        str(address.address),
        address.port,
        kind=socket.SOCK_STREAM,
        device=device,
        listen=queue_size,
    )


class KeyServer(ThreadingHTTPServer):
    """Threaded HTTP server bound to an :class:`AuthKeys` instance."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        authkeys: AuthKeys,
        listen: Any = "127.0.0.1:8090",
        *,
        api_key: Optional[str] = None,
        path: str = "/keys",
        max_usernames: int = 16,
        require_auth: bool = False,
        request_timeout: float = 10.0,
        max_connections: int = 64,
        ssl_context: "Optional[ssl.SSLContext]" = None,
    ) -> None:
        """Bind one listening socket for ``listen`` (one netimps listen entry:
        ``"host:port"``, ``"[v6]:port"``, ``":port"``, a ``ListenAddress``; the
        port defaults to 8090). ``ssl_context`` (server side) serves HTTPS.

        Raises ``ValueError`` for a specification that names no address or more
        than one (use :func:`bind_servers`), and ``OSError`` when the socket
        cannot be bound (``netimps.AddressInUseError`` for a taken port).
        """
        # Fail closed: when the caller asserts an api_key MUST be set (e.g. the
        # CLI, when `[serve] api_key` is present in config) but it resolved
        # empty (unset ${env.NAME}, typo), refuse construction rather than
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
        self.ssl_context = ssl_context
        # One thread per connection: bound them, so idle or slow clients cannot
        # exhaust the process.
        self._slots = threading.BoundedSemaphore(max_connections)
        addresses = _addresses(listen)
        if len(addresses) != 1:
            raise ValueError(
                f"KeyServer listens on one address, not {len(addresses)}; "
                f"use bind_servers()"
            )
        sock = _listening_socket(addresses[0], self.request_queue_size)
        self.address_family = sock.family
        super().__init__(sock.getsockname()[:2], KeyHandler, bind_and_activate=False)
        self.socket.close()
        self.socket = sock
        self.server_address = sock.getsockname()

    @property
    def url(self) -> str:
        """The URL this server answers on, IPv6 hosts in brackets."""
        import netimps

        host, port = self.server_address[:2]
        scheme = "https" if self.ssl_context else "http"
        return f"{scheme}://{netimps.join_host(host, port)}{self.route}"

    def finish_request(self, request, client_address) -> None:
        # The TLS handshake runs here, in the connection's own thread and under
        # its timeout, so a slow client cannot stall the accept loop.
        if self.ssl_context is not None:
            request.settimeout(self.request_timeout)
            request = self.ssl_context.wrap_socket(request, server_side=True)
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address) -> None:
        # A failed handshake or a dropped client is routine; no traceback.
        import sys

        error = sys.exc_info()[1]
        LOGGER.info(
            f"Connection from {client_address[0]} failed: {type(error).__name__}: {error}"
        )

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
            # resolve() loads any per-user ~/.ssh/authkeys.cfg delegation (as
            # the CLI does) and runs under the AuthKeys lock, so concurrent
            # handler threads share the cache safely.
            keys.extend(str(k) for k in self.server.authkeys.resolve(username))
        self._send("\n".join(keys) + ("\n" if keys else ""), HTTPStatus.OK)


def bind_servers(
    authkeys: AuthKeys, listen: Any = "127.0.0.1:8090", **options
) -> "List[KeyServer]":
    """One :class:`KeyServer` per entry of the netimps listen specification
    ``listen`` (``"127.0.0.1:8090,[::1]:8090"``); ``options`` go to each.

    Every socket is bound before this returns; if one fails, those already bound
    are closed and the error is raised (``ValueError`` for a bad specification,
    ``OSError`` for a socket that cannot be bound).
    """
    servers: "List[KeyServer]" = []
    try:
        for address in _addresses(listen):
            servers.append(KeyServer(authkeys, address, **options))
    except BaseException:
        for server in servers:
            server.server_close()
        raise
    return servers


def _is_loopback(server: KeyServer) -> bool:
    import ipaddress

    host = server.server_address[0]
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def serve(servers: "Union[KeyServer, Sequence[KeyServer]]") -> None:
    """Run ``servers`` until interrupted (blocking), then close them."""
    if isinstance(servers, KeyServer):
        servers = [servers]
    for server in servers:
        LOGGER.info(f"Serving authorized keys on {server.url}")
        if not server.api_key:
            LOGGER.warning(
                "No api_key configured: authentication is DISABLED. "
                "Only listen on a trusted interface."
            )
        if server.ssl_context is None and not _is_loopback(server):
            LOGGER.warning(
                f"Serving {server.url} without TLS: keys and the API key cross "
                f"the network in clear text. Set [serve] certificate and key."
            )
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in servers[1:]
    ]
    for thread in threads:
        thread.start()
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutting down (Ctrl-C)")
    finally:
        for server in servers[1:]:
            server.shutdown()
        for server in servers:
            server.server_close()
