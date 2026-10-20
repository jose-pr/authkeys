"""HTTP key server: routing, auth (constant-time), params, threading."""

import threading
import time
import urllib.error
import urllib.request

import pytest

from authkeys import AuthKeys, KeySource, Settings
from authkeys.sources import register_source
from authkeys.server import KeyServer

RSA = "ssh-rsa AAAAB3Nza alice@host"


class OneKeySource(KeySource):
    def __init__(self, options, globals):
        pass

    def authorized_keys(self, username):
        if username == "alice":
            yield RSA


register_source("test-server-onekey", OneKeySource)


@pytest.fixture
def server():
    conf = Settings.from_mapping(
        {"source": {"test": {"backend": "test-server-onekey"}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(auth, "127.0.0.1:0", api_key="secret", path="/keys")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address[:2]
    yield f"http://{host}:{port}"
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=2)


# Bypass any proxy configured in the environment: GitHub's Windows runners set
# HTTP(S)_PROXY, and urllib would otherwise route these localhost requests through
# a proxy that can't reach the ephemeral test server -- which hangs instead of
# honoring the timeout. An empty ProxyHandler forces a direct connection.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(url):
    with _OPENER.open(url, timeout=5) as resp:
        return resp.status, resp.read().decode()


def test_authorized_request_returns_keys(server):
    status, body = _get(f"{server}/keys?username=alice&apikey=secret")
    assert status == 200
    assert RSA in body


def test_missing_apikey_is_401(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{server}/keys?username=alice")
    assert exc.value.code == 401


def test_wrong_apikey_is_401(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{server}/keys?username=alice&apikey=nope")
    assert exc.value.code == 401


def test_non_ascii_apikey_is_401_not_500(server):
    # hmac.compare_digest raises TypeError on non-ASCII str; must yield 401.
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{server}/keys?username=alice&apikey=p%C3%A9")  # 'pé'
    assert exc.value.code == 401


def test_too_many_usernames_is_400(server):
    qs = "&".join(["username=alice"] * 100)
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{server}/keys?{qs}&apikey=secret")
    assert exc.value.code == 400


def test_missing_username_is_400(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{server}/keys?apikey=secret")
    assert exc.value.code == 400


def test_unknown_route_is_404(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{server}/other?apikey=secret")
    assert exc.value.code == 404


def test_auth_disabled_when_no_api_key():
    conf = Settings.from_mapping(
        {"source": {"test": {"backend": "test-server-onekey"}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(auth, "127.0.0.1:0", api_key=None)
    assert srv.check_auth([]) is True


def test_require_auth_with_empty_api_key_raises():
    # Fail-closed invariant lives in KeyServer itself now (not just cli.Serve):
    # constructing with require_auth=True and a falsy api_key must refuse to
    # start rather than silently disabling authentication.
    conf = Settings.from_mapping(
        {"source": {"test": {"backend": "test-server-onekey"}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    with pytest.raises(ValueError):
        KeyServer(auth, "127.0.0.1:0", api_key="", require_auth=True)


def test_require_auth_with_set_api_key_ok():
    conf = Settings.from_mapping(
        {"source": {"test": {"backend": "test-server-onekey"}}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(auth, "127.0.0.1:0", api_key="secret", require_auth=True)
    assert srv.check_auth(["secret"]) is True


def _start(**options):
    auth = AuthKeys()
    auth.load_config(
        Settings.from_mapping({"source": {"test": {"backend": "test-server-onekey"}}})
    )
    srv = KeyServer(auth, "127.0.0.1:0", api_key="secret", **options)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread


def _stop(srv, thread):
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=2)


def test_bearer_token_authorizes(server):
    request = urllib.request.Request(
        f"{server}/keys?username=alice", headers={"Authorization": "Bearer secret"}
    )
    with _OPENER.open(request, timeout=5) as resp:
        assert resp.status == 200 and RSA in resp.read().decode()
    request = urllib.request.Request(
        f"{server}/keys?username=alice", headers={"Authorization": "Bearer wrong"}
    )
    with pytest.raises(urllib.error.HTTPError) as err:
        _OPENER.open(request, timeout=5)
    assert err.value.code == 401


def test_request_log_has_no_query_string(server, caplog):
    import logging

    caplog.set_level(logging.INFO, logger="authkeys.server")
    _get(f"{server}/keys?username=alice&apikey=secret")
    lines = [r.getMessage() for r in caplog.records if r.name == "authkeys.server"]
    assert any("GET /keys 200" in m for m in lines)
    assert not any("secret" in m for m in lines)


def test_idle_connection_is_closed_after_the_timeout():
    import socket
    import time

    srv, thread = _start(request_timeout=0.5)
    try:
        with socket.create_connection(srv.server_address[:2], timeout=5) as sock:
            started = time.monotonic()
            assert sock.recv(1024) == b""
            assert time.monotonic() - started < 4
    finally:
        _stop(srv, thread)


def test_connections_over_the_limit_get_503():
    import socket

    srv, thread = _start(max_connections=1, request_timeout=5)
    try:
        with socket.create_connection(srv.server_address[:2], timeout=5) as idle:
            idle.sendall(b"GET /keys")  # an incomplete request holds the only slot
            with socket.create_connection(srv.server_address[:2], timeout=5) as second:
                assert second.recv(64).startswith(b"HTTP/1.1 503")
    finally:
        _stop(srv, thread)


# --- listening through netimps, and TLS -----------------------------------------


def _auth():
    auth = AuthKeys()
    auth.load_config(
        Settings.from_mapping({"source": {"test": {"backend": "test-server-onekey"}}})
    )
    return auth


def _ipv6_loopback():
    import socket

    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ipv6_loopback(), reason="no IPv6 loopback on this host")
def test_one_spec_serves_ipv4_and_ipv6():
    from authkeys.server import bind_servers, serve

    servers = bind_servers(_auth(), "127.0.0.1:0,[::1]:0", api_key="secret")
    assert [s.socket.family.name for s in servers] == ["AF_INET", "AF_INET6"]
    assert servers[1].url.startswith("http://[::1]:")
    runner = threading.Thread(target=serve, args=(servers,), daemon=True)
    runner.start()
    try:
        for server in servers:
            status, body = _get(server.url + "?username=alice&apikey=secret")
            assert status == 200 and RSA in body
    finally:
        servers[0].shutdown()
        runner.join(timeout=5)
    assert not runner.is_alive()


def test_key_server_takes_one_address():
    with pytest.raises(ValueError, match="bind_servers"):
        KeyServer(_auth(), "127.0.0.1:0,127.0.0.2:0")


def test_bind_servers_closes_what_it_opened_on_failure():
    import socket

    from authkeys.server import bind_servers

    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    try:
        port = taken.getsockname()[1]
        with pytest.raises(OSError):
            bind_servers(_auth(), f"127.0.0.1:0,127.0.0.1:{port}")
    finally:
        taken.close()


@pytest.fixture
def tls_files(tmp_path):
    pytest.importorskip("cryptography")
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem, keyfile = tmp_path / "tls.pem", tmp_path / "tls.key"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(pem), str(keyfile)


def test_https_with_a_server_context(tls_files):
    import ssl

    import sslcontext

    pem, key = tls_files
    context = sslcontext.create_context("server", certificate=pem, key=key)
    srv = KeyServer(_auth(), "127.0.0.1:0", api_key="secret", ssl_context=context)
    thread = threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        assert srv.url.startswith("https://127.0.0.1:")
        client = ssl.create_default_context(cafile=pem)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=client)
        )
        with opener.open(srv.url + "?username=alice&apikey=secret", timeout=5) as resp:
            assert resp.status == 200 and RSA in resp.read().decode()
        with pytest.raises(Exception):
            _get(
                srv.url.replace("https://", "http://") + "?username=alice&apikey=secret"
            )
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def test_cli_serves_https_from_certificate_and_key(tls_files, tmp_path, monkeypatch):
    from authkeys.cli import main

    seen = {}
    import authkeys.server

    monkeypatch.setattr(
        authkeys.server,
        "serve",
        lambda servers: seen.update(urls=[s.url for s in servers])
        or [s.server_close() for s in servers],
    )
    pem, key = tls_files
    conf = tmp_path / "a.cfg"
    conf.write_text(f"[serve]\ncertificate = {pem!r}\nkey = {key!r}\n")
    assert main(["--config", str(conf), "serve", "--listen", "127.0.0.1:0"]) == 0
    assert seen["urls"][0].startswith("https://127.0.0.1:")


def test_clear_text_on_a_public_address_warns(caplog):
    import logging

    from authkeys.server import serve

    srv = KeyServer(_auth(), "0.0.0.0:0", api_key="secret")
    runner = threading.Thread(target=serve, args=(srv,), daemon=True)
    with caplog.at_level(logging.WARNING, logger="authkeys.server"):
        runner.start()
        time.sleep(0.2)
        srv.shutdown()
        runner.join(timeout=5)
    assert any("without TLS" in r.getMessage() for r in caplog.records)
