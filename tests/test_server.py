"""HTTP key server: routing, auth (constant-time), params, threading."""

import threading
import urllib.error
import urllib.request

import pytest

from authkeys import AuthKeys, AuthkeysConfig, AuthkeysSource
from authkeys.server import KeyServer

RSA = "ssh-rsa AAAAB3Nza alice@host"


class OneKeySource(AuthkeysSource):
    def __init__(self, conf, globals):
        pass

    def authorized_keys(self, username):
        if username == "alice":
            yield RSA


@pytest.fixture
def server():
    conf = AuthkeysConfig.from_config(
        {
            "cache": {"backend": "authkeys.cache.AuthKeysCacheMemBackend"},
            "globals": {},
            "source:test": {"backend": f"{__name__}.OneKeySource"},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(auth, bind="127.0.0.1", port=0, api_key="secret", path="/keys")
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
    conf = AuthkeysConfig.from_config(
        {
            "cache": {},
            "globals": {},
            "source:test": {"backend": f"{__name__}.OneKeySource"},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(auth, bind="127.0.0.1", port=0, api_key=None)
    assert srv.check_auth([]) is True


def test_require_auth_with_empty_api_key_raises():
    # Fail-closed invariant lives in KeyServer itself now (not just cli.Serve):
    # constructing with require_auth=True and a falsy api_key must refuse to
    # start rather than silently disabling authentication.
    conf = AuthkeysConfig.from_config(
        {
            "cache": {},
            "globals": {},
            "source:test": {"backend": f"{__name__}.OneKeySource"},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    with pytest.raises(ValueError):
        KeyServer(auth, bind="127.0.0.1", port=0, api_key="", require_auth=True)


def test_require_auth_with_set_api_key_ok():
    conf = AuthkeysConfig.from_config(
        {
            "cache": {},
            "globals": {},
            "source:test": {"backend": f"{__name__}.OneKeySource"},
        }
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(auth, bind="127.0.0.1", port=0, api_key="secret", require_auth=True)
    assert srv.check_auth(["secret"]) is True


def _start(**options):
    auth = AuthKeys()
    auth.load_config(
        AuthkeysConfig.from_config(
            {
                "cache": {},
                "globals": {},
                "source:test": {"backend": f"{__name__}.OneKeySource"},
            }
        )
    )
    srv = KeyServer(auth, bind="127.0.0.1", port=0, api_key="secret", **options)
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
