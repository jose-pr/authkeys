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


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
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
        {"cache": {}, "globals": {}, "source:test": {"backend": f"{__name__}.OneKeySource"}}
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
        {"cache": {}, "globals": {}, "source:test": {"backend": f"{__name__}.OneKeySource"}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    with pytest.raises(ValueError):
        KeyServer(auth, bind="127.0.0.1", port=0, api_key="", require_auth=True)


def test_require_auth_with_set_api_key_ok():
    conf = AuthkeysConfig.from_config(
        {"cache": {}, "globals": {}, "source:test": {"backend": f"{__name__}.OneKeySource"}}
    )
    auth = AuthKeys()
    auth.load_config(conf)
    srv = KeyServer(
        auth, bind="127.0.0.1", port=0, api_key="secret", require_auth=True
    )
    assert srv.check_auth(["secret"]) is True
