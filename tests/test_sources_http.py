"""The http and github sources against real local HTTP and HTTPS servers."""

import datetime
import ipaddress
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("syshttp")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from authkeys.exceptions import ConfigError, SourceError  # noqa: E402
from authkeys.sources import GitHubSource, HTTPSource  # noqa: E402

KEY = "ssh-ed25519 AAAAC3Nza alice@test"


class Handler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def _reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Handler.seen.append((self.path, self.headers.get("Authorization")))
        peer = getattr(self.connection, "getpeercert", lambda: None)()
        path = self.path.split("?", 1)[0]
        if path.startswith("/keys/"):
            body = f"{KEY}\n# a comment\n\n".encode()
            self._reply(200, body)
        elif path.startswith("/status/"):
            self._reply(int(path.rsplit("/", 1)[1]))
        elif path == "/big":
            self._reply(200, b"a" * (9 * 1024 * 1024))
        elif path == "/redirect":
            self._reply(302, headers=[("Location", "/keys/alice")])
        elif path == "/token":
            ok = self.headers.get("Authorization") == "Bearer tok3n"
            self._reply(200 if ok else 401, KEY.encode() if ok else b"")
        elif path == "/whoami":
            name = peer and dict(x[0] for x in peer["subject"]).get("commonName")
            self._reply(200 if name else 403, f"{KEY} {name}".encode())
        else:
            self._reply(404)


def _start(server):
    # A short poll keeps shutdown() from waiting the default half second.
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    return server


@pytest.fixture
def http_url():
    Handler.seen = []
    server = _start(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


# --- a small PKI for the TLS tests ------------------------------------------------

NOW = datetime.datetime.now(datetime.timezone.utc)


def _cert(name, issuer_key, issuer_name, *, ca=False, san=None, eku=None):
    # Python 3.13+ verifies strictly: key identifiers and key usage are required.
    key = ec.generate_private_key(ec.SECP256R1())
    signer = issuer_key or key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san), critical=False
        )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(signer, hashes.SHA256())
    return key, cert


def _write(path, key, cert):
    path.with_suffix(".key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.with_suffix(".pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path.with_suffix(".pem")), str(path.with_suffix(".key"))


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    root = tmp_path_factory.mktemp("pki")
    ca_key, ca = _cert("Test CA", None, None, ca=True)
    _write(root / "ca", ca_key, ca)
    server = _cert(
        "localhost",
        ca_key,
        ca.subject,
        san=[
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    client = _cert(
        "key-client", ca_key, ca.subject, eku=[ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    other_key, other = _cert("Other CA", None, None, ca=True)
    _write(root / "other", other_key, other)
    return {
        "ca": str(root / "ca.pem"),
        "other": str(root / "other.pem"),
        "server": _write(root / "server", *server),
        "client": _write(root / "client", *client),
    }


@pytest.fixture
def https_url(pki):
    Handler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(*pki["server"])
    context.load_verify_locations(pki["ca"])
    context.verify_mode = ssl.CERT_OPTIONAL
    server.socket = context.wrap_socket(server.socket, server_side=True)
    _start(server)
    yield f"https://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


# --- plain HTTP -----------------------------------------------------------------


def test_keys_are_read_skipping_blanks_and_comments(http_url):
    src = HTTPSource({"url": http_url + "/keys/{username}"}, {})
    assert list(src.authorized_keys("alice")) == [KEY]


def test_username_is_percent_encoded(http_url):
    src = HTTPSource({"url": http_url + "/keys/{username}"}, {})
    list(src.authorized_keys("a/b?c&d#e"))
    assert Handler.seen[-1][0] == "/keys/a%2Fb%3Fc%26d%23e"


@pytest.mark.parametrize("status", [403, 404, 503])
def test_an_error_status_raises(http_url, status):
    src = HTTPSource({"url": http_url + f"/status/{status}"}, {})
    with pytest.raises(SourceError, match=f"HTTP {status}"):
        list(src.authorized_keys("alice"))
    assert len(Handler.seen) == 1  # retries default to 0


def test_an_oversized_reply_raises(http_url):
    src = HTTPSource({"url": http_url + "/big"}, {})
    with pytest.raises(OSError, match="larger than"):
        list(src.authorized_keys("alice"))


def test_redirects_are_followed_without_credentials(http_url):
    src = HTTPSource({"url": http_url + "/redirect"}, {})
    assert list(src.authorized_keys("alice")) == [KEY]


def test_bearer_token_from_the_environment_and_no_redirects(http_url, monkeypatch):
    monkeypatch.setenv("AUTHKEYS_TEST_TOKEN", "tok3n")
    src = HTTPSource(
        {"url": http_url + "/token", "token_env": "AUTHKEYS_TEST_TOKEN"}, {}
    )
    assert list(src.authorized_keys("alice")) == [KEY]
    redirecting = HTTPSource(
        {"url": http_url + "/redirect", "token_env": "AUTHKEYS_TEST_TOKEN"}, {}
    )
    with pytest.raises(SourceError, match="HTTP 302"):
        list(redirecting.authorized_keys("alice"))


def test_error_message_has_no_query_string(http_url):
    src = HTTPSource({"url": http_url + "/status/404?token=s3cret"}, {})
    with pytest.raises(SourceError) as info:
        list(src.authorized_keys("alice"))
    assert "s3cret" not in str(info.value)


def test_github_source_uses_the_same_client(http_url):
    src = GitHubSource({"url": http_url + "/keys/{username}.keys"}, {})
    assert list(src.authorized_keys("alice")) == [KEY]


def test_github_defaults_to_github_dot_com():
    assert GitHubSource({}, {}).url == "https://github.com/{username}.keys"


def test_text_where_a_boolean_belongs_is_ignored(caplog):
    src = HTTPSource({"url": "http://x/{username}", "verify": 0}, {})
    assert src.client.allow_redirects is True
    assert any("verify: expected bool or str" in r.getMessage() for r in caplog.records)


def test_url_is_required():
    with pytest.raises(ConfigError, match="'url'"):
        HTTPSource({}, {})


def test_proxy_setting_builds_the_proxy_map(monkeypatch):
    import syshttp.proxy

    calls = []
    real = syshttp.proxy.proxy_map
    monkeypatch.setattr(
        syshttp.proxy, "proxy_map", lambda **kw: calls.append(kw) or real(**kw)
    )
    HTTPSource({"url": "http://x/{username}", "proxy": "direct"}, {})
    HTTPSource({"url": "http://x/{username}", "proxy": "http://proxy.example:3128"}, {})
    HTTPSource({"url": "http://x/{username}"}, {})
    # The source's own calls name a proxy; syshttp's default call does not.
    assert [c for c in calls if "proxy" in c] == [
        {"proxy": ""},
        {"proxy": "http://proxy.example:3128"},
    ]


# --- HTTPS ----------------------------------------------------------------------


def test_https_with_the_test_ca(https_url, pki):
    src = HTTPSource({"url": https_url + "/keys/{username}", "verify": pki["ca"]}, {})
    assert list(src.authorized_keys("alice")) == [KEY]


def test_https_refuses_an_untrusted_server(https_url, pki):
    src = HTTPSource(
        {"url": https_url + "/keys/{username}", "verify": pki["other"]}, {}
    )
    with pytest.raises(ssl.SSLError):
        list(src.authorized_keys("alice"))


def test_https_without_verification(https_url):
    src = HTTPSource({"url": https_url + "/keys/{username}", "verify": False}, {})
    assert list(src.authorized_keys("alice")) == [KEY]


def test_client_certificate_is_presented(https_url, pki):
    cert, key = pki["client"]
    src = HTTPSource(
        {
            "url": https_url + "/whoami",
            "verify": pki["ca"],
            "certificate": cert,
            "key": key,
        },
        {},
    )
    assert list(src.authorized_keys("alice")) == [f"{KEY} key-client"]


def test_no_client_certificate_unless_configured(https_url, pki):
    src = HTTPSource({"url": https_url + "/whoami", "verify": pki["ca"]}, {})
    with pytest.raises(SourceError, match="HTTP 403"):
        list(src.authorized_keys("alice"))


def test_an_ssl_context_is_used_as_given(https_url, pki):
    context = ssl.create_default_context(cafile=pki["ca"])
    cert, key = pki["client"]
    context.load_cert_chain(cert, key)
    src = HTTPSource({"url": https_url + "/whoami"}, {}, ssl_context=context)
    assert list(src.authorized_keys("alice")) == [f"{KEY} key-client"]


def test_key_without_certificate_is_a_config_error(pki):
    with pytest.raises(ConfigError, match="certificate"):
        HTTPSource({"url": "https://x/{username}", "key": pki["client"][1]}, {})
