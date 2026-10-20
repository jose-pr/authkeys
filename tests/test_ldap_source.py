"""LDAP source against a fake ldap3 connection: result codes, referrals, the URL
scheme, and the default certificate filter (with real certificates)."""

import datetime
import os

import pytest

ldap3 = pytest.importorskip("ldap3")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from authkeys.exceptions import ConfigError, SourceError  # noqa: E402
from authkeys.sources import LDAPSource, only_auth_keys  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
CA_KEY = ec.generate_private_key(ec.SECP256R1())
CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
CA_CERT = (
    x509.CertificateBuilder()
    .subject_name(CA_NAME)
    .issuer_name(CA_NAME)
    .public_key(CA_KEY.public_key())
    .serial_number(1)
    .not_valid_before(NOW - datetime.timedelta(days=30))
    .not_valid_after(NOW + datetime.timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(CA_KEY, hashes.SHA256())
)


def _cert(*, self_signed=False, key_usage=None, eku=None, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice")])
    start = NOW - datetime.timedelta(days=30)
    end = (
        NOW - datetime.timedelta(days=1)
        if expired
        else NOW + datetime.timedelta(days=30)
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject if self_signed else CA_NAME)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if key_usage is not None:
        flags = dict.fromkeys(
            [
                "digital_signature",
                "content_commitment",
                "key_encipherment",
                "data_encipherment",
                "key_agreement",
                "key_cert_sign",
                "crl_sign",
                "encipher_only",
                "decipher_only",
            ],
            False,
        )
        flags.update(key_usage)
        builder = builder.add_extension(x509.KeyUsage(**flags), critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(key if self_signed else CA_KEY, hashes.SHA256())


@pytest.mark.parametrize(
    "kwargs,kept",
    [
        ({}, True),
        ({"key_usage": {"digital_signature": True}}, True),
        ({"eku": [ExtendedKeyUsageOID.CLIENT_AUTH]}, True),
        ({"eku": [ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]}, True),
        ({"self_signed": True}, False),  # e.g. an AD EFS recovery certificate
        ({"expired": True}, False),
        ({"key_usage": {"key_encipherment": True}}, False),
        ({"eku": [ExtendedKeyUsageOID.EMAIL_PROTECTION]}, False),
    ],
)
def test_default_filter(kwargs, kept):
    assert only_auth_keys("alice", _cert(**kwargs)) is kept


class FakeConnection:
    """Stands in for ldap3.Connection: one canned search answer."""

    answer = {"result": 0, "description": "success"}
    response = []

    def __init__(self, *args, **kwargs):
        FakeConnection.options = kwargs
        self.result = dict(FakeConnection.answer)
        self.response = list(FakeConnection.response)

    def open(self):
        pass

    def start_tls(self):
        return True

    def bind(self):
        return True

    def search(self, *args, **kwargs):
        return self.result["result"] == 0 and any(
            r.get("type") == "searchResEntry" for r in self.response
        )

    def unbind(self):
        pass


REF = {"type": "searchResRef", "uri": ["ldap://ForestDnsZones.example/DC=example"]}


def _entry(*certs):
    der = [c.public_bytes(serialization.Encoding.DER) for c in certs]
    return {
        "type": "searchResEntry",
        "dn": "uid=alice",
        "raw_attributes": {"userCertificate": der},
    }


def _fake_ldap3(monkeypatch):
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: object())


@pytest.fixture
def source(monkeypatch):
    _fake_ldap3(monkeypatch)
    options = {
        "server": "ldaps://dc.example",
        "basedn": "dc=example",
        "client": "ldap3",
        "auth": "anonymous",
    }
    return LDAPSource(options, {})


def _answer(monkeypatch, result, response):
    monkeypatch.setattr(FakeConnection, "answer", result)
    monkeypatch.setattr(FakeConnection, "response", response)


def test_refused_search_raises(source, monkeypatch):
    _answer(monkeypatch, {"result": 1, "description": "operationsError"}, [])
    with pytest.raises(SourceError, match="operationsError"):
        list(source.authorized_keys("alice"))


def test_referrals_only_is_no_keys(source, monkeypatch):
    _answer(monkeypatch, {"result": 0, "description": "success"}, [REF, REF, REF])
    assert list(source.authorized_keys("ghost")) == []


def test_entry_after_referrals_is_read_and_filtered(source, monkeypatch):
    good, efs = _cert(eku=[ExtendedKeyUsageOID.CLIENT_AUTH]), _cert(self_signed=True)
    _answer(
        monkeypatch,
        {"result": 0, "description": "success"},
        [REF, _entry(good, efs), REF],
    )
    keys = list(source.authorized_keys("alice"))
    assert len(keys) == 1 and keys[0].startswith("ecdsa-sha2-nistp256 ")


def test_entry_without_the_attribute_is_no_keys(source, monkeypatch):
    entry = {"type": "searchResEntry", "dn": "uid=alice", "raw_attributes": {}}
    _answer(monkeypatch, {"result": 0, "description": "success"}, [entry])
    assert list(source.authorized_keys("alice")) == []


def test_ambiguous_match_raises(source, monkeypatch):
    _answer(monkeypatch, {"result": 0, "description": "success"}, [_entry(), _entry()])
    with pytest.raises(SourceError, match="matched 2 entries"):
        list(source.authorized_keys("alice"))


def test_attribute_options_and_case_are_matched(source, monkeypatch):
    # OpenLDAP answers with "userCertificate;binary", and ldap3 also returns the
    # plain name, empty.
    der = _cert(eku=[ExtendedKeyUsageOID.CLIENT_AUTH]).public_bytes(
        serialization.Encoding.DER
    )
    entry = {
        "type": "searchResEntry",
        "dn": "uid=alice",
        "raw_attributes": {"usercertificate;binary": [der], "userCertificate": []},
    }
    _answer(monkeypatch, {"result": 0, "description": "success"}, [entry])
    assert len(list(source.authorized_keys("alice"))) == 1


def test_cert_filter_none_keeps_every_certificate(monkeypatch):
    _fake_ldap3(monkeypatch)
    src = LDAPSource(
        {
            "server": "dc.example",
            "client": "ldap3",
            "auth": "anonymous",
            "cert_filter": "none",
        },
        {},
    )
    _answer(
        monkeypatch,
        {"result": 0, "description": "success"},
        [_entry(_cert(self_signed=True))],
    )
    assert len(list(src.authorized_keys("alice"))) == 1


def test_issuer_ca_keeps_only_certificates_it_issued(monkeypatch, tmp_path):
    _fake_ldap3(monkeypatch)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(CA_CERT.public_bytes(serialization.Encoding.PEM))
    src = LDAPSource(
        {
            "server": "dc.example",
            "client": "ldap3",
            "auth": "anonymous",
            "cert_filter": "none",
            "issuer_ca": str(ca_file),
        },
        {},
    )
    issued, foreign = _cert(), _cert(self_signed=True)
    _answer(
        monkeypatch, {"result": 0, "description": "success"}, [_entry(issued, foreign)]
    )
    assert len(list(src.authorized_keys("alice"))) == 1


def test_comment_has_no_spaces(source, monkeypatch):
    _answer(
        monkeypatch,
        {"result": 0, "description": "success"},
        [_entry(_cert(eku=[ExtendedKeyUsageOID.CLIENT_AUTH]))],
    )
    (line,) = source.authorized_keys("alice")
    assert len(line.split(" ")) == 3


@pytest.mark.parametrize(
    "options,message",
    [
        ({}, "needs a 'server'"),
        ({"server": "dc", "auth": "magic"}, "auth must be one of"),
        ({"server": "dc", "auth": "simple"}, "bind_dn and password_env"),
        (
            {
                "server": "ldap://dc",
                "auth": "simple",
                "bind_dn": "x",
                "password_env": "Y",
                "starttls": False,
            },
            "ldap://",
        ),
        ({"server": "dc", "auth": "external"}, "tls_cert"),
        ({"server": "dc", "client": "nope"}, "client must be"),
        ({"server": "http://dc"}, "ldaps:// or ldap://"),
    ],
)
def test_invalid_options_are_config_errors(options, message):
    with pytest.raises(ConfigError, match=message):
        LDAPSource(options, {})


def test_gssapi_with_ldap3_seals_a_clear_text_session(monkeypatch):
    pytest.importorskip("winkerberos" if os.name == "nt" else "gssapi")
    _fake_ldap3(monkeypatch)
    src = LDAPSource({"server": "ldap://dc.example", "client": "ldap3"}, {})
    _answer(monkeypatch, {"result": 0, "description": "success"}, [])
    list(src.authorized_keys("alice"))
    assert FakeConnection.options["session_security"] == ldap3.ENCRYPT
    assert FakeConnection.options["sasl_mechanism"] == ldap3.KERBEROS
    assert FakeConnection.options["auto_referrals"] is False


def test_an_ssl_context_selects_ldap3_and_is_used(monkeypatch):
    import ssl

    from authkeys.sources._ldapclients import LDAP3Client

    _fake_ldap3(monkeypatch)
    seen = {}
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: seen.update(k) or object())
    context = ssl.create_default_context()
    src = LDAPSource(
        {"server": "dc.example", "auth": "anonymous"}, {}, ssl_context=context
    )
    assert isinstance(src.client, LDAP3Client)
    _answer(monkeypatch, {"result": 0, "description": "success"}, [])
    list(src.authorized_keys("alice"))
    assert seen["tls"].context is context


def test_python_ldap_refuses_an_ssl_context():
    pytest.importorskip("ldap")
    import ssl

    with pytest.raises(ConfigError, match="cannot take an SSLContext"):
        LDAPSource(
            {"server": "dc", "client": "python-ldap", "auth": "anonymous"},
            {},
            ssl_context=ssl.create_default_context(),
        )


@pytest.mark.parametrize("server", ["ldap://dc.example", "LDAP://dc.example:389"])
def test_plain_ldap_url_is_refused_without_sealing_or_starttls(server):
    with pytest.raises(ConfigError, match="ldaps://"):
        LDAPSource({"server": server, "auth": "anonymous"}, {})


def test_failed_search_keeps_cached_keys_with_expired_on_error(source, monkeypatch):
    from authkeys import AuthKeys, Source
    from authkeys.cache import AuthKeysCache, MemoryCache

    auth = AuthKeys()
    auth.cache = AuthKeysCache(MemoryCache(), ttl=0)
    auth.use_expired_on_error = True
    auth.sources = {
        "ldap": Source(
            cached=True, enabled=True, backend=source, sanitize=None, expire=None
        )
    }
    _answer(
        monkeypatch,
        {"result": 0, "description": "success"},
        [_entry(_cert(eku=[ExtendedKeyUsageOID.CLIENT_AUTH]))],
    )
    first = list(auth.authorized_keys("alice"))
    _answer(monkeypatch, {"result": 49, "description": "invalidCredentials"}, [])
    assert [k.key for k in auth.authorized_keys("alice")] == [k.key for k in first]
