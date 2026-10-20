"""LDAP source against a fake ldap3 connection: result codes, referrals, the URL
scheme, and the default certificate filter (with real certificates)."""

import datetime

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
        self.result = dict(FakeConnection.answer)
        self.response = list(FakeConnection.response)

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


@pytest.fixture
def source(tmp_path, monkeypatch):
    for name in ("cert.pem", "key.pem"):
        (tmp_path / name).write_text("x")
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: object())
    monkeypatch.setattr(ldap3, "Tls", lambda *a, **k: object())
    options = {
        "server": "ldaps://dc.example",
        "basedn": "dc=example",
        "tls_cert": str(tmp_path / "cert.pem"),
        "tls_key": str(tmp_path / "key.pem"),
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


def test_cert_filter_none_keeps_every_certificate(source, monkeypatch, tmp_path):
    options = {
        "server": "dc.example",
        "cert_filter": "none",
        "tls_cert": str(tmp_path / "cert.pem"),
        "tls_key": str(tmp_path / "key.pem"),
    }
    src = LDAPSource(options, {})
    _answer(
        monkeypatch,
        {"result": 0, "description": "success"},
        [_entry(_cert(self_signed=True))],
    )
    assert len(list(src.authorized_keys("alice"))) == 1


@pytest.mark.parametrize("server", ["ldap://dc.example", "LDAP://dc.example:389"])
def test_plain_ldap_url_is_refused(server):
    options = {"server": server}
    with pytest.raises(ConfigError, match="ldaps://"):
        LDAPSource(options, {})


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
