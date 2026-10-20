"""The ldap source against a real OpenLDAP server (skipped where slapd is absent),
once per installed client: python-ldap and ldap3."""

import ssl

import pytest

import ldap_server
from authkeys.exceptions import ConfigError, SourceError
from authkeys.sources import LDAPSource


def _clients():
    found = []
    for module, name in (("ldap", "python-ldap"), ("ldap3", "ldap3")):
        try:
            __import__(module)
            found.append(name)
        except ImportError:
            found.append(
                pytest.param(
                    name, marks=pytest.mark.skip(reason=f"{module} not installed")
                )
            )
    return found


@pytest.fixture(params=_clients())
def client(request):
    return request.param


def _source(slapd, client, **options):
    base = {
        "server": slapd.ldaps_url,
        "basedn": ldap_server.BASE_DN,
        "client": client,
        "auth": "anonymous",
        "tls_verify": slapd.ca,
    }
    base.update(options)
    return LDAPSource(base, {})


def test_alice_gets_her_client_auth_certificate_only(slapd, client):
    (line,) = _source(slapd, client).authorized_keys("alice")
    assert line.startswith("ecdsa-sha2-nistp256 ") and line.endswith("(CN=alice)")


def test_cert_filter_none_returns_both(slapd, client):
    assert len(_source(slapd, client, cert_filter="none").authorized_keys("alice")) == 2


def test_issuer_ca_drops_the_self_signed_one(slapd, client):
    src = _source(slapd, client, cert_filter="none", issuer_ca=slapd.ca)
    assert len(src.authorized_keys("alice")) == 1


@pytest.mark.parametrize("user", ["bob", "nobody-here", "*)(uid=*"])
def test_no_certificate_or_no_entry_is_no_keys(slapd, client, user):
    assert _source(slapd, client).authorized_keys(user) == []


def test_an_ambiguous_match_is_an_error(slapd, client):
    with pytest.raises(SourceError, match="matched 2 entries"):
        _source(slapd, client, username_attr="cn").authorized_keys("twin")


def test_simple_bind_over_tls(slapd, client, monkeypatch):
    monkeypatch.setenv("AUTHKEYS_TEST_LDAP_PW", ldap_server.ROOT_PASSWORD)
    src = _source(
        slapd,
        client,
        auth="simple",
        bind_dn=ldap_server.ROOT_DN,
        password_env="AUTHKEYS_TEST_LDAP_PW",
    )
    assert len(src.authorized_keys("alice")) == 1


def test_a_wrong_password_is_an_error(slapd, client, monkeypatch):
    monkeypatch.setenv("AUTHKEYS_TEST_LDAP_PW", "wrong")
    src = _source(
        slapd,
        client,
        auth="simple",
        bind_dn=ldap_server.ROOT_DN,
        password_env="AUTHKEYS_TEST_LDAP_PW",
    )
    with pytest.raises(SourceError):
        src.authorized_keys("alice")


def test_external_bind_with_a_client_certificate(slapd, client):
    src = _source(
        slapd,
        client,
        auth="external",
        tls_cert=slapd.client_cert,
        tls_key=slapd.client_key,
    )
    assert len(src.authorized_keys("alice")) == 1


def test_starttls_on_the_clear_text_port(slapd, client):
    src = _source(slapd, client, server=slapd.ldap_url, starttls=True)
    assert len(src.authorized_keys("alice")) == 1


def test_clear_text_without_starttls_or_kerberos_is_refused(slapd, client):
    with pytest.raises(ConfigError, match="ldaps://"):
        _source(slapd, client, server=slapd.ldap_url)


def test_an_untrusted_server_certificate_fails(slapd, client):
    with pytest.raises(Exception):
        _source(slapd, client, tls_verify=slapd.other_ca).authorized_keys("alice")


# --- the ldap3 client with an sslcontext context -------------------------------------


def test_ldap3_uses_a_given_context(slapd):
    pytest.importorskip("ldap3")
    context = ssl.create_default_context(cafile=slapd.ca)
    src = LDAPSource(
        {"server": slapd.ldaps_url, "basedn": ldap_server.BASE_DN, "auth": "anonymous"},
        {},
        ssl_context=context,
    )
    assert src.client.name == "ldap3"
    assert len(src.authorized_keys("alice")) == 1


def test_ldap3_with_a_context_for_another_ca_fails(slapd):
    pytest.importorskip("ldap3")
    context = ssl.create_default_context(cafile=slapd.other_ca)
    src = LDAPSource(
        {"server": slapd.ldaps_url, "basedn": ldap_server.BASE_DN, "auth": "anonymous"},
        {},
        ssl_context=context,
    )
    with pytest.raises(Exception):
        src.authorized_keys("alice")


def test_ldap3_starttls_and_external_with_a_sslcontext_context(slapd):
    pytest.importorskip("ldap3")
    import sslcontext

    context = sslcontext.create_context(
        cafile=slapd.ca, certificate=slapd.client_cert, key=slapd.client_key
    )
    src = LDAPSource(
        {
            "server": slapd.ldap_url,
            "starttls": True,
            "basedn": ldap_server.BASE_DN,
            "auth": "external",
        },
        {},
        ssl_context=context,
    )
    assert len(src.authorized_keys("alice")) == 1
