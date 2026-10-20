"""LDAP source: derive SSH keys from X.509 certificates stored in a directory.

The one entry whose ``username_attr`` equals the username is read; each value of
its ``cert_attr`` is parsed as a DER certificate and its public key serialized to
OpenSSH format. A ``cert_filter`` callable ``(username, cert) -> bool | str`` drops
a certificate or supplies a comment; it defaults to :func:`only_auth_keys`, and
``cert_filter = none`` keeps every one. ``issuer_ca`` keeps only certificates
issued by one of its certificates.

Two clients do the LDAP work: python-ldap when it imports (an appliance or a
distribution often ships it), else ldap3 (``pip install authkeys[ldap]``).
Kerberos (``auth = "gssapi"``, the default) uses the host's machine credentials:
the keytab's principal, read by MIT Kerberos.
"""

import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, List, Mapping, Optional, Union

from duho import logging

from .. import KeySource, utils
from ..config import typed
from ..exceptions import ConfigError
from ._ldapclients import LDAPSettings, make_client, use_machine_keytab

LOGGER = logging.getLogger("authkeys.sources.ldap")

# (username, cert) -> False to drop, str for a comment, True/None for default
CertFilter = Callable[[str, "object"], "Union[bool, str]"]

_AUTH_MODES = ("gssapi", "simple", "external", "anonymous")
_DEFAULT_KEYTAB = "/etc/krb5.keytab"


def escape_filter_value(value: str) -> str:
    """Escape a value for an LDAP search filter (RFC 4515, section 3)."""
    out = []
    for char in value:
        if char in "\\*()\x00":
            out.append("\\%02x" % ord(char))
        else:
            out.append(char)
    return "".join(out)


def _validity(cert):
    # cryptography 42 added the timezone-aware properties.
    before = getattr(cert, "not_valid_before_utc", None)
    after = getattr(cert, "not_valid_after_utc", None)
    if before is None:
        before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def only_auth_keys(username: str, cert) -> bool:
    """Default filter: keep only certificates that are login credentials.

    A certificate is kept when it is within its validity period, is not
    self-signed, its KeyUsage (when present) permits digital signature, and its
    ExtendedKeyUsage (when present) includes clientAuth or anyExtendedKeyUsage.
    Directories also hold encryption, e-mail and recovery certificates in the
    same attribute; those must not become SSH keys.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    before, after = _validity(cert)
    if not before <= datetime.now(timezone.utc) <= after:
        return False
    if cert.issuer == cert.subject:
        return False
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.digital_signature:
        return False
    try:
        purposes = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        purposes = None
    if purposes is not None and not (
        ExtendedKeyUsageOID.CLIENT_AUTH in purposes
        or ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in purposes
    ):
        return False
    return True


class LDAPSource(KeySource):
    """Keys derived from X.509 certificates stored in an LDAP directory.

    ``ssl_context`` (programmatic use) is the client TLS context; it selects the
    ldap3 client, which can take one.
    """

    options = frozenset(
        {
            "server",
            "basedn",
            "cert_attr",
            "username_attr",
            "client",
            "auth",
            "keytab",
            "principal",
            "bind_dn",
            "password_env",
            "starttls",
            "tls_verify",
            "tls_cert",
            "tls_key",
            "timeout",
            "cert_filter",
            "issuer_ca",
        }
    )

    def __init__(
        self,
        options: Mapping[str, Any],
        globals: dict,
        *,
        ssl_context: "Optional[ssl.SSLContext]" = None,
    ) -> None:
        where = "ldap source"
        server = typed(options, "server", str, None, where)
        if not server:
            raise ConfigError("the ldap source needs a 'server'")
        auth = typed(options, "auth", str, "gssapi", where).strip().lower()
        if auth not in _AUTH_MODES:
            raise ConfigError(
                f"ldap source: auth must be one of {', '.join(_AUTH_MODES)}, not {auth!r}"
            )
        starttls = typed(options, "starttls", bool, False, where)
        url = server.strip()
        if "://" not in url:
            url = f"ldaps://{url}"
        scheme = url.split("://", 1)[0].lower()
        if scheme not in ("ldap", "ldaps"):
            raise ConfigError(
                f"ldap source: 'server' must be ldaps:// or ldap://, not {scheme}://"
            )
        # A clear-text connection decides who logs in: allow it only when Kerberos
        # seals the session or StartTLS encrypts it.
        if scheme == "ldap" and not (starttls or auth == "gssapi"):
            raise ConfigError(
                "ldap source 'server' must be an ldaps:// URL or a host name, or use "
                'ldap:// with starttls = true or auth = "gssapi" (a sealed session)'
            )
        tls_cert = typed(options, "tls_cert", str, None, where)
        tls_key = typed(options, "tls_key", str, None, where)
        if auth == "external" and not (tls_cert or ssl_context):
            raise ConfigError(
                'ldap source: auth = "external" needs tls_cert and tls_key'
            )
        bind_dn = typed(options, "bind_dn", str, None, where)
        password_env = typed(options, "password_env", str, None, where)
        if auth == "simple":
            if not (bind_dn and password_env):
                raise ConfigError(
                    'ldap source: auth = "simple" needs bind_dn and password_env'
                )
            if scheme == "ldap" and not starttls:
                raise ConfigError(
                    "ldap source: a simple bind needs TLS (ldaps:// or starttls)"
                )
        keytab = typed(options, "keytab", str, _DEFAULT_KEYTAB, where)
        if auth == "gssapi":
            use_machine_keytab(keytab)
        self.username_attr = typed(options, "username_attr", str, "uid", where)
        self.cert_attr = typed(options, "cert_attr", str, "userCertificate", where)
        self.settings = LDAPSettings(
            url=url,
            starttls=starttls,
            basedn=typed(options, "basedn", str, "", where),
            attribute=self.cert_attr,
            auth=auth,
            keytab=keytab,
            principal=typed(options, "principal", str, None, where),
            bind_dn=bind_dn,
            password_env=password_env,
            tls_verify=typed(options, "tls_verify", str, None, where),
            tls_cert=tls_cert,
            tls_key=tls_key,
            timeout=float(typed(options, "timeout", (int, float), 10.0, where)),
            ssl_context=ssl_context,
        )
        self.client = make_client(
            self.settings, typed(options, "client", str, "auto", where)
        )
        cert_filter: "Optional[Union[str, CertFilter]]" = typed(
            options, "cert_filter", str, None, where
        )
        if cert_filter is None:
            cert_filter = only_auth_keys
        elif cert_filter.strip().lower() == "none":
            cert_filter = None
        else:
            cert_filter = utils.import_module_object(cert_filter)
        self.cert_filter = cert_filter
        self.issuers = self._load_issuers(typed(options, "issuer_ca", str, None, where))

    @staticmethod
    def _load_issuers(path: "Optional[str]") -> list:
        if not path:
            return []
        from cryptography import x509

        try:
            issuers = x509.load_pem_x509_certificates(Path(path).read_bytes())
        except (OSError, ValueError) as e:
            raise ConfigError(
                f"ldap source: issuer_ca {path}: {type(e).__name__}"
            ) from None
        if not issuers:
            raise ConfigError(f"ldap source: issuer_ca {path} holds no certificate")
        return issuers

    def _issued_by_trusted(self, cert) -> bool:
        for issuer in self.issuers:
            try:
                cert.verify_directly_issued_by(issuer)
                return True
            except Exception:
                continue
        return False

    def _search_filter(self, username: str) -> str:
        """The search filter, with the username escaped.

        The username may come from a ``serve`` request, so it must not be able to
        inject filter clauses (``*)(uid=*``).
        """
        return f"({self.username_attr}={escape_filter_value(username)})"

    def authorized_keys(self, username: str) -> Iterable[str]:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization.ssh import (
            serialize_ssh_public_key,
        )

        keys: List[str] = []
        for raw in self.client.certificates(self._search_filter(username)):
            cert = x509.load_der_x509_certificate(bytes(raw))
            if self.issuers and not self._issued_by_trusted(cert):
                continue
            comment: "Union[bool, str, None]" = None
            if self.cert_filter:
                comment = self.cert_filter(username, cert)
                if comment is False:
                    continue
            if comment is None or isinstance(comment, bool):
                # The comment is one field of an authorized_keys line: no spaces.
                subject = cert.subject.rfc4514_string().replace(" ", "_")
                comment = f"{username}({subject})"
            key = serialize_ssh_public_key(cert.public_key()).decode()
            keys.append(f"{key} {comment}")
        return keys
